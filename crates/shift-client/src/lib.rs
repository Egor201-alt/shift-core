pub mod core;
pub mod socks5;

pub use crate::core::{ClientConfig, PskSource, RunningClient};

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use tokio::runtime::Runtime;

#[derive(Deserialize)]
struct FfiConfig {
    server_addr: String,
    server_public_key: String,
    #[serde(default)]
    psk_passphrase: Option<String>,
    #[serde(default)]
    psk_hex: Option<String>,
    #[serde(default = "default_cipher")]
    cipher: String,
    #[serde(default = "default_bind")]
    socks_bind: String,
    #[serde(default = "default_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default)]
    camouflage_sni: Option<String>,
}

fn default_cipher() -> String {
    "auto".to_owned()
}

fn default_bind() -> String {
    "127.0.0.1:1080".to_owned()
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn parse_cipher(name: &str) -> Result<shift_proto::CipherSuite, String> {
    match name {
        "auto" => Ok(shift_proto::CipherSuite::preferred()),
        "chacha20poly1305" => Ok(shift_proto::CipherSuite::ChaCha20Poly1305),
        "aes256gcm" => Ok(shift_proto::CipherSuite::Aes256Gcm),
        other => Err(format!("unknown cipher '{other}'")),
    }
}

impl FfiConfig {
    fn into_client_config(self) -> Result<(ClientConfig, SocketAddr), String> {
        let server_public_key =
            shift_proto::hex_decode32(&self.server_public_key).map_err(|err| err.to_string())?;
        let psk = match (self.psk_passphrase, self.psk_hex) {
            (Some(passphrase), None) => PskSource::Passphrase(passphrase),
            (None, Some(hex)) => PskSource::Hex(hex),
            _ => return Err("provide exactly one of psk_passphrase or psk_hex".to_owned()),
        };
        let cipher = parse_cipher(&self.cipher)?;
        let bind: SocketAddr = self
            .socks_bind
            .parse()
            .map_err(|_| format!("invalid socks_bind '{}'", self.socks_bind))?;
        Ok((
            ClientConfig {
                server_addr: self.server_addr,
                server_public_key,
                psk,
                cipher,
                connect_timeout: Duration::from_millis(self.connect_timeout_ms),
                camouflage_sni: self.camouflage_sni,
            },
            bind,
        ))
    }
}

struct Instance {
    runtime: Runtime,
    handle: RunningClient,
}

static REGISTRY: OnceLock<Mutex<HashMap<i64, Instance>>> = OnceLock::new();
static NEXT_ID: OnceLock<std::sync::atomic::AtomicI64> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<i64, Instance>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_id() -> i64 {
    NEXT_ID
        .get_or_init(|| std::sync::atomic::AtomicI64::new(1))
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

pub fn start(config_json: &str) -> Result<i64, String> {
    let parsed: FfiConfig = serde_json::from_str(config_json).map_err(|err| err.to_string())?;
    let (config, bind) = parsed.into_client_config()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| err.to_string())?;

    let handle = runtime
        .block_on(core::run_socks5(config, bind))
        .map_err(|err| err.to_string())?;

    let id = next_id();
    registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(id, Instance { runtime, handle });
    Ok(id)
}

pub fn stop(id: i64) -> bool {
    let instance = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&id);
    match instance {
        Some(instance) => {
            instance.handle.stop();
            instance.runtime.shutdown_background();
            true
        }
        None => false,
    }
}

/// # Safety
/// `config_json` must be a valid pointer to a NUL-terminated UTF-8 C string
/// that stays valid for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn shift_client_start(config_json: *const c_char) -> i64 {
    if config_json.is_null() {
        return -1;
    }
    let text = match std::panic::catch_unwind(|| {
        CStr::from_ptr(config_json).to_str().map(str::to_owned)
    }) {
        Ok(Ok(text)) => text,
        _ => return -1,
    };
    match std::panic::catch_unwind(|| start(&text)) {
        Ok(Ok(id)) => id,
        Ok(Err(err)) => {
            eprintln!("shift_client_start failed: {err}");
            -1
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn shift_client_stop(handle: i64) -> i32 {
    match std::panic::catch_unwind(|| stop(handle)) {
        Ok(true) => 0,
        Ok(false) => -1,
        Err(_) => -2,
    }
}

/// # Safety
/// `ptr` must be a pointer previously returned by a shift-client function
/// that documents ownership transfer via `CString::into_raw`, and must not
/// be freed more than once.
#[no_mangle]
pub unsafe extern "C" fn shift_client_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}
