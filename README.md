# Shift / Shift Core

Rust workspace implementing the Shift Protocol: a DPI-resistant tunnel
core meant to sit in front of Xray/Marzban.

## Crates

- `crates/shift-proto` — the wire protocol shared by client and server:
  `crypto.rs` (ChaCha20-Poly1305 / AES-256-GCM, blake3 key schedule),
  `frame.rs` (length-encrypted, AEAD-sealed frame codec),
  `handshake.rs` (X25519 + PSK handshake with replay protection),
  `morphing.rs` (Adaptive Burst Mode traffic shaper),
  `open.rs` (in-tunnel open-connection request/status),
  `tunnel.rs` (tokio-based relay glue, behind the `tokio` feature).
- `crates/shift-server` — the server daemon: on handshake or auth failure it
  transparently proxies the connection to a decoy host (`fallback.rs`);
  on success it forwards the decrypted stream to a local Xray/Marzban port
  (`forwarder.rs`).
- `crates/shift-client` — the client core: an embedded SOCKS5 server
  (`socks5.rs`), a safe Rust API (`core.rs`), and a C-ABI surface for GUI
  integration (`lib.rs`, `include/shift_client.h`), plus a standalone CLI
  (`shift-cli`).

## Building

```bash
cargo build --workspace --release
```

Produces `shift-server`, `shift-cli`, and `libshift_client.so` (or
`.dll` on Windows) under `target/<...>/release/`.

## Running

Server:

```bash
shift-server \
  --listen 0.0.0.0:443 \
  --forward 127.0.0.1:10001 \
  --fallback 1.1.1.1:443 \
  --psk "a long shared passphrase" \
  --server-secret <64 hex chars, optional>
```

If `--server-secret` is omitted, the server logs a freshly generated
identity on startup; save it to keep the same public key across restarts.

Client:

```bash
shift-cli \
  --server your.server:443 \
  --server-public-key <64 hex chars from the server log> \
  --psk "a long shared passphrase" \
  --socks-bind 127.0.0.1:1080
```

Point any SOCKS5-aware application at `127.0.0.1:1080`.

## Testing

```bash
cargo test --workspace
```

`crates/shift-server/tests/integration.rs` spins up an in-process echo
server, a `shift-server`, and a `shift-client`, and relays real traffic
through the full SOCKS5 → Shift tunnel → forward path, plus a decoy
fallback check for a wrong PSK.

## CI

`.github/workflows/build.yml` runs `fmt`/`clippy`/`test`, then
cross-compiles release binaries for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, and `x86_64-pc-windows-gnu`, and bundles all
three targets into one `shift-core-all-platforms.zip` artifact. Pushing a
`v*` tag also publishes that archive as a GitHub Release.
