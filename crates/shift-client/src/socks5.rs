use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use shift_proto::{Host, Target};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;
const REPLY_OK: u8 = 0;
const REPLY_GENERAL_FAILURE: u8 = 1;
const REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;

pub struct Socks5Listener {
    listener: TcpListener,
}

impl Socks5Listener {
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Socks5Listener {
            listener: TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        self.listener.accept().await
    }
}

pub async fn read_connect_request(stream: &mut TcpStream) -> io::Result<Target> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 client",
        ));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no acceptable auth method",
        ));
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad request version",
        ));
    }
    if header[1] != CMD_CONNECT {
        reply(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only CONNECT is supported",
        ));
    }

    let host = match header[3] {
        ATYP_V4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Host::V4(Ipv4Addr::from(octets))
        }
        ATYP_V6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Host::V6(Ipv6Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "domain is not utf-8"))?;
            Host::Domain(name)
        }
        _ => {
            reply(stream, REPLY_GENERAL_FAILURE).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown address type",
            ));
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;

    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

pub async fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    let payload = [VERSION, code, 0, ATYP_V4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&payload).await
}

pub async fn reply_success(stream: &mut TcpStream) -> io::Result<()> {
    reply(stream, REPLY_OK).await
}

pub async fn reply_failure(stream: &mut TcpStream) -> io::Result<()> {
    reply(stream, REPLY_GENERAL_FAILURE).await
}
