#![cfg(feature = "early-data")]

use std::io::{self, Write};
use std::net::{self, SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;

use rustls::crypto::cipher::OutboundPlain;
use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, Connection, ServerConfig, VecInput};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    wrapper: impl Fn(TcpStream) -> S,
    data: &[u8],
    vectored: bool,
) -> io::Result<(TlsStream<S>, Vec<u8>)> {
    let connector = TlsConnector::from(config).early_data(true);
    let stream = wrapper(TcpStream::connect(&addr).await?);
    let domain = ServerName::try_from("foobar.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    utils::write(&mut stream, data, vectored).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    Ok((stream, buf))
}

#[tokio::test]
async fn test_0rtt() -> io::Result<()> {
    test_0rtt_impl(|s| s, false).await
}

#[tokio::test]
async fn test_0rtt_vectored() -> io::Result<()> {
    test_0rtt_impl(|s| s, true).await
}

#[tokio::test]
async fn test_0rtt_vectored_flush_pending() -> io::Result<()> {
    test_0rtt_impl(utils::FlushWrapper::new, false).await
}

async fn test_0rtt_impl<S: AsyncRead + AsyncWrite + Unpin>(
    wrapper: impl Fn(TcpStream) -> S,
    vectored: bool,
) -> io::Result<()> {
    let (mut server, mut client) = utils::make_configs();
    server.max_early_data_size = 8192;
    let server = Arc::new(server);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        loop {
            let (mut sock, _addr) = listener.accept().unwrap();

            let server = Arc::clone(&server);
            thread::spawn(move || serve(server, &mut sock).unwrap());
        }
    });

    client.enable_early_data = true;
    let client = Arc::new(client);
    let addr = SocketAddr::from(([127, 0, 0, 1], server_port));

    let (io, buf) = send(client.clone(), addr, &wrapper, b"hello", vectored).await?;
    assert!(!io.get_ref().1.side().is_early_data_accepted());
    assert_eq!("LATE:hello", String::from_utf8_lossy(&buf));

    let (io, buf) = send(client, addr, wrapper, b"world!", vectored).await?;
    assert!(io.get_ref().1.side().is_early_data_accepted());
    assert_eq!("EARLY:world!LATE:", String::from_utf8_lossy(&buf));

    Ok(())
}

/// Writes back any early data prefixed by `EARLY:`, then `LATE:`, then echoes until closed.
fn serve(config: Arc<ServerConfig>, sock: &mut net::TcpStream) -> io::Result<()> {
    let mut conn = Connection::new(config).map_err(io::Error::other)?;
    let mut input = VecInput::default();
    let mut tls = Vec::new();
    let mut plaintext = Vec::new();

    let mut early_data = Vec::new();
    let mut closed = false;
    while conn.is_handshaking() {
        if input.read(sock)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        let mut handler = conn.read_tls(&mut input, &mut tls);
        while let Some(payload) = handler.next_early_data() {
            early_data.extend_from_slice(payload.map_err(io::Error::other)?.bytes());
        }
        closed = handler
            .handle_all(&mut plaintext)
            .map_err(io::Error::other)?
            .peer_has_closed();

        sock.write_all(&tls)?;
        tls.clear();
    }

    if !early_data.is_empty() {
        conn.write(OutboundPlain::from(b"EARLY:"), &mut tls)
            .map_err(io::Error::other)?;
        conn.write(OutboundPlain::from(&early_data), &mut tls)
            .map_err(io::Error::other)?;
    }

    conn.write(OutboundPlain::from(b"LATE:"), &mut tls)
        .map_err(io::Error::other)?;

    while !closed {
        conn.write(OutboundPlain::from(&plaintext), &mut tls)
            .map_err(io::Error::other)?;
        plaintext.clear();
        sock.write_all(&tls)?;
        tls.clear();

        if input.read(sock)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        closed = conn
            .read_tls(&mut input, &mut tls)
            .handle_all(&mut plaintext)
            .map_err(io::Error::other)?
            .peer_has_closed();
    }

    conn.write(OutboundPlain::from(&plaintext), &mut tls)
        .map_err(io::Error::other)?;
    conn.send_close_notify(&mut tls).map_err(io::Error::other)?;
    sock.write_all(&tls)
}

// Include `utils` module
include!("utils.rs");
