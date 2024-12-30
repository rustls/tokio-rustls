#![cfg(feature = "compute-heavy-future-executor")]
//! Using the `compute-heavy-future-executor` feature shifts the global behavior
//! of processing bytes + establishing handshakes. So all other test suites running are validating
//! parity of processing.
//!
//! This suite in particular is probing that the async executor futures are actually doing anything + that executor
//! failures are handled properly.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;

use compute_heavy_future_executor::{global_sync_strategy_builder, CustomExecutorSyncClosure};
use futures_util::{future::Future, ready};
use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, ServerConnection, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

struct Read1<T>(T);

impl<T: AsyncRead + Unpin> Future for Read1<T> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = [0];
        let mut buf = ReadBuf::new(&mut buf);

        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;

        if buf.filled().is_empty() {
            Poll::Ready(Ok(()))
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// returns rx to listen on to confirm layer was hit
fn async_session_executor() -> (tokio::sync::mpsc::Receiver<()>, Arc<AtomicBool>) {
    let (result_tx, result_rx) = tokio::sync::mpsc::channel(10);
    let fail = Arc::new(AtomicBool::new(false));

    let fail_cloned = fail.clone();
    let closure: CustomExecutorSyncClosure = Box::new(move |f| {
        let tx = result_tx.clone();
        let fail = fail_cloned.clone();

        Box::new(async move {
            if fail.load(Ordering::Relaxed) {
                return Err(Box::from("executor failed"));
            }
            let _ = tx.send(()).await;
            Ok(tokio::task::spawn_blocking(move || f()).await.unwrap())
        })
    });

    global_sync_strategy_builder()
        .initialize_custom_executor(closure)
        .unwrap();

    (result_rx, fail)
}

#[tokio::test]
async fn test_async_session() {
    let (mut res_rx, fail) = async_session_executor();

    let _ = async_session_impl().await;

    let res = res_rx.recv().await;
    assert!(res.is_some(), "async session executor did not fire");

    // make the async executor fail further calls
    fail.store(true, Ordering::Relaxed);

    let res = async_session_impl().await;
    assert!(
        res.is_err_and(|err| err.kind() == ErrorKind::Other),
        "async session executor did not return proper error"
    );
}

async fn send(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    data: &[u8],
    vectored: bool,
) -> io::Result<(TlsStream<TcpStream>, Vec<u8>)> {
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(&addr).await?;
    let domain = ServerName::try_from("foobar.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    utils::write(&mut stream, data, vectored).await?;
    stream.flush().await?;
    stream.shutdown().await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;

    Ok((stream, buf))
}

async fn async_session_impl() -> io::Result<()> {
    let (server, client) = utils::make_configs();
    let server = Arc::new(server);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_port = listener.local_addr().unwrap().port();
    thread::spawn(move || loop {
        let (mut sock, _addr) = listener.accept().unwrap();

        let server = Arc::clone(&server);
        thread::spawn(move || {
            let mut conn = ServerConnection::new(server).unwrap();
            conn.complete_io(&mut sock).unwrap();

            let mut stream = Stream::new(&mut conn, &mut sock);
            stream.write_all(b"FOO:").unwrap();
            loop {
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    conn.send_close_notify();
                    conn.complete_io(&mut sock).unwrap();
                    break;
                }
                stream.write_all(&buf[..n]).unwrap();
            }
        });
    });

    let client = Arc::new(client);
    let addr = SocketAddr::from(([127, 0, 0, 1], server_port));

    let _ = send(client.clone(), addr, b"hello", false).await?;

    Ok(())
}

// Include `utils` module
include!("utils.rs");
