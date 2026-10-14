use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::future::poll_fn;
use futures_util::task::noop_waker_ref;
use rustls::crypto::cipher::OutboundPlain;
use rustls::pki_types::ServerName;
use rustls::{ClientSide, Connection, ServerSide, SideData};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::Stream;
use crate::{Buffered, TLS_BUFFER_LIMIT};

impl<Side: SideData> Buffered<Side> {
    fn process_new_packets(&mut self) -> io::Result<()> {
        self.process_input()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(())
    }

    fn send_close_notify(&mut self) -> io::Result<()> {
        self.conn
            .send_close_notify(&mut self.tls)
            .map_err(io::Error::other)
    }
}

struct Good<'a, Side: SideData>(&'a mut Buffered<Side>);

impl<Side: SideData> AsyncRead for Good<'_, Side> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let tls = &mut self.0.tls;
        if tls.is_empty() {
            return Poll::Pending;
        }

        let n = Ord::min(buf.remaining(), tls.len());
        buf.put_slice(&tls[..n]);
        tls.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl<Side: SideData> AsyncWrite for Good<'_, Side> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = self.0.read_buf()?;
        let len = Ord::min(read_buf.remaining(), buf.len());
        read_buf.put_slice(&buf[..len]);
        self.0.used += len;
        self.0.process_new_packets()?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.process_new_packets()?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send_close_notify()?;
        dbg!("sent close notify");
        self.poll_flush(cx)
    }
}

struct Pending;

impl AsyncRead for Pending {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Pending {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Expected(Cursor<Vec<u8>>);

impl AsyncRead for Expected {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = std::io::Read::read(&mut this.0, buf.initialize_unfilled())?;
        buf.advance(n);

        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Expected {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Eof;

impl AsyncRead for Eof {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Eof {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn stream_good() -> io::Result<()> {
    stream_good_impl(false, false).await
}

#[tokio::test]
async fn stream_good_vectored() -> io::Result<()> {
    stream_good_impl(true, false).await
}

#[tokio::test]
async fn stream_good_bufread() -> io::Result<()> {
    stream_good_impl(false, true).await
}

async fn stream_good_impl(vectored: bool, bufread: bool) -> io::Result<()> {
    const FILE: &[u8] = include_bytes!("../../README.md");

    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    server
        .conn
        .write(OutboundPlain::from(FILE), &mut server.tls)
        .map_err(io::Error::other)?;
    server.send_close_notify()?;

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client);

        let mut buf = Vec::new();
        if bufread {
            dbg!(tokio::io::copy_buf(&mut stream, &mut buf).await)?;
        } else {
            dbg!(stream.read_to_end(&mut buf).await)?;
        }
        assert_eq!(buf, FILE);

        dbg!(utils::write(&mut stream, b"Hello World!", vectored).await)?;
        stream.buffered.send_close_notify()?;

        dbg!(stream.shutdown().await)?;
    }

    dbg!(server.process_new_packets())?;
    assert_eq!(server.received_plaintext, b"Hello World!");

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_bad() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut bad = Pending;
    let mut stream = Stream::new(&mut bad, &mut client);
    assert_eq!(
        poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
        8
    );
    assert_eq!(
        poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
        8
    );
    let fill = vec![0x00; TLS_BUFFER_LIMIT];
    let r = poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &fill)).await?; // fill buffer
    assert!(r < TLS_BUFFER_LIMIT);

    let mut cx = Context::from_waker(noop_waker_ref());
    let ret = stream.as_mut_pin().poll_write(&mut cx, &[0x01]);
    assert!(ret.is_pending());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake() -> io::Result<()> {
    let (mut server, mut client) = make_pair();

    {
        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client);
        let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

        assert!(r > 0);
        assert!(w > 0);

        poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
    }

    assert!(!server.conn.is_handshaking());
    assert!(!client.conn.is_handshaking());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_buffered_handshake() -> io::Result<()> {
    use tokio::io::BufWriter;

    let (mut server, mut client) = make_pair();

    {
        let mut good = BufWriter::new(Good(&mut server));
        let mut stream = Stream::new(&mut good, &mut client);
        let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

        assert!(r > 0);
        assert!(w > 0);

        poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
    }

    assert!(!server.conn.is_handshaking());
    assert!(!client.conn.is_handshaking());

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake_eof() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut bad = Expected(Cursor::new(Vec::new()));
    let mut stream = Stream::new(&mut bad, &mut client);

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_handshake_write_eof() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut io = Eof;
    let mut stream = Stream::new(&mut io, &mut client);

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::WriteZero))
    );

    Ok(()) as io::Result<()>
}

// see https://github.com/tokio-rs/tls/issues/77
#[tokio::test]
async fn stream_handshake_regression_issues_77() -> io::Result<()> {
    let (_, mut client) = make_pair();

    let mut bad = Expected(Cursor::new(b"\x15\x03\x01\x00\x02\x02\x00".to_vec()));
    let mut stream = Stream::new(&mut bad, &mut client);

    let mut cx = Context::from_waker(noop_waker_ref());
    let r = stream.handshake(&mut cx);
    assert_eq!(
        r.map_err(|err| err.kind()),
        Poll::Ready(Err(io::ErrorKind::InvalidData))
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_eof() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut bad = Expected(Cursor::new(Vec::new()));
    let mut stream = Stream::new(&mut bad, &mut client);

    let mut buf = Vec::new();
    let result = stream.read_to_end(&mut buf).await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );

    Ok(()) as io::Result<()>
}

#[tokio::test]
async fn stream_write_zero() -> io::Result<()> {
    let (mut server, mut client) = make_pair();
    poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

    let mut io = Eof;
    let mut stream = Stream::new(&mut io, &mut client);

    stream.write_all(b"1").await.unwrap();
    let result = stream.flush().await;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(io::ErrorKind::WriteZero)
    );

    Ok(()) as io::Result<()>
}

fn make_pair() -> (Buffered<ServerSide>, Buffered<ClientSide>) {
    let (sconfig, cconfig) = utils::make_configs();
    let server = Connection::new(Arc::new(sconfig)).unwrap();

    let domain = ServerName::try_from("foobar.com").unwrap();
    let mut tls = Vec::new();
    let client = Arc::new(cconfig).connect(domain).build(&mut tls).unwrap();

    (
        Buffered::new(server, Vec::new()),
        Buffered::new(client, tls),
    )
}

fn do_handshake(
    client: &mut Buffered<ClientSide>,
    server: &mut Buffered<ServerSide>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let mut good = Good(server);
    let mut stream = Stream::new(&mut good, client);

    while stream.buffered.conn.is_handshaking() {
        ready!(stream.handshake(cx))?;
    }

    while !stream.buffered.tls.is_empty() {
        ready!(stream.write_io(cx))?;
    }

    Poll::Ready(Ok(()))
}

// Share `utils` module with integration tests
include!("../../tests/utils.rs");
