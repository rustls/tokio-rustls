use std::future::Future;
use std::io;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "early-data")]
use std::task::Waker;
use std::task::{Context, Poll};

#[cfg(feature = "early-data")]
use rustls::crypto::cipher::OutboundPlain;
use rustls::enums::ApplicationProtocol;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientSide, Connection, Tcp};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{IoSession, MidHandshake, Stream, TlsState};
use crate::{Buffered, TlsStreamParts};

/// A wrapper around a `rustls::ClientConfig`, providing an async `connect` method.
#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
    #[cfg(feature = "early-data")]
    early_data: bool,
}

impl TlsConnector {
    /// Enable 0-RTT.
    ///
    /// If you want to use 0-RTT,
    /// You must also set `ClientConfig.enable_early_data` to `true`.
    #[cfg(feature = "early-data")]
    pub fn early_data(mut self, flag: bool) -> Self {
        self.early_data = flag;
        self
    }

    /// Returns a future that performs a TLS handshake with `domain` using the `stream`.
    ///
    /// You likely want to wrap this in a timeout (for example with [`tokio::time::timeout`][])
    /// to bound the handshake time.
    ///
    /// [`tokio::time::timeout`]: https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
    #[inline]
    pub fn connect<IO>(&self, domain: ServerName<'static>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_impl(domain, stream, None, |_| ())
    }

    /// Similar to [`Self::connect()`], but calls `f` before performing the handshake.
    ///
    /// As with [`Self::connect()`] you likely want to wrap this in a timeout to
    /// bound the handshake time.
    ///
    /// The `f` handler is given a mutable reference to a [`ClientConnection`][] that can
    /// be used for tasks like writing early data.
    ///
    /// [`ClientConnection`]: https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html
    #[inline]
    pub fn connect_with<IO, F>(&self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut Connection<ClientSide, Tcp>),
    {
        self.connect_impl(domain, stream, None, f)
    }

    fn connect_impl<IO, F>(
        &self,
        domain: ServerName<'static>,
        stream: IO,
        alpn_protocols: Option<Vec<ApplicationProtocol<'static>>>,
        f: F,
    ) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut Connection<ClientSide, Tcp>),
    {
        let mut builder = self.inner.connect(domain);
        if let Some(alpn_protocols) = alpn_protocols {
            builder = builder.with_alpn(alpn_protocols);
        }

        let mut tls = Vec::with_capacity(16_384);
        let mut conn = match builder.build(&mut tls) {
            Ok(session) => session,
            Err(error) => {
                return Connect(MidHandshake::Error {
                    io: stream,
                    // TODO(eliza): should this really return an `io::Error`?
                    // Probably not...
                    error: io::Error::new(io::ErrorKind::Other, error),
                });
            }
        };
        f(&mut conn);

        Connect(MidHandshake::Handshaking(TlsStream {
            io: stream,

            #[cfg(not(feature = "early-data"))]
            state: TlsState::Stream,

            #[cfg(feature = "early-data")]
            state: if self.early_data && conn.early_data().is_some() {
                TlsState::EarlyData(0, Vec::new())
            } else {
                TlsState::Stream
            },

            need_flush: false,
            error: None,

            #[cfg(feature = "early-data")]
            early_waker: None,

            buffered: Buffered::new(conn, tls),
        }))
    }

    pub fn with_alpn(
        &self,
        alpn_protocols: Vec<ApplicationProtocol<'static>>,
    ) -> TlsConnectorWithAlpn<'_> {
        TlsConnectorWithAlpn {
            inner: self,
            alpn_protocols,
        }
    }

    /// Get a read-only reference to underlying config
    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.inner
    }
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> Self {
        Self {
            inner,
            #[cfg(feature = "early-data")]
            early_data: false,
        }
    }
}

pub struct TlsConnectorWithAlpn<'c> {
    inner: &'c TlsConnector,
    alpn_protocols: Vec<ApplicationProtocol<'static>>,
}

impl TlsConnectorWithAlpn<'_> {
    /// Returns a future that performs a TLS handshake with `domain` using the `stream`.
    ///
    /// You likely want to wrap this in a timeout (for example with [`tokio::time::timeout`][])
    /// to bound the handshake time.
    ///
    /// [`tokio::time::timeout`]: https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
    #[inline]
    pub fn connect<IO>(self, domain: ServerName<'static>, stream: IO) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), |_| ())
    }

    /// Similar to [`Self::connect()`], but calls `f` before performing the handshake.
    ///
    /// As with [`Self::connect()`] you likely want to wrap this in a timeout to
    /// bound the handshake time.
    ///
    /// The `f` handler is given a mutable reference to a [`ClientConnection`][] that can
    /// be used for tasks like writing early data.
    ///
    /// [`ClientConnection`]: https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html
    #[inline]
    pub fn connect_with<IO, F>(self, domain: ServerName<'static>, stream: IO, f: F) -> Connect<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut Connection<ClientSide, Tcp>),
    {
        self.inner
            .connect_impl(domain, stream, Some(self.alpn_protocols), f)
    }
}

/// Future returned from `TlsConnector::connect` which will resolve
/// once the connection handshake has finished.
pub struct Connect<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Connect<IO> {
    #[inline]
    pub fn into_fallible(self) -> FallibleConnect<IO> {
        FallibleConnect(self.0)
    }

    pub fn get_ref(&self) -> Option<&IO> {
        match &self.0 {
            MidHandshake::Handshaking(sess) => Some(sess.get_ref().0),
            MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }

    pub fn get_mut(&mut self) -> Option<&mut IO> {
        match &mut self.0 {
            MidHandshake::Handshaking(sess) => Some(sess.get_mut().0),
            MidHandshake::SendAlert { io, .. } => Some(io),
            MidHandshake::Error { io, .. } => Some(io),
            MidHandshake::End => None,
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Connect<IO> {
    type Output = io::Result<TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleConnect<IO> {
    type Output = Result<TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// Like [Connect], but returns `IO` on failure.
pub struct FallibleConnect<IO>(MidHandshake<TlsStream<IO>>);

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) buffered: Buffered<ClientSide>,
    pub(crate) state: TlsState,
    pub(crate) need_flush: bool,
    /// Buffered error that occurred during batch reading
    pub(crate) error: Option<io::Error>,

    #[cfg(feature = "early-data")]
    pub(crate) early_waker: Option<Waker>,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &Connection<ClientSide, Tcp>) {
        (&self.io, &self.buffered.conn)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut Connection<ClientSide, Tcp>) {
        (&mut self.io, &mut self.buffered.conn)
    }

    /// Consumes the `TlsStream`, returning its underlying parts.
    #[inline]
    pub fn into_inner(self) -> TlsStreamParts<IO, ClientSide> {
        let mut input = self.buffered.input;
        input.truncate(self.buffered.used);

        TlsStreamParts {
            io: self.io,
            conn: self.buffered.conn,
            input,
            tls: self.buffered.tls,
            received_plaintext: self.buffered.received_plaintext,
        }
    }

    /// Assembles a stream from an `IO`, the connection and its buffers.
    ///
    /// This is the inverse of [`Self::into_inner()`]. It allows an established
    /// connection to be wrapped around a different `IO`, for example to move it
    /// to another runtime via `TcpStream::into_std()` and `TcpStream::from_std()`,
    /// or to wrap a connection whose handshake was driven outside of this crate.
    ///
    /// The connection must have completed its handshake, because the `TlsStream` is
    /// unable to drive handshakes (checked with a `debug_assert!`), and it must
    /// not have been shut down.
    #[inline]
    pub fn from_parts(parts: TlsStreamParts<IO, ClientSide>) -> Self {
        let TlsStreamParts {
            io,
            conn,
            input,
            tls,
            received_plaintext,
        } = parts;

        debug_assert!(
            !conn.is_handshaking(),
            "TlsStream::from_parts() requires a completed handshake"
        );

        let buffered = Buffered {
            conn,
            used: input.len(),
            input,
            tls,
            received_plaintext,
            received_close_notify: false,
            has_seen_eof: false,
        };

        Self {
            io,
            buffered,
            state: TlsState::Stream,
            need_flush: false,
            error: None,
            #[cfg(feature = "early-data")]
            early_waker: None,
        }
    }
}

#[cfg(unix)]
impl<S> AsRawFd for TlsStream<S>
where
    S: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<S> AsRawSocket for TlsStream<S>
where
    S: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Side = ClientSide;

    #[inline]
    fn skip_handshake(&self) -> bool {
        self.state.is_early_data()
    }

    #[inline]
    fn get_mut(
        &mut self,
    ) -> (
        &mut TlsState,
        &mut Self::Io,
        &mut Buffered<ClientSide>,
        &mut bool,
    ) {
        (
            &mut self.state,
            &mut self.io,
            &mut self.buffered,
            &mut self.need_flush,
        )
    }

    #[inline]
    fn into_io(self) -> Self::Io {
        self.io
    }
}

#[cfg(feature = "early-data")]
impl<IO> TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_early_data(&mut self, cx: &mut Context<'_>) {
        // In the EarlyData state, we have not really established a Tls connection.
        // Before writing data through `AsyncWrite` and completing the tls handshake,
        // we ignore read readiness and return to pending.
        //
        // In order to avoid event loss,
        // we need to register a waker and wake it up after tls is connected.
        if self
            .early_waker
            .as_ref()
            .filter(|waker| cx.waker().will_wake(waker))
            .is_none()
        {
            self.early_waker = Some(cx.waker().clone());
        }
    }
}

impl<IO> AsyncRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(err) = self.error.take() {
            return Poll::Ready(Err(err));
        };
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let len = data.len().min(buf.remaining());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        buf.put_slice(&data[..len]);
        self.as_mut().consume(len);

        while buf.remaining() > 0 {
            let data = match self.as_mut().poll_fill_buf(cx) {
                Poll::Ready(Ok([])) => break,
                Poll::Ready(Ok(data)) => data,
                Poll::Ready(Err(err)) => {
                    self.error = Some(err);
                    break;
                }
                Poll::Pending => break,
            };
            let len = Ord::min(data.len(), buf.remaining());
            buf.put_slice(&data[..len]);
            self.as_mut().consume(len);
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncBufRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.state {
            #[cfg(feature = "early-data")]
            TlsState::EarlyData(..) => {
                self.get_mut().poll_early_data(cx);
                Poll::Pending
            }
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let stream = Stream::new(&mut this.io, &mut this.buffered);

                match stream.poll_fill_buf(cx) {
                    Poll::Ready(Ok(buf)) => {
                        if buf.is_empty() {
                            this.state.shutdown_read();
                        }

                        Poll::Ready(Ok(buf))
                    }
                    Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        this.state.shutdown_read();
                        Poll::Ready(Err(err))
                    }
                    output => output,
                }
            }
            TlsState::ReadShutdown | TlsState::FullyShutdown => Poll::Ready(Ok(&[])),
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        let Self { io, buffered, .. } = &mut *self;
        Pin::new(&mut Stream::new(io, buffered)).consume(amt);
    }
}

impl<IO> AsyncWrite for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.buffered).set_need_flush(this.need_flush);

        #[cfg(feature = "early-data")]
        {
            let bufs = [io::IoSlice::new(buf)];
            let written = poll_handle_early_data(
                &mut this.state,
                &mut stream,
                &mut this.early_waker,
                cx,
                &bufs,
            )?;
            match written {
                Poll::Ready(0) => {}
                Poll::Ready(written) => return Poll::Ready(Ok(written)),
                Poll::Pending => {
                    this.need_flush = stream.need_flush;
                    return Poll::Pending;
                }
            }
        }

        stream.as_mut_pin().poll_write(cx, buf)
    }

    /// Note: that it does not guarantee the final data to be sent.
    /// To be cautious, you must manually call `flush`.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.buffered).set_need_flush(this.need_flush);

        #[cfg(feature = "early-data")]
        {
            let written = poll_handle_early_data(
                &mut this.state,
                &mut stream,
                &mut this.early_waker,
                cx,
                bufs,
            )?;
            match written {
                Poll::Ready(0) => {}
                Poll::Ready(written) => return Poll::Ready(Ok(written)),
                Poll::Pending => {
                    this.need_flush = stream.need_flush;
                    return Poll::Pending;
                }
            }
        }

        stream.as_mut_pin().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream =
            Stream::new(&mut this.io, &mut this.buffered).set_need_flush(this.need_flush);

        #[cfg(feature = "early-data")]
        {
            let written = poll_handle_early_data(
                &mut this.state,
                &mut stream,
                &mut this.early_waker,
                cx,
                &[],
            )?;
            if written.is_pending() {
                this.need_flush = stream.need_flush;
                return Poll::Pending;
            }
        }

        stream.as_mut_pin().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        #[cfg(feature = "early-data")]
        {
            // complete handshake
            if matches!(self.state, TlsState::EarlyData(..)) {
                ready!(self.as_mut().poll_flush(cx))?;
            }
        }

        let this = self.get_mut();
        if this.state.writeable() {
            if let Err(err) = this.buffered.conn.send_close_notify(&mut this.buffered.tls) {
                return Poll::Ready(Err(io::Error::other(err)));
            }
            this.state.shutdown_write();
        }

        let mut stream = Stream::new(&mut this.io, &mut this.buffered);
        stream.as_mut_pin().poll_shutdown(cx)
    }
}

#[cfg(feature = "early-data")]
fn poll_handle_early_data<IO>(
    state: &mut TlsState,
    stream: &mut Stream<IO, ClientSide>,
    early_waker: &mut Option<Waker>,
    cx: &mut Context<'_>,
    bufs: &[io::IoSlice<'_>],
) -> Poll<io::Result<usize>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    if let TlsState::EarlyData(pos, data) = state {
        // write early data
        if let Some(mut early_data) = stream.buffered.conn.early_data() {
            let (mut chunks, mut non_empty, mut end) =
                (Vec::<&[u8]>::with_capacity(bufs.len()), false, 0);
            for buf in bufs {
                if buf.is_empty() {
                    continue;
                }

                chunks.push(&*buf);
                non_empty |= true;
                end += buf.len();
            }

            if non_empty {
                let plaintext = OutboundPlain::Multiple {
                    chunks: &chunks,
                    start: 0,
                    end,
                };

                let written = match early_data.write(plaintext, &mut stream.buffered.tls) {
                    Ok(written) => written,
                    Err(err) => return Poll::Ready(Err(io::Error::other(err))),
                };

                if written != 0 {
                    // Keep the early data around to resend it if the server rejects it
                    OutboundPlain::Multiple {
                        chunks: &chunks,
                        start: 0,
                        end: written,
                    }
                    .copy_to_vec(data);
                    return Poll::Ready(Ok(written));
                }
            }
        }

        // complete handshake
        while stream.buffered.conn.is_handshaking() {
            ready!(stream.handshake(cx))?;
        }

        // write early data (fallback)
        if !stream.buffered.conn.side().is_early_data_accepted() {
            while *pos < data.len() {
                let len = ready!(stream.as_mut_pin().poll_write(cx, &data[*pos..]))?;
                *pos += len;
            }
        }

        // end
        *state = TlsState::Stream;

        if let Some(waker) = early_waker.take() {
            waker.wake();
        }
    }

    Poll::Ready(Ok(0))
}
