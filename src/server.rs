use std::future::Future;
use std::io::{self, Write as _};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::server::{NeedsInput, ServerHandshake};
use rustls::{Connection as _, ServerConfig, ServerConnection, VecInput};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{
    CursorVec, IoSession, IoSessionParts, MidHandshake, Stream, SyncReadAdapter, SyncWriteAdapter,
    TlsState,
};

/// A wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> Self {
        Self { inner }
    }
}

impl TlsAcceptor {
    /// Returns a future for completing a TLS handshake for a client using `stream`.
    ///
    /// You likely want to wrap this in a timeout (for example with [`tokio::time::timeout`][])
    /// to bound the handshake time.
    ///
    /// [`tokio::time::timeout`]: https://docs.rs/tokio/latest/tokio/time/fn.timeout.html
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with(stream, |_| ())
    }

    /// Similar to [`Self::accept()`], but calls `f` before performing the handshake.
    ///
    /// As with [`Self::accept()`] you likely want to wrap this in a timeout to
    /// bound the handshake time.
    ///
    /// The `f` handler is given a mutable reference to a [`ServerConnection`][] that can be used
    /// to configure the connection before the handshake.
    ///
    /// Because no data has been read from `stream` yet when `f` is called ClientHello
    /// dependent state (like early data) is not yet available.
    ///
    /// [`ServerConnection`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html
    pub fn accept_with<IO, F>(&self, stream: IO, f: F) -> Accept<IO>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
        F: FnOnce(&mut ServerConnection),
    {
        let mut session = match ServerConnection::new(self.inner.clone()) {
            Ok(session) => session,
            Err(error) => {
                return Accept(MidHandshake::Error {
                    io: stream,
                    // TODO(eliza): should this really return an `io::Error`?
                    // Probably not...
                    error: io::Error::other(error),
                });
            }
        };
        f(&mut session);

        Accept(MidHandshake::Handshaking(TlsStream {
            session,
            io: stream,
            input: VecInput::default(),
            tls: CursorVec::default(),
            plaintext: CursorVec::default(),
            state: TlsState::Stream,
            need_flush: false,
        }))
    }

    /// Get a read-only reference to underlying config
    pub fn config(&self) -> &Arc<ServerConfig> {
        &self.inner
    }
}

/// A future for reading a `ClientHello` from `io` without committing to a [`ServerConfig`][].
///
/// Awaiting it yields a [`StartHandshake`], which exposes the
/// [`ClientHello`][] (for example, to choose a config based on SNI) and performs
/// the rest of the handshake via [`StartHandshake::into_stream()`].
///
/// [`ServerConfig`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConfig.html
/// [`ClientHello`]: https://docs.rs/rustls/latest/rustls/server/struct.ClientHello.html
pub struct LazyConfigAcceptor<IO> {
    handshake: Option<NeedsInput>,
    io: Option<IO>,
    input: VecInput,
    tls: CursorVec,
    error: Option<io::Error>,
    flush_error: bool,
}

impl<IO> LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns a new `LazyConfigAcceptor` that reads a `ClientHello` from `io`.
    ///
    /// You likely want to wrap awaiting the acceptor in a timeout to bound how long the
    /// peer may take to send the `ClientHello`.
    ///
    /// Note that awaiting the acceptor is only the first half of the handshake and
    /// [`StartHandshake::into_stream()`] performs the rest.
    ///
    /// To bound the time for the complete handshake, share one deadline across
    /// both awaits (for example with [`tokio::time::timeout_at`][]) rather than giving each
    /// its own timeout.
    ///
    /// If a timeout elapses before the `ClientHello` arrives, [`Self::take_io()`] can
    /// recover the `io`, for example to answer the peer in plaintext before closing.
    ///
    /// [`tokio::time::timeout_at`]: https://docs.rs/tokio/latest/tokio/time/fn.timeout_at.html
    #[inline]
    pub fn new(io: IO) -> Self {
        Self {
            handshake: Some(ServerHandshake::start()),
            io: Some(io),
            input: VecInput::default(),
            tls: CursorVec::default(),
            error: None,
            flush_error: false,
        }
    }

    /// Takes back the client connection. Will return `None` if called more than once or if the
    /// connection has been accepted.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn choose_server_config(
    /// #     _: rustls::server::ClientHello,
    /// # ) -> std::sync::Arc<rustls::ServerConfig> {
    /// #     unimplemented!();
    /// # }
    /// # #[allow(unused_variables)]
    /// # async fn listen() {
    /// use tokio::io::AsyncWriteExt;
    /// let listener = tokio::net::TcpListener::bind("127.0.0.1:4443").await.unwrap();
    /// let (stream, _) = listener.accept().await.unwrap();
    ///
    /// let acceptor = tokio_rustls::LazyConfigAcceptor::new(stream);
    /// tokio::pin!(acceptor);
    ///
    /// match acceptor.as_mut().await {
    ///     Ok(start) => {
    ///         let clientHello = start.client_hello();
    ///         let config = choose_server_config(clientHello);
    ///         let stream = start.into_stream(config).await.unwrap();
    ///         // Proceed with handling the ServerConnection...
    ///     }
    ///     Err(err) => {
    ///         if let Some(mut stream) = acceptor.take_io() {
    ///             stream
    ///                 .write_all(
    ///                     format!("HTTP/1.1 400 Invalid Input\r\n\r\n\r\n{:?}\n", err)
    ///                         .as_bytes()
    ///                 )
    ///                 .await
    ///                 .unwrap();
    ///         }
    ///     }
    /// }
    /// # }
    /// ```
    pub fn take_io(&mut self) -> Option<IO> {
        self.io.take()
    }
}

impl<IO> Future for LazyConfigAcceptor<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<StartHandshake<IO>, io::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            let io = match this.io.as_mut() {
                Some(io) => io,
                None => {
                    return Poll::Ready(Err(io::Error::other(
                        "acceptor cannot be polled after acceptance",
                    )));
                }
            };

            while !this.tls.is_empty() {
                let available = this.tls.len();
                match (SyncWriteAdapter { io, cx }).write(this.tls.pending()) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                    Err(e) => {
                        return Poll::Ready(Err(this.error.take().unwrap_or(e)));
                    }
                    Ok(0) => {
                        return Poll::Ready(Err(this
                            .error
                            .take()
                            .unwrap_or_else(|| io::ErrorKind::WriteZero.into())));
                    }
                    Ok(written) if written > available => {
                        this.tls.clear();
                        return Poll::Ready(Err(this.error.take().unwrap_or_else(|| {
                            io::Error::other(format!(
                                "illegal poll_write() return value ({written} > {available})"
                            ))
                        })));
                    }
                    Ok(written) => {
                        this.tls.consume(written);
                    }
                }
            }

            if this.error.is_some() {
                if this.flush_error {
                    match Pin::new(io).poll_flush(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(_) => {}
                    }
                }
                return Poll::Ready(Err(this.error.take().unwrap()));
            }

            let Some(handshake) = this.handshake.take() else {
                return Poll::Ready(Err(io::Error::other(
                    "acceptor cannot be polled after acceptance",
                )));
            };

            let mut reader = SyncReadAdapter { io, cx };
            match this.input.read(&mut reader) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()).into(),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    this.handshake = Some(handshake);
                    return Poll::Pending;
                }
                Err(e) => return Err(e).into(),
            }

            match handshake.process(&mut this.input, this.tls.append_vec()) {
                Ok(ServerHandshake::Accepted(accepted)) => {
                    let io = this.io.take().unwrap();
                    return Poll::Ready(Ok(StartHandshake {
                        accepted,
                        io,
                        input: std::mem::take(&mut this.input),
                        tls: std::mem::take(&mut this.tls),
                    }));
                }
                Ok(ServerHandshake::NeedsInput(next)) => {
                    this.handshake = Some(next);
                }
                Ok(_) => {
                    return Poll::Ready(Err(io::Error::other(
                        "unexpected server handshake state before configuration",
                    )));
                }
                Err(error) => {
                    this.flush_error = !this.tls.is_empty();
                    this.error = Some(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            }
        }
    }
}

/// An incoming connection received through [`LazyConfigAcceptor`].
///
/// This contains the generic `IO` asynchronous transport,
/// [`ClientHello`](rustls::server::ClientHello) data,
/// and all the state required to continue the TLS handshake (e.g. via
/// [`StartHandshake::into_stream`]).
#[non_exhaustive]
#[derive(Debug)]
pub struct StartHandshake<IO> {
    accepted: rustls::server::Accepted,
    io: IO,
    input: VecInput,
    tls: CursorVec,
}

impl<IO> StartHandshake<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns a reference to the underlying transport.
    pub fn get_ref(&self) -> &IO {
        &self.io
    }

    /// Returns a mutable reference to the underlying transport.
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    pub fn client_hello(&self) -> rustls::server::ClientHello<'_> {
        self.accepted.client_hello()
    }

    /// Returns a future that performs the rest of the TLS handshake using `config`.
    ///
    /// You likely want to wrap this in a timeout to bound the handshake time. Ideally
    /// with [`tokio::time::timeout_at`][], reusing the deadline that also bounded
    /// awaiting the [`LazyConfigAcceptor`] so both halves of the handshake share
    /// one budget. See [`LazyConfigAcceptor::new()`].
    ///
    /// [`tokio::time::timeout_at`]: https://docs.rs/tokio/latest/tokio/time/fn.timeout_at.html
    pub fn into_stream(self, config: Arc<ServerConfig>) -> Accept<IO> {
        self.into_stream_with(config, |_| ())
    }

    /// Similar to [`Self::into_stream()`], but calls `f` before performing the handshake.
    ///
    /// As with [`Self::into_stream()`] you likely want to wrap this in a timeout to
    /// bound the handshake time.
    ///
    /// The `f` handler is given a mutable reference to a [`ServerConnection`][] that can be
    /// used to configure the connection before the handshake.
    ///
    /// [`ServerConnection`]: https://docs.rs/rustls/latest/rustls/server/struct.ServerConnection.html
    pub fn into_stream_with<F>(self, config: Arc<ServerConfig>, f: F) -> Accept<IO>
    where
        F: FnOnce(&mut ServerConnection),
    {
        let Self {
            accepted,
            io,
            input,
            mut tls,
        } = self;
        let mut conn = match accepted.choose_config(config, tls.append_vec()) {
            Ok(ServerHandshake::NeedsInput(next)) => next.into_buffered_connection(),
            Ok(_) => {
                return Accept(MidHandshake::Error {
                    io,
                    error: io::Error::other(
                        "unexpected server handshake state after choosing configuration",
                    ),
                });
            }
            Err(error) => {
                // TODO(eliza): should this really return an `io::Error`?
                // Probably not...
                let error = io::Error::new(io::ErrorKind::InvalidData, error);
                return Accept(if tls.is_empty() {
                    MidHandshake::Error { io, error }
                } else {
                    MidHandshake::SendAlert {
                        io,
                        alert: tls,
                        error,
                    }
                });
            }
        };
        f(&mut conn);

        Accept(MidHandshake::Handshaking(TlsStream {
            session: conn,
            io,
            input,
            tls,
            plaintext: CursorVec::default(),
            state: TlsState::Stream,
            need_flush: false,
        }))
    }
}

/// Future returned from `TlsAcceptor::accept` which will resolve
/// once the accept handshake has finished.
pub struct Accept<IO>(MidHandshake<TlsStream<IO>>);

impl<IO> Accept<IO> {
    #[inline]
    pub fn into_fallible(self) -> FallibleAccept<IO> {
        FallibleAccept(self.0)
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

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for Accept<IO> {
    type Output = io::Result<TlsStream<IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map_err(|(err, _)| err)
    }
}

/// Like [Accept], but returns `IO` on failure.
pub struct FallibleAccept<IO>(MidHandshake<TlsStream<IO>>);

impl<IO: AsyncRead + AsyncWrite + Unpin> Future for FallibleAccept<IO> {
    type Output = Result<TlsStream<IO>, (io::Error, IO)>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
#[derive(Debug)]
pub struct TlsStream<IO> {
    pub(crate) io: IO,
    pub(crate) session: ServerConnection,
    pub(crate) input: VecInput,
    pub(crate) tls: CursorVec,
    pub(crate) plaintext: CursorVec,
    pub(crate) state: TlsState,
    pub(crate) need_flush: bool,
}

impl<IO> TlsStream<IO> {
    #[inline]
    pub fn get_ref(&self) -> (&IO, &ServerConnection) {
        (&self.io, &self.session)
    }

    #[inline]
    pub fn get_mut(&mut self) -> (&mut IO, &mut ServerConnection) {
        (&mut self.io, &mut self.session)
    }

    /// Extract the transport and rustls connection.
    ///
    /// Any buffered TLS or plaintext data is discarded.
    #[inline]
    pub fn into_inner(self) -> (IO, ServerConnection) {
        (self.io, self.session)
    }
}

impl<IO> IoSession for TlsStream<IO> {
    type Io = IO;
    type Session = ServerConnection;

    #[inline]
    fn skip_handshake(&self) -> bool {
        false
    }

    #[inline]
    fn get_mut(&mut self) -> IoSessionParts<'_, Self::Io, Self::Session> {
        IoSessionParts {
            state: &mut self.state,
            io: &mut self.io,
            session: &mut self.session,
            input: &mut self.input,
            tls: &mut self.tls,
            plaintext: &mut self.plaintext,
            need_flush: &mut self.need_flush,
        }
    }

    #[inline]
    fn into_io_tls(self) -> (Self::Io, CursorVec) {
        (self.io, self.tls)
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
        let data = ready!(self.as_mut().poll_fill_buf(cx))?;
        let len = data.len().min(buf.remaining());
        buf.put_slice(&data[..len]);
        self.consume(len);
        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncBufRead for TlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        match self.state {
            TlsState::Stream | TlsState::WriteShutdown => {
                let this = self.get_mut();
                let stream = Stream::new(
                    &mut this.io,
                    &mut this.session,
                    &mut this.input,
                    &mut this.tls,
                    &mut this.plaintext,
                )
                .set_eof(!this.state.readable());

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
            #[cfg(feature = "early-data")]
            ref s => unreachable!("server TLS can not hit this state: {:?}", s),
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.plaintext.consume(amt);
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
        let mut stream = Stream::new(
            &mut this.io,
            &mut this.session,
            &mut this.input,
            &mut this.tls,
            &mut this.plaintext,
        )
        .set_eof(!this.state.readable());
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
        let mut stream = Stream::new(
            &mut this.io,
            &mut this.session,
            &mut this.input,
            &mut this.tls,
            &mut this.plaintext,
        )
        .set_eof(!this.state.readable());
        stream.as_mut_pin().poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut stream = Stream::new(
            &mut this.io,
            &mut this.session,
            &mut this.input,
            &mut this.tls,
            &mut this.plaintext,
        )
        .set_eof(!this.state.readable());
        stream.as_mut_pin().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.writeable() {
            let this = self.as_mut().get_mut();
            this.session.send_close_notify(this.tls.append_vec());
            self.state.shutdown_write();
        }

        let this = self.get_mut();
        let mut stream = Stream::new(
            &mut this.io,
            &mut this.session,
            &mut this.input,
            &mut this.tls,
            &mut this.plaintext,
        )
        .set_eof(!this.state.readable());
        stream.as_mut_pin().poll_shutdown(cx)
    }
}

#[cfg(unix)]
impl<IO> AsRawFd for TlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.get_ref().0.as_raw_fd()
    }
}

#[cfg(windows)]
impl<IO> AsRawSocket for TlsStream<IO>
where
    IO: AsRawSocket,
{
    fn as_raw_socket(&self) -> RawSocket {
        self.get_ref().0.as_raw_socket()
    }
}
