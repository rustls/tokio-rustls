use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};

use rustls::server::AcceptedAlert;
use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{PacketProcessingMode, Stream, SyncWriteAdapter, TlsState};

#[cfg(feature = "vacation")]
use super::async_session::AsyncSession;

pub(crate) trait IoSession {
    type Io;
    type Session;
    type Extras;

    fn skip_handshake(&self) -> bool;
    fn get_mut(&mut self) -> (&mut TlsState, &mut Self::Io, &mut Self::Session);
    fn into_io(self) -> Self::Io;
    #[allow(dead_code)]
    fn into_inner(self) -> (TlsState, Self::Io, Self::Session, Self::Extras);
    #[allow(dead_code)]
    fn from_inner(
        state: TlsState,
        io: Self::Io,
        session: Self::Session,
        extras: Self::Extras,
    ) -> Self;
}

pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    #[cfg(feature = "vacation")]
    AsyncSession(AsyncSession<IS>),
    End,
    SendAlert {
        io: IS::Io,
        alert: AcceptedAlert,
        error: io::Error,
    },
    Error {
        io: IS::Io,
        error: io::Error,
    },
}
impl<IS, SD> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin + Send + 'static,
    SD: SideData,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, MidHandshake::End) {
            MidHandshake::Handshaking(stream) => stream,
            #[cfg(feature = "vacation")]
            MidHandshake::AsyncSession(mut async_session) => {
                let pinned = Pin::new(&mut async_session);
                let session_result = ready!(pinned.poll(cx));
                async_session.into_stream(session_result, cx)?
            }
            MidHandshake::SendAlert {
                mut io,
                mut alert,
                error,
            } => loop {
                match alert.write(&mut SyncWriteAdapter { io: &mut io, cx }) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        *this = MidHandshake::SendAlert { io, error, alert };
                        return Poll::Pending;
                    }
                    Err(_) | Ok(0) => return Poll::Ready(Err((error, io))),
                    Ok(_) => {}
                };
            },
            // Starting the handshake returned an error; fail the future immediately.
            MidHandshake::Error { io, error } => return Poll::Ready(Err((error, io))),
            _ => panic!("unexpected polling after handshake"),
        };

        if !stream.skip_handshake() {
            let (state, io, session) = stream.get_mut();
            let mut tls_stream = Stream::new(io, session).set_eof(!state.readable());

            macro_rules! try_poll {
                ( $e:expr ) => {
                    match $e {
                        Poll::Ready(Ok(_)) => (),
                        #[cfg(feature = "vacation")]
                        Poll::Ready(Err(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                            // TODO: downcast to decide on closure, for now we only do this for
                            // process_packets

                            // decompose the stream and send the session to background executor
                            let mut async_session = AsyncSession::process_packets(stream);

                            let pinned = Pin::new(&mut async_session);
                            // poll once to kick off work
                            match pinned.poll(cx) {
                                // didn't need to sleep for async session
                                Poll::Ready(res) => {
                                    let stream = async_session.into_stream(res, cx)?;
                                    // rather than continuing processing here,
                                    // we keep memory  management simple and recompose
                                    // our future for a fresh poll
                                    *this = MidHandshake::Handshaking(stream);
                                    // tell executor to immediately poll us again
                                    cx.waker().wake_by_ref();
                                    return Poll::Pending;
                                }
                                // task is sleeping until async session is complete
                                Poll::Pending => {
                                    *this = MidHandshake::AsyncSession(async_session);
                                    return Poll::Pending;
                                }
                            }
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err((err, stream.into_io()))),
                        Poll::Pending => {
                            *this = MidHandshake::Handshaking(stream);
                            return Poll::Pending;
                        }
                    }
                };
            }

            while tls_stream.session.is_handshaking() {
                #[cfg(feature = "vacation")]
                try_poll!(tls_stream.handshake(cx, PacketProcessingMode::Async));
                #[cfg(not(feature = "vacation"))]
                try_poll!(tls_stream.handshake(cx, PacketProcessingMode::Sync));
            }

            try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
        }

        Poll::Ready(Ok(stream))
    }
}
