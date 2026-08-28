use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, mem};

use rustls::{Connection as RustlsConnection, VecInput};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::{CursorVec, Stream, SyncWriteAdapter, TlsState};

pub(crate) struct IoSessionParts<'a, IO, Session> {
    pub(crate) state: &'a mut TlsState,
    pub(crate) io: &'a mut IO,
    pub(crate) session: &'a mut Session,
    pub(crate) input: &'a mut VecInput,
    pub(crate) tls: &'a mut CursorVec,
    pub(crate) plaintext: &'a mut CursorVec,
    pub(crate) need_flush: &'a mut bool,
}

pub(crate) trait IoSession {
    type Io;
    type Session;

    fn skip_handshake(&self) -> bool;
    fn get_mut(&mut self) -> IoSessionParts<'_, Self::Io, Self::Session>;
    fn into_io_tls(self) -> (Self::Io, CursorVec);
}

pub(crate) enum MidHandshake<IS: IoSession> {
    Handshaking(IS),
    End,
    SendAlert {
        io: IS::Io,
        alert: CursorVec,
        error: io::Error,
    },
    Error {
        io: IS::Io,
        error: io::Error,
    },
}

impl<IS> Future for MidHandshake<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: RustlsConnection + Unpin,
{
    type Output = Result<IS, (io::Error, IS::Io)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let mut stream = match mem::replace(this, Self::End) {
            Self::Handshaking(stream) => stream,
            Self::SendAlert {
                mut io,
                mut alert,
                error,
            } => loop {
                if !alert.is_empty() {
                    let available = alert.len();
                    match (SyncWriteAdapter { io: &mut io, cx }).write(alert.pending()) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            *this = Self::SendAlert { io, error, alert };
                            return Poll::Pending;
                        }
                        Err(_) | Ok(0) => return Poll::Ready(Err((error, io))),
                        Ok(written) if written > available => {
                            alert.clear();
                            return Poll::Ready(Err((error, io)));
                        }
                        Ok(written) => {
                            alert.consume(written);
                            continue;
                        }
                    }
                }

                match Pin::new(&mut io).poll_flush(cx) {
                    Poll::Pending => {
                        *this = Self::SendAlert { io, error, alert };
                        return Poll::Pending;
                    }
                    Poll::Ready(_) => return Poll::Ready(Err((error, io))),
                }
            },
            // Starting the handshake returned an error; fail the future immediately.
            Self::Error { io, error } => return Poll::Ready(Err((error, io))),
            _ => panic!("unexpected polling after handshake"),
        };

        if !stream.skip_handshake() {
            let IoSessionParts {
                state,
                io,
                session,
                input,
                tls,
                plaintext,
                need_flush,
            } = stream.get_mut();
            let handshake_error = 'handshake: {
                let mut tls_stream = Stream::new(io, session, input, tls, plaintext)
                    .set_eof(!state.readable())
                    .set_need_flush(*need_flush);

                macro_rules! try_poll {
                    ( $e:expr ) => {
                        match $e {
                            Poll::Ready(Ok(x)) => x,
                            Poll::Ready(Err(err)) => {
                                break 'handshake Some((err, tls_stream.need_flush));
                            }
                            Poll::Pending => {
                                *need_flush = tls_stream.need_flush;
                                *this = MidHandshake::Handshaking(stream);
                                return Poll::Pending;
                            }
                        }
                    };
                }

                while tls_stream.session.is_handshaking() {
                    try_poll!(tls_stream.handshake(cx));
                }

                try_poll!(Pin::new(&mut tls_stream).poll_flush(cx));
                None
            };

            if let Some((err, need_flush)) = handshake_error {
                let (io, alert) = stream.into_io_tls();
                if alert.is_empty() && !need_flush {
                    return Poll::Ready(Err((err, io)));
                }
                *this = Self::SendAlert {
                    io,
                    alert,
                    error: err,
                };
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(stream))
    }
}
