use std::{
    future::Future,
    io,
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

use pin_project_lite::pin_project;
use rustls::{ConnectionCommon, SideData};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::IoSession;

use super::{Stream, TlsState};

/// Full result of sync closure
type SessionResult<S> = Result<S, (Option<S>, io::Error)>;
/// Executor result wrapping sync closure result
type ExecutorResult<S> = Result<SessionResult<S>, vacation::Error>;
/// Future wrapping waiting on executor
type SessionFuture<S> = Box<dyn Future<Output = ExecutorResult<S>> + Unpin + Send>;

pin_project! {
/// Session is off doing compute-heavy sync work, such as initializing the session or processing handshake packets.
/// Might be on another thread / external threadpool.
///
/// This future sleeps on it in current worker thread until it completes.
pub(crate) struct AsyncSession<IS: IoSession> {
    #[pin]
    future: SessionFuture<IS::Session>,
    io: IS::Io,
    state: TlsState,
    extras: IS::Extras,
}
}

impl<IS, SD> AsyncSession<IS>
where
    IS: IoSession + Unpin,
    IS::Io: AsyncRead + AsyncWrite + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin + Send + 'static,
    SD: SideData,
{
    pub(crate) fn process_packets(stream: IS) -> Self {
        let (state, io, mut session, extras) = stream.into_inner();

        let closure = move || match session.process_new_packets() {
            Ok(_) => Ok(session),
            Err(err) => Err((
                Some(session),
                io::Error::new(io::ErrorKind::InvalidData, err),
            )),
        };

        // TODO: if we ever start also delegating non-handshake byte processing, make this chance of blocking
        // variable and set by caller
        let future = vacation::execute(closure, vacation::ChanceOfBlocking::High);

        Self {
            future: Box::new(Box::pin(future)),
            io,
            state,
            extras,
        }
    }

    pub(crate) fn into_stream(
        mut self,
        session_result: Result<IS::Session, (Option<IS::Session>, io::Error)>,
        cx: &mut Context<'_>,
    ) -> Result<IS, (io::Error, IS::Io)> {
        match session_result {
            Ok(session) => Ok(IS::from_inner(self.state, self.io, session, self.extras)),
            Err((Some(mut session), err)) => {
                // In case we have an alert to send describing this error,
                // try a last-gasp write -- but don't predate the primary
                // error.
                let mut tls_stream: Stream<'_, <IS as IoSession>::Io, <IS as IoSession>::Session> =
                    Stream::new(&mut self.io, &mut session).set_eof(!self.state.readable());
                let _ = tls_stream.write_io(cx);

                // still drop the tls session and return the io error only
                Err((err, self.io))
            }
            Err((None, err)) => Err((err, self.io)),
        }
    }

    #[inline]
    pub fn get_ref(&self) -> &IS::Io {
        &self.io
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut IS::Io {
        &mut self.io
    }
}

impl<IS, SD> Future for AsyncSession<IS>
where
    IS: IoSession + Unpin,
    IS::Session: DerefMut + Deref<Target = ConnectionCommon<SD>> + Unpin + Send + 'static,
    SD: SideData,
{
    type Output = Result<IS::Session, (Option<IS::Session>, io::Error)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        match ready!(this.future.as_mut().poll(cx)) {
            Ok(session_res) => match session_res {
                Ok(res) => Poll::Ready(Ok(res)),
                // return any session along with the error,
                // so the caller can flush any remaining alerts in buffer to i/o
                Err((session, err)) => Poll::Ready(Err((
                    session,
                    io::Error::new(io::ErrorKind::InvalidData, err),
                ))),
            },
            // We don't have a session to flush here because the executor ate it
            // TODO: not all errors should be modeled as io
            Err(executor_error) => Poll::Ready(Err((
                None,
                io::Error::new(io::ErrorKind::Other, executor_error),
            ))),
        }
    }
}
