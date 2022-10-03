//! An async tls stream library based on rustls and futures-io. Both for server/client.
//!
//! # Examples
//!
//! **Server**
//! ```no_run
//! let listener = async_net::TcpListener::bind((Ipv4Addr::LOCALHOST, 4443)).await.unwrap();
//! let (stream, remote_addr) = listener.accept().await.unwrap();
//!
//! // Recv Client Hello
//! let accept = TlsAccepted::accept(stream).await.unwrap();
//!
//! let server_config = Arc::new(server_config);
//! let mut stream = accept.into_stream(server_config.clone()).unwrap();
//! // handshake completed
//! stream.flush().await.unwrap();
//! ```
//!
//! **Client**
//!
//! ```no_run
//! let server_name = "test.com".try_into().unwrap();
//! let client_config = Arc::new(client_config);
//! let connector = TlsConnector::new(client_config.clone(), server_name).unwrap();
//!
//! let stream = async_net::TcpStream::connect((Ipv4Addr::LOCALHOST, 4443)).await.unwrap();
//!
//! let mut stream = connector.connect(stream);
//! // handshake completed
//! stream.flush().await.unwrap();
//! ```
//! or [examples](https://github.com/hs-CN/async-rustls-stream/blob/master/examples).

use futures_io::{AsyncRead, AsyncWrite};
use rustls::{
    server::{Accepted, Acceptor, ClientHello},
    ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection, ServerName,
    SideData, Stream,
};
use std::{
    future::Future,
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

struct InnerStream<'a, 'b, T> {
    cx: &'a mut Context<'b>,
    stream: &'a mut T,
}

impl<'a, 'b, T: AsyncRead + Unpin> Read for InnerStream<'a, 'b, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match Pin::new(&mut self.stream).poll_read(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        match Pin::new(&mut self.stream).poll_read_vectored(self.cx, bufs) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<'a, 'b, T: AsyncWrite + Unpin> Write for InnerStream<'a, 'b, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.stream).poll_write(self.cx, buf) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut self.stream).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.stream).poll_flush(self.cx) {
            Poll::Ready(res) => res,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

/// Tls Stream Implement [`AsyncRead`] and [`AsyncWrite`]
pub struct TlsStream<C, T> {
    connection: C,
    stream: T,
}

impl<C, T> TlsStream<C, T> {
    pub fn get_ref(&self) -> (&C, &T) {
        (&self.connection, &self.stream)
    }

    pub fn get_mut(&mut self) -> (&mut C, &mut T) {
        (&mut self.connection, &mut self.stream)
    }
}

impl<C, T, S> AsyncRead for TlsStream<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>> + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    S: SideData,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let (connection, stream) = (*self).get_mut();
        let mut stream = Stream {
            conn: connection,
            sock: &mut InnerStream { cx, stream },
        };
        match stream.read(buf) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

    fn poll_read_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let (connection, stream) = (*self).get_mut();
        let mut stream = Stream {
            conn: connection,
            sock: &mut InnerStream { cx, stream },
        };
        match stream.read_vectored(bufs) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }
}

impl<C, T, S> AsyncWrite for TlsStream<C, T>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>> + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    S: SideData,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let (connection, stream) = (*self).get_mut();
        let mut stream = Stream {
            conn: connection,
            sock: &mut InnerStream { cx, stream },
        };
        match stream.write(buf) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let (connection, stream) = (*self).get_mut();
        let mut stream = Stream {
            conn: connection,
            sock: &mut InnerStream { cx, stream },
        };
        match stream.write_vectored(bufs) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let (connection, stream) = (*self).get_mut();
        let mut stream = Stream {
            conn: connection,
            sock: &mut InnerStream { cx, stream },
        };
        match stream.flush() {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            res => Poll::Ready(res),
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

/// Tls Client Connector.
///
/// Use [`TlsConnector::connect()`] to get [`TlsStream`] for client.
///
/// Then use [`TlsStream`]::flush() to finish the handshake.
pub struct TlsConnector(ClientConnection);

impl TlsConnector {
    pub fn new(config: Arc<ClientConfig>, server_name: ServerName) -> Result<Self, rustls::Error> {
        let connection = ClientConnection::new(config, server_name)?;
        Ok(Self(connection))
    }

    /// The `stream` generally should implement [`AsyncRead`] and [`AsyncWrite`].
    pub fn connect<T>(self, stream: T) -> TlsStream<ClientConnection, T> {
        TlsStream {
            connection: self.0,
            stream,
        }
    }
}

/// Tls Server Accept the `Client Hello` and finish the handshake.
///
/// Use [`TlsAccepted::accept()`] to receive the `Client Hello`.
///
/// Then use [`TlsAccepted::into_stream()`] to get [`TlsStream`].
///
/// Then use [`TlsStream`]::flush() to finish the handshake.
pub struct TlsAccepted<T> {
    accepted: Accepted,
    stream: T,
}

impl<T> TlsAccepted<T> {
    /// Get the [`ClientHello`] received form client.
    pub fn client_hello(&self) -> ClientHello {
        self.accepted.client_hello()
    }

    /// Convert Into [`TlsStream`] with [`ServerConfig`].
    pub fn into_stream(
        self,
        config: Arc<ServerConfig>,
    ) -> Result<TlsStream<ServerConnection, T>, rustls::Error> {
        let connection = self.accepted.into_connection(config)?;
        Ok(TlsStream {
            connection,
            stream: self.stream,
        })
    }
}

impl<T> TlsAccepted<T>
where
    T: AsyncRead + Unpin,
{
    /// Receive `Client Hello`. The `stream` generally should implement [`AsyncRead`] and [`AsyncWrite`].
    pub async fn accept(mut stream: T) -> io::Result<TlsAccepted<T>> {
        let accepted = AcceptFuture {
            acceptor: Acceptor::new().unwrap(),
            stream: &mut stream,
        }
        .await?;
        Ok(TlsAccepted { accepted, stream })
    }
}

struct AcceptFuture<'a, T> {
    acceptor: Acceptor,
    stream: &'a mut T,
}

impl<'a, T> AcceptFuture<'a, T> {
    fn get_mut(&mut self) -> (&mut Acceptor, &mut T) {
        (&mut self.acceptor, self.stream)
    }
}

impl<'a, T: AsyncRead + Unpin> Future for AcceptFuture<'a, T> {
    type Output = io::Result<Accepted>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (acceptor, stream) = (*self).get_mut();
        match acceptor.read_tls(&mut InnerStream { cx, stream }) {
            Ok(_) => match self.acceptor.accept() {
                Ok(None) => Poll::Pending,
                Ok(Some(accepted)) => Poll::Ready(Ok(accepted)),
                Err(err) => Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, err))),
            },
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

#[cfg(test)]
mod test;
