# Description

An async tls stream library based on [rustls](https://crates.io/crates/rustls) and [futures-io](https://crates.io/crates/futures-io). Both for server/client.

## Server

```rust
let listener = async_net::TcpListener::bind((Ipv4Addr::LOCALHOST, 4443)).await.unwrap();
let (stream, remote_addr) = listener.accept().await.unwrap();
// Recv Client Hello
let accept = TlsAccepted::accept(stream).await.unwrap();
let server_config = Arc::new(server_config);
let mut stream = accept.into_stream(server_config.clone()).unwrap();
// handshake completed
stream.flush().await.unwrap();
```

## Client

```rust
let server_name = "test.com".try_into().unwrap();
let client_config = Arc::new(client_config);
let connector = TlsConnector::new(client_config.clone(), server_name).unwrap();
let stream = async_net::TcpStream::connect((Ipv4Addr::LOCALHOST, 4443)).await.unwrap();
let mut stream = connector.connect(stream);
// handshake completed
stream.flush().await.unwrap();
```

or [examples](https://github.com/hs-CN/async-rustls-stream/blob/master/examples).
