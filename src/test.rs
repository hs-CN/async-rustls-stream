use crate::{TlsAccepted, TlsConnector};
use async_executor::Executor;
use futures_lite::prelude::*;
use rustls::ServerConfig;
use std::{io::Cursor, net::Ipv4Addr, sync::Arc, time::Duration};

static EX: Executor = Executor::new();

#[test]
fn server_client_test() {
    let ca_cert: Vec<_> = rustls_pemfile::certs(&mut Cursor::new(include_bytes!("../cert/ca.crt")))
        .unwrap()
        .into_iter()
        .map(|x| rustls::Certificate(x))
        .collect();
    let ca_key: Vec<_> =
        rustls_pemfile::rsa_private_keys(&mut Cursor::new(include_bytes!("../cert/ca.key")))
            .unwrap()
            .into_iter()
            .map(|x| rustls::PrivateKey(x))
            .collect();

    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(ca_cert.clone(), ca_key[0].clone())
        .unwrap();
    let server_config = Arc::new(server_config);
    EX.spawn(async move {
        let listener = async_net::TcpListener::bind((Ipv4Addr::LOCALHOST, 4443))
            .await
            .unwrap();
        loop {
            let (stream, _remote_addr) = listener.accept().await.unwrap();
            let server_config = server_config.clone();
            EX.spawn(async move {
                let accept = TlsAccepted::accept(stream).await.unwrap();
                let mut stream = accept.into_stream(server_config.clone()).unwrap();
                stream.flush().await.unwrap();

                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                let str = String::from_utf8_lossy(&buf[..n]);
                assert_eq!(str, "server and client test");

                stream.write_all(&buf[..n]).await.unwrap();
                stream.flush().await.unwrap();
            })
            .detach();
        }
    })
    .detach();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(&ca_cert[0]).unwrap();
    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let server_name = "test.com".try_into().unwrap();
    let client_task = EX.spawn(async move {
        let connector = TlsConnector::new(config.clone(), server_name).unwrap();
        let stream = async_net::TcpStream::connect((Ipv4Addr::LOCALHOST, 4443))
            .await
            .unwrap();
        let mut stream = connector.connect(stream);
        stream.flush().await.unwrap();
        async_io::Timer::after(Duration::from_millis(1)).await;

        let line = "server and client test";
        stream.write_all(line.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let back = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(line, back);
    });

    async_io::block_on(EX.run(client_task));
}
