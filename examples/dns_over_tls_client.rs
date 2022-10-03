use async_io::Async;
use async_tls::TlsConnector;
use dns_types::{DnsClass, DnsType, Request, Response};
use futures_lite::{AsyncReadExt, AsyncWriteExt};
use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
};

fn main() {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);
    let connector = TlsConnector::new(config.clone(), "dot.pub".try_into().unwrap()).unwrap();
    let addr = ToSocketAddrs::to_socket_addrs("dot.pub:853")
        .unwrap()
        .next()
        .unwrap();

    async_io::block_on(async {
        let stream = Async::<TcpStream>::connect(addr).await.unwrap();
        let mut stream = connector.connect(stream);
        stream.flush().await.unwrap();
        let request = Request::new("github.com", DnsType::A, DnsClass::Internet);
        let buf = request.as_bytes();
        let len_bytes = (buf.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0; 2];
        stream.read_exact(&mut buf).await.unwrap();
        let len = u16::from_be_bytes(buf) as usize;

        let mut buf = vec![0; len];
        stream.read_exact(&mut buf).await.unwrap();

        stream.close().await.unwrap();
        let response = Response::from_bytes_unchecked(&buf);
        println!("{:?}", response.ip_with_ttl())
    });
}
