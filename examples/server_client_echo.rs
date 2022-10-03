use async_executor::Executor;
use async_io::{Async, Timer};
use async_tls::{TlsAccepted, TlsConnector};
use blocking::Unblock;
use futures_lite::{io::BufReader, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use rustls::ServerConfig;
use std::{
    io::{Cursor, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

static EX: Executor = Executor::new();

fn main() {
    let mut tasks = Vec::new();

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
    let _server_task = EX.spawn(async move {
        let listener = Async::<TcpListener>::bind((Ipv4Addr::LOCALHOST, 4443)).unwrap();
        loop {
            let (stream, remote_addr) = listener.accept().await.unwrap();
            let server_config = server_config.clone();
            let _handle_task = EX.spawn(async move {
                println!("[Server] accept {}", remote_addr);
                let accept = TlsAccepted::accept(stream).await.unwrap();
                let mut stream = accept.into_stream(server_config).unwrap();
                stream.flush().await.unwrap();
                println!("[Server] Hello");

                let mut buf = [0; 1024];
                loop {
                    buf.fill(0);
                    let n = stream.read(&mut buf).await.unwrap();
                    let str = String::from_utf8_lossy(&buf[..n]);

                    if str == "q" {
                        println!("[Server] Exit");
                        break;
                    }
                    println!("[Server] {}", str);
                    stream.write_all(&buf[..n]).await.unwrap();
                    stream.flush().await.unwrap();
                }
            });
            tasks.push(_handle_task);
        }
    });

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
        let stream = Async::<TcpStream>::connect((Ipv4Addr::LOCALHOST, 4443))
            .await
            .unwrap();
        let mut stream = connector.connect(stream);
        stream.flush().await.unwrap();
        println!("[Client] Hello");
        Timer::after(Duration::from_millis(1)).await;

        let stdin = Unblock::new(std::io::stdin());
        let mut stdin = BufReader::new(stdin);

        let mut buf = [0; 1024];
        let mut line = String::new();
        loop {
            line.clear();
            print!("you say (q to exit):");
            std::io::stdout().flush().unwrap();
            stdin.read_line(&mut line).await.unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }
            stream.write_all(line.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();

            if line == "q" {
                println!("[Client] Exit");
                break;
            }

            let n = stream.read(&mut buf).await.unwrap();
            let back = String::from_utf8_lossy(&buf[..n]);
            println!("[Client] {}", back);
        }
    });

    async_io::block_on(EX.run(client_task));
}
