use shared::server::{get_vsock_server, Listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn main() {
    println!("Hello, world!");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(start_server());
}

async fn start_server() {
    let mut server = get_vsock_server(8001, shared::server::CID::Local)
        .await
        .unwrap();
    loop {
        let mut buffer = [0;1024];
        match server.accept().await {
            Ok(mut stream) => {
                match stream.read(&mut buffer).await {
                    Ok(size) => {
                        let incoming_data = String::from_utf8_lossy(&buffer[..size]);
                        println!("recived data {:?}", incoming_data);
                    },
                    Err(e) => {
                        println!("failed to read from socket; err = {:?}", e);
                    }
                }

                match stream.write(&buffer).await {
                    Ok(size) => {
                        println!("send data {:?}", size);
                    },
                    Err(e) => {
                        println!("failed to write to socket; err = {:?}", e);
                    }
                }
            },
            Err(e) => {
                println!("failed to accept client; error = {:?}", e);
                continue;
            }
        };
    }
}
