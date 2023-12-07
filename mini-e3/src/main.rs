use shared::server::{get_vsock_server, Listener};

fn main() {
    println!("Hello, world!");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(start_server());
}

async fn start_server() {
    let mut server = get_vsock_server(8001, shared::server::CID::Enclave)
        .await
        .unwrap();
    loop {
        let stream = match server.accept().await {
            Ok(stream) => {

            },
            Err(e) => {
                println!("failed to accept client; error = {:?}", e);
                continue;
            }
        };
    }
}
