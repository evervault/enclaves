use acme_server::{configuration, error::Result, server::AcmeServer};
use shared::storage::s3;

#[tokio::main]
async fn main() -> Result<()> {
    let acme_s3_client = s3::S3Client::new(configuration::get_acme_s3_bucket()).await;
    println!("Starting acme server");
    AcmeServer::new().run_server(acme_s3_client).await?;
    Ok(())
}
