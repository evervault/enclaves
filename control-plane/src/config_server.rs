use crate::clients::cert_provisioner::CertProvisionerClient;
use crate::error::Result;

use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use shared::server::config_server::requests::{ConfigServerPayload, GetCertTokenResponseDataPlane};
use shared::server::config_server::routes::ConfigServerPath;
use shared::server::Listener;
#[cfg(not(feature = "enclave"))]
use shared::server::TcpServer;
#[cfg(feature = "enclave")]
use shared::server::VsockServer;
#[cfg(not(feature = "enclave"))]
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

pub struct ConfigServer {
    cert_provisioner_client: CertProvisionerClient,
}

impl ConfigServer {
    pub fn new(cert_provisioner_client: CertProvisionerClient) -> Self {
        Self {
            cert_provisioner_client,
        }
    }

    pub async fn listen(&self) -> Result<()> {
        #[cfg(feature = "enclave")]
        let mut enclave_conn =
            VsockServer::bind(shared::PARENT_CID, shared::ENCLAVE_CONFIG_PORT.into()).await?;

        #[cfg(not(feature = "enclave"))]
        let mut enclave_conn = TcpServer::bind(std::net::SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            shared::ENCLAVE_CONFIG_PORT,
        ))
        .await?;

        let server = conn::Http::new();

        let cert_client = self.cert_provisioner_client.clone();

        println!("Running config server on {}", shared::ENCLAVE_CONFIG_PORT);
        loop {
            let cert_client = cert_client.clone();
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting config request from data plane — {:?}", e);
                    continue;
                }
            };

            let server = server.clone();

            tokio::spawn(async move {
                let cert_client = cert_client.clone();
                let sent_response = server
                    .serve_connection(
                        connection,
                        service_fn(|req: Request<Body>| {
                            let cert_client = cert_client.clone();
                            async move { handle_incoming_request(req, cert_client).await }
                        }),
                    )
                    .await;

                if let Err(processing_err) = sent_response {
                    eprintln!(
                        "An error occurred while processing the request — {}",
                        processing_err
                    );
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

async fn handle_incoming_request(
    req: Request<Body>,
    cert_provisioner_client: CertProvisionerClient,
) -> Result<Response<Body>> {
    let (req_info, _) = req.into_parts();

    match ConfigServerPath::from_str(req_info.uri.path()) {
        Ok(ConfigServerPath::GetCertToken) => {
            Ok(handle_cert_token_request(cert_provisioner_client).await)
        }
        _ => Ok(build_bad_request_response()),
    }
}

async fn handle_cert_token_request(
    cert_provisioner_client: CertProvisionerClient,
) -> Response<Body> {
    let token_response = match cert_provisioner_client.get_token().await {
        Ok(res) => res,
        Err(err) => {
            println!("Request to cert provisioner for token failed. Err: {}", err);
            return build_error_response(format!(
                "Request to cert provisioner for token failed. Err: {}",
                err
            ));
        }
    };

    let body = match GetCertTokenResponseDataPlane::new(token_response.token()).into_body() {
        Ok(body) => body,
        Err(err) => {
            return build_error_response(format!(
                "Failed to serialise client provisioner token response: {}",
                err
            ))
        }
    };

    let res = Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(body);

    println!("Token returned from cert provisioner, sending it back to the cage");

    res.unwrap_or_else(|err| {
        build_error_response(format!(
            "Couldn't build cert token response. Error: {}",
            err
        ))
    })
}

fn build_bad_request_response() -> Response<Body> {
    Response::builder()
        .status(404)
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .expect("Infallible")
}

fn build_error_response(body_msg: String) -> Response<Body> {
    println!("Request failed: {}", body_msg);
    Response::builder()
        .status(500)
        .header("Content-Type", "application/json")
        .body(Body::from(body_msg))
        .expect("Infallible")
}
