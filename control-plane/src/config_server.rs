use crate::clients::cert_provisioner::{
    CertProvisionerClient, GetCertTokenResponseControlPlane, GetE3TokenResponseControlPlane,
};
use crate::configuration;
use crate::error::{Result, ServerError};

use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use serde::de::DeserializeOwned;
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, GetCertTokenResponseDataPlane, GetE3TokenResponseDataPlane,
    PostTrxLogsRequest,
};
use shared::server::config_server::routes::ConfigServerPath;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::str::FromStr;

#[derive(Clone)]
pub struct ConfigServer {
    cert_provisioner_client: CertProvisionerClient,
    cage_context: configuration::CageContext,
}

impl ConfigServer {
    pub fn new(cert_provisioner_client: CertProvisionerClient) -> Self {
        Self {
            cert_provisioner_client,
            cage_context: configuration::CageContext::from_env_vars(),
        }
    }

    pub async fn listen(&self) -> Result<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CONFIG_PORT, Parent).await?;

        let server = conn::Http::new();

        let cert_client = self.cert_provisioner_client.clone();
        let cage_context = self.cage_context.clone();

        println!("Running config server on {}", shared::ENCLAVE_CONFIG_PORT);
        loop {
            let cert_client = cert_client.clone();
            let cage_context = cage_context.clone();
            let connection = match enclave_conn.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    eprintln!("Error accepting config request from data plane — {e:?}");
                    continue;
                }
            };

            let server = server.clone();

            tokio::spawn(async move {
                let cert_client = cert_client.clone();
                let cage_context = cage_context.clone();
                let sent_response =
                    server
                        .serve_connection(
                            connection,
                            service_fn(|req: Request<Body>| {
                                let cert_client = cert_client.clone();
                                let cage_context = cage_context.clone();
                                async move {
                                    handle_incoming_request(req, cert_client, cage_context).await
                                }
                            }),
                        )
                        .await;

                if let Err(processing_err) = sent_response {
                    eprintln!("An error occurred while processing the request — {processing_err}");
                }
            });
        }

        #[allow(unreachable_code)]
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum TokenType {
    Cert(ConfigServerPath),
    E3(ConfigServerPath),
}
async fn handle_incoming_request(
    req: Request<Body>,
    cert_provisioner_client: CertProvisionerClient,
    cage_context: configuration::CageContext,
) -> Result<Response<Body>> {
    match ConfigServerPath::from_str(req.uri().path()) {
        Ok(ConfigServerPath::GetCertToken) => Ok(handle_token_request(
            cert_provisioner_client,
            TokenType::Cert(ConfigServerPath::GetCertToken),
        )
        .await),
        Ok(ConfigServerPath::GetE3Token) => Ok(handle_token_request(
            cert_provisioner_client,
            TokenType::E3(ConfigServerPath::GetE3Token),
        )
        .await),
        Ok(ConfigServerPath::PostTrxLogs) => {
            Ok(handle_post_trx_logs_request(req, cage_context).await)
        }
        _ => Ok(build_bad_request_response()),
    }
}

async fn handle_token_request(
    cert_provisioner_client: CertProvisionerClient,
    token_type: TokenType,
) -> Response<Body> {
    match get_token(cert_provisioner_client, token_type.clone()).await {
        Ok(res) => res,
        Err(e) => build_error_response(format!(
            "Failed to get token for token {token_type:?} err: {e}"
        )),
    }
}

async fn get_token(
    cert_provisioner_client: CertProvisionerClient,
    token_type: TokenType,
) -> Result<Response<Body>> {
    let body = match token_type {
        TokenType::Cert(path) => {
            let token_response = cert_provisioner_client
                .get_token::<GetCertTokenResponseControlPlane>(path.clone())
                .await?;
            GetCertTokenResponseDataPlane::new(token_response.token()).into_body()?
        }
        TokenType::E3(path) => {
            let token_response = cert_provisioner_client
                .get_token::<GetE3TokenResponseControlPlane>(path.clone())
                .await?;
            GetE3TokenResponseDataPlane::new(token_response.token(), token_response.token_id())
                .into_body()?
        }
    };

    let res = Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(body)?;

    println!("Token returned from cert provisioner, sending it back to the cage");

    Ok(res)
}

fn validate_trx_log(trx_log: &TrxContext, cage_context: &configuration::CageContext) -> bool {
    trx_log.cage_uuid == cage_context.cage_uuid
        && trx_log.cage_name == cage_context.cage_name
        && trx_log.team_uuid == cage_context.team_uuid
        && trx_log.app_uuid == cage_context.app_uuid
}

async fn handle_post_trx_logs_request(
    req: Request<Body>,
    cage_context: configuration::CageContext,
) -> Response<Body> {
    println!("Recieved request in config server to log transactions");
    let parsed_result: Result<PostTrxLogsRequest> = parse_request(req).await;
    match parsed_result {
        Ok(log_body) => {
            log_body.trx_logs().into_iter().for_each(|trx| {
                if validate_trx_log(&trx, &cage_context) {
                    trx.record_trx();
                }
            });
            build_success_response()
        }
        Err(_) => build_error_response("Failed to parse log body from data plane".to_string()),
    }
}

fn build_success_response() -> Response<Body> {
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .expect("Infallible")
}

fn build_bad_request_response() -> Response<Body> {
    Response::builder()
        .status(404)
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .expect("Infallible")
}

fn build_error_response(body_msg: String) -> Response<Body> {
    println!("Request failed: {body_msg}");
    Response::builder()
        .status(500)
        .header("Content-Type", "application/json")
        .body(Body::from(body_msg))
        .expect("Infallible")
}

async fn parse_request<T: DeserializeOwned>(req: Request<Body>) -> Result<T> {
    let req_body = hyper::body::to_bytes(req.into_body()).await?;
    serde_json::from_slice(&req_body).map_err(ServerError::JsonError)
}
