use crate::clients::cert_provisioner::{
    CertProvisionerClient, GetCertTokenResponseControlPlane, GetE3TokenResponseControlPlane,
};
use crate::clients::storage::StorageClientInterface;

use crate::configuration;
use crate::error::{Result as ServerResult, ServerError};

use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response};
use serde::de::DeserializeOwned;
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, DeleteObjectRequest, GetCertTokenResponseDataPlane,
    GetE3TokenResponseDataPlane, GetObjectRequest, GetObjectResponse, PostTrxLogsRequest,
    PutObjectRequest,
};
use shared::server::config_server::routes::ConfigServerPath;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::str::FromStr;

#[derive(Clone)]
pub struct ConfigServer<T: StorageClientInterface> {
    cert_provisioner_client: CertProvisionerClient,
    storage_client: T,
    cage_context: configuration::CageContext,
}

impl<T: StorageClientInterface + Clone + Send + Sync + 'static> ConfigServer<T> {
    pub fn new(cert_provisioner_client: CertProvisionerClient, storage_client: T) -> Self {
        Self {
            cert_provisioner_client,
            storage_client,
            cage_context: configuration::CageContext::from_env_vars(),
        }
    }

    pub async fn listen(&self) -> ServerResult<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CONFIG_PORT, Parent).await?;

        let server = conn::Http::new();

        let cert_client = self.cert_provisioner_client.clone();
        let storage_client = self.storage_client.clone();
        let cage_context = self.cage_context.clone();

        println!("Running config server on {}", shared::ENCLAVE_CONFIG_PORT);
        loop {
            let cert_client = cert_client.clone();
            let storage_client = storage_client.clone();
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
                let storage_client = storage_client.clone();
                let cage_context = cage_context.clone();
                let sent_response = server
                    .serve_connection(
                        connection,
                        service_fn(|req: Request<Body>| {
                            let cert_client = cert_client.clone();
                            let storage_client = storage_client.clone();
                            let cage_context = cage_context.clone();
                            async move {
                                handle_incoming_request(
                                    req,
                                    cert_client,
                                    storage_client,
                                    cage_context,
                                )
                                .await
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
async fn handle_incoming_request<T: StorageClientInterface>(
    req: Request<Body>,
    cert_provisioner_client: CertProvisionerClient,
    storage_client: T,
    cage_context: configuration::CageContext,
) -> ServerResult<Response<Body>> {
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
        Ok(ConfigServerPath::Storage) => match *req.method() {
            Method::GET => handle_acme_storage_get_request(req, storage_client, cage_context).await,
            Method::PUT => handle_acme_storage_put_request(req, storage_client, cage_context).await,
            Method::DELETE => {
                handle_acme_storage_delete_request(req, storage_client, cage_context).await
            }
            _ => Ok(build_bad_request_response()),
        },
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
) -> ServerResult<Response<Body>> {
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
    let parsed_result: ServerResult<PostTrxLogsRequest> = parse_request(req).await;
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

async fn handle_acme_storage_get_request<T: StorageClientInterface>(
    req: Request<Body>,
    storage_client: T,
    cage_context: configuration::CageContext,
) -> ServerResult<Response<Body>> {
    println!("Recieved get request in config server for acme storage");
    let parsed_result: ServerResult<GetObjectRequest> = parse_request(req).await;
    match parsed_result {
        Ok(request_body) => {
            let namespaced_key = namespace_key(request_body.key(), &cage_context);
            let object = match storage_client.get_object(namespaced_key).await {
                Ok(object) => object,
                Err(err) => {
                    println!("Failed to get object in storage client: {}", err);
                    return Ok(build_error_response(
                        "Failed to get object in storage client".to_string(),
                    ));
                }
            };
            let body = GetObjectResponse::new(object).into_body()?;

            Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(body)
                .map_err(ServerError::HyperHttp)
        }
        Err(_) => Ok(build_error_response(
            "Failed to parse get object request from data plane".to_string(),
        )),
    }
}

async fn handle_acme_storage_put_request<T: StorageClientInterface>(
    req: Request<Body>,
    storage_client: T,
    cage_context: configuration::CageContext,
) -> ServerResult<Response<Body>> {
    println!("Recieved post request in config server for acme storage");
    let parsed_result: ServerResult<PutObjectRequest> = parse_request(req).await;
    match parsed_result {
        Ok(request_body) => {
            let namespaced_key = namespace_key(request_body.key(), &cage_context);

            match storage_client
                .put_object(namespaced_key, request_body.object())
                .await
            {
                Ok(_) => Ok(build_success_response()),
                Err(err) => {
                    println!("Failed to put object in storage client: {}", err);
                    Ok(build_error_response(
                        "Failed to put object in storage client".to_string(),
                    ))
                }
            }
        }
        Err(_) => Ok(build_error_response(
            "Failed to parse put object request from data plane".to_string(),
        )),
    }
}

async fn handle_acme_storage_delete_request<T: StorageClientInterface>(
    req: Request<Body>,
    storage_client: T,
    cage_context: configuration::CageContext,
) -> ServerResult<Response<Body>> {
    let parsed_result: ServerResult<DeleteObjectRequest> = parse_request(req).await;
    match parsed_result {
        Ok(request_body) => {
            let namespaced_key = namespace_key(request_body.key(), &cage_context);

            match storage_client.delete_object(namespaced_key).await {
                Ok(_) => Ok(build_success_response()),
                Err(err) => {
                    println!("Failed to delete object in storage client: {}", err);
                    Ok(build_error_response(
                        "Failed to delete object in storage client".to_string(),
                    ))
                }
            }
        }
        Err(_) => Ok(build_error_response(
            "Failed to parse delete object request from data plane".to_string(),
        )),
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

fn namespace_key(key: String, cage_context: &configuration::CageContext) -> String {
    format!(
        "{}/{}/{}/{}",
        cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, key
    )
}

async fn parse_request<T: DeserializeOwned>(req: Request<Body>) -> ServerResult<T> {
    let req_body = hyper::body::to_bytes(req.into_body()).await?;
    serde_json::from_slice(&req_body).map_err(ServerError::JsonError)
}

#[cfg(test)]
mod tests {
    use crate::clients::storage::StorageClientError;

    use super::*;
    use async_trait::async_trait;
    use mockall::{mock, predicate::eq};

    mock! {
      #[derive(Debug)]
      pub StorageClientInterface {}
      #[async_trait]
      impl StorageClientInterface for StorageClientInterface {
          async fn get_object(&self, key: String) -> Result<String, StorageClientError>;
          async fn put_object(&self, key: String, body: String) -> Result<(), StorageClientError>;
          async fn delete_object(&self, key: String) -> Result<(), StorageClientError>;
      }
    }

    fn get_cage_context() -> configuration::CageContext {
        configuration::CageContext::new(
            "cage_123".to_string(),
            "v1".to_string(),
            "test-me".to_string(),
            "app_123".to_string(),
            "team_456".to_string(),
        )
    }

    #[tokio::test]
    async fn test_handle_acme_storage_get_request() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();

        let req_body = GetObjectRequest::new(key.clone()).into_body().unwrap();
        let req = hyper::Request::builder()
            .method(Method::GET)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid,
            cage_context.app_uuid,
            cage_context.cage_uuid,
            key.clone()
        );

        mock_storage_client
            .expect_get_object()
            .with(eq(expected_key))
            .returning(move |_| Ok("super_secret".to_string()));

        let result = handle_acme_storage_get_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_success());
    }

    #[tokio::test]
    async fn test_handle_acme_storage_get_request_error_is_response() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();

        let req_body = GetObjectRequest::new(key.clone()).into_body().unwrap();
        let req = hyper::Request::builder()
            .method(Method::GET)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid,
            cage_context.app_uuid,
            cage_context.cage_uuid,
            key.clone()
        );

        mock_storage_client
            .expect_get_object()
            .with(eq(expected_key))
            .returning(move |_| {
                Err(StorageClientError::General(
                    "some_get_object_error".to_string(),
                ))
            });

        let result = handle_acme_storage_get_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_server_error());
    }

    #[tokio::test]
    async fn test_handle_acme_storage_put_request() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();
        let object = "super_secret".to_string();

        let req_body = PutObjectRequest::new(key.clone(), object.clone())
            .into_body()
            .unwrap();
        let req = hyper::Request::builder()
            .method(Method::GET)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, key
        );

        mock_storage_client
            .expect_put_object()
            .with(eq(expected_key), eq(object))
            .returning(move |_, _| Ok(()));

        let result = handle_acme_storage_put_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_success());
    }

    #[tokio::test]
    async fn test_handle_acme_storage_put_request_error_is_response() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();
        let object = "super_secret".to_string();

        let req_body = PutObjectRequest::new(key.clone(), object.clone())
            .into_body()
            .unwrap();
        let req = hyper::Request::builder()
            .method(Method::GET)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, key
        );

        mock_storage_client
            .expect_put_object()
            .with(eq(expected_key), eq(object))
            .returning(move |_, _| {
                Err(StorageClientError::General(
                    "some_put_object_error".to_string(),
                ))
            });

        let result = handle_acme_storage_put_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_server_error());
    }

    #[tokio::test]
    async fn test_handle_acme_storage_delete_request() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();

        let req_body = DeleteObjectRequest::new(key.clone()).into_body().unwrap();
        let req = hyper::Request::builder()
            .method(Method::DELETE)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid,
            cage_context.app_uuid,
            cage_context.cage_uuid,
            key.clone()
        );

        mock_storage_client
            .expect_delete_object()
            .with(eq(expected_key))
            .returning(move |_| Ok(()));

        let result =
            handle_acme_storage_delete_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_success());
    }

    #[tokio::test]
    async fn test_handle_acme_storage_delete_error_is_response() {
        let mut mock_storage_client = MockStorageClientInterface::new();

        let key = "some_key".to_string();

        let req_body = GetObjectRequest::new(key.clone()).into_body().unwrap();
        let req = hyper::Request::builder()
            .method(Method::DELETE)
            .body(req_body)
            .unwrap();

        let cage_context = get_cage_context();

        let expected_key = format!(
            "{}/{}/{}/{}",
            cage_context.team_uuid,
            cage_context.app_uuid,
            cage_context.cage_uuid,
            key.clone()
        );

        mock_storage_client
            .expect_delete_object()
            .with(eq(expected_key))
            .returning(move |_| {
                Err(StorageClientError::General(
                    "some_delete_object_error".to_string(),
                ))
            });

        let result =
            handle_acme_storage_delete_request(req, mock_storage_client, cage_context).await;

        assert!(result.is_ok());
        assert!(result.unwrap().status().is_server_error());
    }
}
