use crate::clients::cert_provisioner::{
    CertProvisionerClient, GetCertTokenResponseControlPlane, GetE3TokenResponseControlPlane,
};
use shared::storage::StorageClientInterface;

use crate::acme_account_details::AcmeAccountDetails;
use crate::configuration;
use crate::error::{Result as ServerResult, ServerError};

use hyper::server::conn;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response};
use serde::de::DeserializeOwned;

use shared::acme::jws::{jws, Jwk, NewOrderPayload};
use shared::logging::TrxContext;
use shared::server::config_server::requests::{
    ConfigServerPayload, DeleteObjectRequest, GetCertTokenResponseDataPlane,
    GetE3TokenResponseDataPlane, GetObjectRequest, GetObjectResponse, JwsRequest,
    PostTrxLogsRequest, PutObjectRequest,
};
use shared::server::config_server::requests::{JwkResponse, JwsResponse, SignatureType};
use shared::server::config_server::routes::ConfigServerPath;
use shared::server::CID::Parent;
use shared::server::{get_vsock_server, Listener};
use std::str::FromStr;

#[derive(Clone)]
pub struct ConfigServer<T: StorageClientInterface> {
    cert_provisioner_client: CertProvisionerClient,
    storage_client: T,
    cage_context: configuration::CageContext,
    acme_account_details: AcmeAccountDetails,
}

impl<T: StorageClientInterface + Clone + Send + Sync + 'static> ConfigServer<T> {
    pub fn new(cert_provisioner_client: CertProvisionerClient, storage_client: T) -> Self {
        let acme_account_details = AcmeAccountDetails::new_from_env()
            .expect("Failed to get acme account details from env");
        Self {
            cert_provisioner_client,
            storage_client,
            cage_context: configuration::CageContext::from_env_vars(),
            acme_account_details,
        }
    }

    pub async fn listen(&self) -> ServerResult<()> {
        let mut enclave_conn = get_vsock_server(shared::ENCLAVE_CONFIG_PORT, Parent).await?;

        let server = conn::Http::new();

        let cert_client = self.cert_provisioner_client.clone();
        let storage_client = self.storage_client.clone();
        let cage_context = self.cage_context.clone();
        let acme_account_details = self.acme_account_details.clone();
        println!("Running config server on {}", shared::ENCLAVE_CONFIG_PORT);
        loop {
            let cert_client = cert_client.clone();
            let storage_client = storage_client.clone();
            let cage_context = cage_context.clone();
            let acme_account_details = acme_account_details.clone();
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
                let acme_account_details = acme_account_details.clone();
                let sent_response = server
                    .serve_connection(
                        connection,
                        service_fn(|req: Request<Body>| {
                            let cert_client = cert_client.clone();
                            let storage_client = storage_client.clone();
                            let cage_context = cage_context.clone();
                            let acme_account_details = acme_account_details.clone();
                            async move {
                                handle_incoming_request(
                                    req,
                                    cert_client,
                                    storage_client,
                                    cage_context,
                                    acme_account_details,
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
    acme_account_details: AcmeAccountDetails,
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
        Ok(ConfigServerPath::AcmeSign) => {
            Ok(handle_acme_signing_request(req, acme_account_details, cage_context).await)
        }
        Ok(ConfigServerPath::AcmeJWK) => Ok(handle_acme_jwk_request(acme_account_details).await),
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
    let parsed_result: ServerResult<GetObjectRequest> = parse_request(req).await;
    match parsed_result {
        Ok(request_body) => {
            let namespaced_key = namespace_key(request_body.key(), &cage_context);
            println!(
                "Received get request in config server for {}",
                namespaced_key
            );
            let object = match storage_client.get_object(namespaced_key).await {
                Ok(object) => match object {
                    Some(object) => object,
                    None => {
                        println!("Object not found in storage client");
                        return Ok(build_bad_request_response());
                    }
                },
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
    let parsed_result: ServerResult<PutObjectRequest> = parse_request(req).await;
    match parsed_result {
        Ok(request_body) => {
            let namespaced_key = namespace_key(request_body.key(), &cage_context);
            println!(
                "Received post request in config server for {}",
                namespaced_key
            );
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
            println!(
                "Received delete request in config server for {}",
                namespaced_key
            );
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

async fn handle_acme_signing_request(
    req: Request<Body>,
    acme_account_details: AcmeAccountDetails,
    cage_context: configuration::CageContext,
) -> Response<Body> {
    println!("Received ACME signing request in config server");
    match sign_acme_payload(req, acme_account_details, cage_context).await {
        Ok(response) => response,
        Err(err) => {
            println!("Failed to sign request: {}", err);
            build_error_response("Failed to sign JWS request".to_string())
        }
    }
}

async fn sign_acme_payload(
    req: Request<Body>,
    acme_account_details: AcmeAccountDetails,
    cage_context: configuration::CageContext,
) -> ServerResult<Response<Body>> {
    let parsed_result: ServerResult<JwsRequest> = parse_request(req).await;

    match parsed_result {
        Ok(jws_request) => {
            let (key, key_id) = match jws_request.signature_type {
                SignatureType::HMAC => (
                    acme_account_details
                        .eab_config
                        .clone()
                        .map(|x| x.private_key()),
                    acme_account_details.eab_config.map(|x| x.key_id()),
                ),
                SignatureType::ECDSA => (
                    Some(acme_account_details.account_ec_key),
                    jws_request.account_id,
                ),
            };

            if jws_request.url.contains("/newOrder") {
                let order_payload: NewOrderPayload = serde_json::from_str(&jws_request.payload)?;

                if !valid_order_identifiers(order_payload, cage_context) {
                    return Ok(build_bad_request_response());
                }
            };

            let jws = jws(
                &jws_request.url,
                jws_request.nonce,
                &jws_request.payload,
                &key.unwrap(),
                key_id,
            );

            match jws {
                Ok(jws) => {
                    let jws_response: JwsResponse = JwsResponse::from(&jws);
                    let body = jws_response.into_body()?;

                    Response::builder()
                        .status(200)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .map_err(ServerError::HyperHttp)
                }
                Err(err) => {
                    println!("Failed to sign request: {}", err);
                    Ok(build_error_response(
                        "Failed to sign JWS request".to_string(),
                    ))
                }
            }
        }
        Err(err) => {
            println!("Failed to parse signing request from data plane: {}", err);
            Ok(build_error_response(
                "Failed to parse signing request from data plane".to_string(),
            ))
        }
    }
}

async fn handle_acme_jwk_request(acme_account_details: AcmeAccountDetails) -> Response<Body> {
    println!("Recieved ACME JWK request in config server");
    match get_acme_jwk(acme_account_details).await {
        Ok(response) => response,
        Err(err) => {
            println!("Failed to get jwk: {}", err);
            build_error_response("Failed to get JWK".to_string())
        }
    }
}

async fn get_acme_jwk(acme_account_details: AcmeAccountDetails) -> ServerResult<Response<Body>> {
    let jwk = Jwk::new(&acme_account_details.account_ec_key)?;
    let jwk_response: JwkResponse = jwk.to_response();
    let body = jwk_response.into_body()?;

    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(ServerError::HyperHttp)
}

fn valid_order_identifiers(
    payload: NewOrderPayload,
    cage_context: configuration::CageContext,
) -> bool {
    let cage_base_domain = configuration::get_trusted_cert_base_domain();

    let cage_domain = format!(
        "{}.{}.{}",
        &cage_context.cage_name,
        &cage_context.hyphenated_app_uuid(),
        cage_base_domain
    );

    payload
        .identifiers
        .into_iter()
        .all(|identifier| identifier.value == cage_domain)
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
    format!("{}/{}", cage_context.clone().get_namespace_string(), key)
}

async fn parse_request<T: DeserializeOwned>(req: Request<Body>) -> ServerResult<T> {
    let req_body = hyper::body::to_bytes(req.into_body()).await?;
    serde_json::from_slice(&req_body).map_err(ServerError::JsonError)
}

#[cfg(test)]
mod tests {

    use shared::acme::helpers;
    use shared::acme::jws::Identifier;

    use super::*;
    use mockall::predicate::eq;
    use shared::mocks::storage_client_mock::MockStorageClientInterface;
    use shared::storage::StorageClientError;

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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
        );

        mock_storage_client
            .expect_get_object()
            .with(eq(expected_key))
            .returning(move |_| Ok(Some("super_secret".to_string())));

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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
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
            "{}/{}/{}",
            cage_context.hyphenated_app_uuid(),
            cage_context.cage_name,
            key
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

    #[tokio::test]
    async fn test_handle_acme_signing_request_success() {
        let cage_context = get_cage_context();
        let acme_account_details = AcmeAccountDetails {
            account_ec_key: helpers::gen_ec_private_key().unwrap(),
            eab_config: None,
        };

        let req_body = JwsRequest::new(
            SignatureType::ECDSA,
            "https://acme-staging-v02.api.letsencrypt.org/acme/newAccount".to_string(),
            Some("some_nonce".to_string()),
            "some_payload".to_string(),
            None,
        )
        .into_body()
        .unwrap();

        let result = handle_acme_signing_request(
            hyper::Request::builder()
                .method(Method::POST)
                .body(req_body)
                .unwrap(),
            acme_account_details,
            cage_context,
        )
        .await;

        assert!(result.status().is_success());
    }

    #[tokio::test]
    async fn test_handle_acme_signing_request_bad_request_new_order() {
        let cage_context = get_cage_context();
        let acme_account_details = AcmeAccountDetails {
            account_ec_key: helpers::gen_ec_private_key().unwrap(),
            eab_config: None,
        };

        let new_order_payload = NewOrderPayload {
            identifiers: vec![Identifier {
                r#type: "dns".to_string(),
                value: "some_other_domain.com".to_string(),
            }],
        };

        let new_order_payload_string = serde_json::to_string(&new_order_payload).unwrap();

        let req_body = JwsRequest::new(
            SignatureType::ECDSA,
            "https://acme-staging-v02.api.letsencrypt.org/acme/newOrder".to_string(),
            Some("some_nonce".to_string()),
            new_order_payload_string,
            None,
        )
        .into_body()
        .unwrap();

        let result = handle_acme_signing_request(
            hyper::Request::builder()
                .method(Method::POST)
                .body(req_body)
                .unwrap(),
            acme_account_details,
            cage_context,
        )
        .await;

        assert!(result.status().is_client_error());
    }

    #[test]
    fn test_validate_new_order_valid() {
        let cage_context = get_cage_context();
        let payload = NewOrderPayload {
            identifiers: vec![Identifier {
                r#type: "dns".to_string(),
                value: format!(
                    "{}.{}.cage.evervault.com",
                    cage_context.cage_name,
                    cage_context.app_uuid.replace('_', "-")
                ),
            }],
        };

        assert!(valid_order_identifiers(payload, cage_context));
    }

    #[test]
    fn test_validate_new_order_invalid() {
        let cage_context = get_cage_context();
        let payload = NewOrderPayload {
            identifiers: vec![Identifier {
                r#type: "dns".to_string(),
                value: "some_other_domain.com".to_string(),
            }],
        };

        assert!(!valid_order_identifiers(payload, cage_context));
    }

    #[test]
    fn test_validate_new_order_multiple_domains_invalid() {
        let cage_context = get_cage_context();
        let payload = NewOrderPayload {
            identifiers: vec![
                Identifier {
                    r#type: "dns".to_string(),
                    value: "some_other_domain.com".to_string(),
                },
                Identifier {
                    r#type: "dns".to_string(),
                    value: format!(
                        "{}.{}.cage.evervault.com",
                        cage_context.cage_name,
                        cage_context.app_uuid.replace('_', "-")
                    ),
                },
            ],
        };

        assert!(!valid_order_identifiers(payload, cage_context));
    }
}
