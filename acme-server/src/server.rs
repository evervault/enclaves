use crate::error::Result;
use axum::extract::{Host, Path};
use axum::{http::StatusCode, response::Response, routing::get, Router};
use hyper::Body;
use shared::storage::StorageClientInterface;

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/:token";

pub struct AcmeServer {}

impl Default for AcmeServer {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(unused)]
impl AcmeServer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run_server<T: StorageClientInterface + Send + Sync + Clone + 'static>(
        &self,
        storage_client: T,
    ) -> Result<()> {
        let app = Router::new().route(
            CHALLENGE_PATH,
            get(move |Host(host): Host, Path(token): Path<String>| {
                handle_get_challenge(host, token, storage_client)
            }),
        );

        axum::Server::bind(
            &"0.0.0.0:80"
                .parse()
                .expect("Infallible - hardcoded address"),
        )
        .serve(app.into_make_service())
        .await?;
        Ok(())
    }
}

async fn handle_get_challenge<T: StorageClientInterface>(
    host: String,
    token: String,
    storage_client: T,
) -> Response<Body> {
    let parts: Vec<&str> = host.split('.').collect();

    // cage-name.app-uuid.cages.evervault.com
    if parts.len() != 5 {
        eprintln!("Request was made to a hostname that does not look like a cage hostname");
        return build_infallible_response("Bad hostname", StatusCode::BAD_REQUEST);
    }

    let file_path = format!("{}/{}/acme-challenges/{}", parts[1], parts[0], token);
    get_challenge(file_path, storage_client).await
}

async fn get_challenge<T: StorageClientInterface>(
    file_path: String,
    storage_client: T,
) -> Response<Body> {
    println!("Received request for challenge: {}", file_path);
    match storage_client.get_object(file_path).await {
        Ok(Some(challenge)) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(challenge))
            .unwrap(),
        Ok(None) => build_infallible_response("Not Found", StatusCode::NOT_FOUND),
        Err(err) => {
            println!("Error Retrieving challenge: {}", err);
            build_infallible_response(
                "Error Retrieving challenge",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}

fn build_infallible_response(msg: &str, status_code: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status_code)
        .body(Body::from(msg.to_string()))
        .expect("Infallible - hardcoded response")
}

#[cfg(test)]
mod tests {

    use super::*;
    use mockall::predicate::eq;
    use shared::mocks::storage_client_mock::MockStorageClientInterface;
    use shared::storage::StorageClientError;

    fn get_expected_path(challenge_key: &str) -> String {
        format!(
            "{}/{}/acme-challenges/{}",
            "app-123", "test-cage", challenge_key
        )
    }

    #[tokio::test]
    async fn test_get_challenge_success() {
        let mut mock = MockStorageClientInterface::new();
        let expected_path = get_expected_path("test-success");

        mock.expect_get_object()
            .with(eq(expected_path.clone()))
            .times(1)
            .returning(|_| Ok(Some("Challenge-test".to_string())));

        let response = get_challenge(expected_path, mock).await;

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = hyper::body::to_bytes(response.into_body())
            .await
            .expect("Failed to convert body to bytes");

        let body_string = String::from_utf8_lossy(&body_bytes);
        assert_eq!(body_string, "Challenge-test");
    }

    #[tokio::test]
    async fn test_get_challenge_not_found() {
        let mut mock = MockStorageClientInterface::new();
        let expected_path = get_expected_path("test-not-found");

        mock.expect_get_object()
            .with(eq(expected_path.clone()))
            .times(1)
            .returning(|_| Ok(None));

        let response = get_challenge(expected_path, mock).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body_bytes = hyper::body::to_bytes(response.into_body())
            .await
            .expect("Failed to convert body to bytes");

        let body_string = String::from_utf8_lossy(&body_bytes);
        assert_eq!(body_string, "Not Found");
    }

    #[tokio::test]
    async fn test_get_challenge_error() {
        let mut mock = MockStorageClientInterface::new();
        let expected_path = get_expected_path("test-error");

        mock.expect_get_object()
            .with(eq(expected_path.clone()))
            .times(1)
            .returning(|_| Err(StorageClientError::General("ERROR TEST".to_string())));

        let response = get_challenge(expected_path, mock).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body_bytes = hyper::body::to_bytes(response.into_body())
            .await
            .expect("Failed to convert body to bytes");

        let body_string = String::from_utf8_lossy(&body_bytes);
        assert_eq!(body_string, "Error Retrieving challenge");
    }
}
