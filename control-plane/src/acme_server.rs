//Simple server running on port 80 to server ACME challenges

use axum::extract::Path;
use axum::{http::StatusCode, response::Response, routing::get, Router};
use hyper::Body;

use crate::clients::storage::StorageClientInterface;
use crate::configuration;
use crate::error::Result;

const CHALLENGE_PATH: &str = "/www/.well-known/acme-challenge/:token";

pub struct AcmeServer {}

#[allow(unused)]
impl AcmeServer {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn run_server<T: StorageClientInterface + Send + Sync + Clone + 'static>(
        &self,
        storage_client: T,
    ) -> Result<()>{
        let cage_context = configuration::CageContext::from_env_vars();
        let app = Router::new().route(
            CHALLENGE_PATH,
            get(move |token| handle_get_challenge(token, cage_context, storage_client)),
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
    Path(token): Path<String>,
    cage_context: configuration::CageContext,
    storage_client: T,
) -> Response<Body> {
    println!("Received request for token: {}", token);
    let namespace = cage_context.get_namespace_string();
    let file_path = format!("{}/www/.well-known/acme-challenge/{}", namespace, token);
    get_challenge(file_path, storage_client).await
}

async fn get_challenge<T: StorageClientInterface>(
    file_path: String,
    storage_client: T,
) -> Response<Body> {
    match storage_client.get_object(file_path).await {
        Ok(Some(challenge)) => Response::builder()
            .status(StatusCode::OK)
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
    use crate::clients::storage::StorageClientError;
    use crate::mocks::storage_client_mock::MockStorageClientInterface;
    use mockall::predicate::eq;

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
    async fn test_get_challenge_success() {
        let mut mock = MockStorageClientInterface::new();
        let cage_context = get_cage_context();
        let challenge_key = "test-success";
        let expected_path = format!(
            "{}/{}/{}/www/.well-known/acme-challenge/{}",
            cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, challenge_key
        );

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
        let cage_context = get_cage_context();
        let challenge_key = "test-not-found";
        let expected_path = format!(
            "{}/{}/{}/www/.well-known/acme-challenge/{}",
            cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, challenge_key
        );

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
        let cage_context = get_cage_context();
        let challenge_key = "test-error";
        let expected_path = format!(
            "{}/{}/{}/www/.well-known/acme-challenge/{}",
            cage_context.team_uuid, cage_context.app_uuid, cage_context.cage_uuid, challenge_key
        );

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
