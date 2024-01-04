use crate::{
    configuration,
    error::{Result, ServerError},
};
use hyper::{
    client::conn::{Connection, SendRequest},
    Body, Response,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shared::server::config_server::routes::ConfigServerPath;
use shared::{CLIENT_MAJOR_VERSION, CLIENT_VERSION};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{Certificate, PrivateKey, RootCertStore, ServerName},
};

const CERT_PROVISIONER_MTLS_PORT: i32 = 3443;

async fn get_socket() -> Result<TcpStream> {
    let addr = format!(
        "{}:{}",
        configuration::get_cert_provisoner_host(),
        CERT_PROVISIONER_MTLS_PORT
    );

    log::debug!("Attempting to get socket connection to {addr:?}");

    let socket_connection = TcpStream::connect(addr.clone())
        .await
        .map_err(ServerError::Io);

    log::debug!("Got socket connection to {addr:?}");

    socket_connection
}

fn get_mtls_connector(
    root_certificate: Certificate,
    client_key_pair: (Vec<Certificate>, PrivateKey),
) -> tokio_rustls::TlsConnector {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&root_certificate)
        .expect("Failed to add cert to root for talking to cert provisioner");

    let base_config_builder = tokio_rustls::rustls::ClientConfig::builder().with_safe_defaults();

    let (client_cert_chain, client_key) = client_key_pair;
    let mtls_connector_config = base_config_builder
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_cert_chain, client_key)
        .expect("Failed to add client cert for making connector to cert provisioner");

    tokio_rustls::TlsConnector::from(std::sync::Arc::new(mtls_connector_config))
}

fn get_token_request_metadata_from_env() -> GetCertTokenRequestControlPlane {
    let enclave_uuid = configuration::get_enclave_uuid();
    let version_id = configuration::get_enclave_version()
        .parse::<i32>()
        .expect("Can't parse Enclave version ENV var into integer");
    let enclave_name = configuration::get_enclave_name();
    let app_uuid = configuration::get_app_uuid();
    let team_uuid = configuration::get_team_uuid();

    GetCertTokenRequestControlPlane::new(
        enclave_uuid,
        version_id,
        enclave_name,
        app_uuid,
        team_uuid,
    )
}

#[derive(Clone)]
pub struct CertProvisionerClient {
    mtls_connector: tokio_rustls::TlsConnector,
    server_name: ServerName,
}

impl CertProvisionerClient {
    pub fn new(
        client_key_pair: (Vec<Certificate>, PrivateKey),
        root_certificate: Certificate,
    ) -> Self {
        let server_name: ServerName =
            ServerName::try_from(configuration::get_cert_provisoner_host().as_str())
                .expect("Hardcoded hostnames");

        Self {
            mtls_connector: get_mtls_connector(root_certificate, client_key_pair),
            server_name,
        }
    }

    fn construct_uri(&self, port: i32, path: &str) -> String {
        format!(
            "https://{}:{}{}",
            configuration::get_cert_provisoner_host(),
            &port,
            &path
        )
    }

    async fn get_connection(
        &self,
    ) -> Result<(
        SendRequest<hyper::Body>,
        Connection<TlsStream<TcpStream>, hyper::Body>,
    )> {
        let client_connection: TcpStream = get_socket().await?;

        let connection = self
            .mtls_connector
            .connect(self.server_name.clone(), client_connection)
            .await
            .map_err(ServerError::Io)?;

        hyper::client::conn::Builder::new()
            .handshake::<TlsStream<TcpStream>, hyper::Body>(connection)
            .await
            .map_err(ServerError::Hyper)
    }

    async fn send(
        &self,
        path: &str,
        method: &str,
        body: hyper::Body,
        mtls: bool,
    ) -> Result<Response<Body>> {
        let request = hyper::Request::builder()
            .uri(self.construct_uri(CERT_PROVISIONER_MTLS_PORT, path))
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                format!("Cage-Control-Plane/{}", &*CLIENT_VERSION),
            )
            .header(
                "Accept",
                format!("application/json;version={}", &*CLIENT_MAJOR_VERSION),
            )
            .method(method)
            .body(body)
            .expect("Failed to build request");

        let (mut request_sender, connection) = self.get_connection().await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                log::error!("Error in cert provisoner connection: {e} MTLS connection: {mtls}");
            }
        });

        let response = request_sender.send_request(request).await?;
        if !response.status().is_success() {
            return Err(ServerError::FailedRequest(response.status().to_string()));
        }

        Ok(response)
    }

    pub async fn get_token<T: DeserializeOwned>(&self, path: ConfigServerPath) -> Result<T> {
        let body = get_token_request_metadata_from_env().into_body()?;
        let response = self.send(&format!("{path}"), "GET", body, true).await?;
        let result: T = self.parse_response(response).await?;
        Ok(result)
    }

    async fn parse_response<T: DeserializeOwned>(&self, res: Response<Body>) -> Result<T> {
        let response_body = res.into_body();
        let response_body = hyper::body::to_bytes(response_body).await?;

        serde_json::from_slice(&response_body).map_err(ServerError::JsonError)
    }
}

pub trait CertProvisionerPayload: Sized + Serialize {
    fn into_body(self) -> Result<hyper::Body> {
        Ok(hyper::Body::from(serde_json::to_vec(&self)?))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetCertTokenRequestControlPlane {
    cage_uuid: String,
    version_id: i32,
    cage_name: String,
    app_uuid: String,
    team_uuid: String,
}

impl CertProvisionerPayload for GetCertTokenRequestControlPlane {}

impl GetCertTokenRequestControlPlane {
    fn new(
        cage_uuid: String,
        version_id: i32,
        cage_name: String,
        app_uuid: String,
        team_uuid: String,
    ) -> Self {
        Self {
            cage_uuid,
            version_id,
            cage_name,
            app_uuid,
            team_uuid,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetCertTokenResponseControlPlane {
    token: String,
}

impl CertProvisionerPayload for GetCertTokenResponseControlPlane {}

impl GetCertTokenResponseControlPlane {
    pub fn token(&self) -> String {
        self.token.clone()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetE3TokenResponseControlPlane {
    token: String,
    token_id: String,
}

impl CertProvisionerPayload for GetE3TokenResponseControlPlane {}

impl GetE3TokenResponseControlPlane {
    pub fn token(&self) -> String {
        self.token.clone()
    }
    pub fn token_id(&self) -> String {
        self.token_id.clone()
    }
}
