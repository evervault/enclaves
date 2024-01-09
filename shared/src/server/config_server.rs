use super::error;

pub mod routes {

    use super::error::{ServerError, ServerResult};

    use std::str::FromStr;

    #[derive(Clone, Debug)]
    pub enum ConfigServerPath {
        GetCertToken,
        PostTrxLogs,
        GetE3Token,
        Storage,
        AcmeSign,
        AcmeJWK,
    }

    impl FromStr for ConfigServerPath {
        type Err = ServerError;

        fn from_str(input: &str) -> ServerResult<ConfigServerPath> {
            match input {
                "/cert/token" => Ok(Self::GetCertToken),
                "/e3/token" => Ok(Self::GetE3Token),
                "/trx/logs" => Ok(Self::PostTrxLogs),
                "/storage" => Ok(Self::Storage),
                "/acme/sign" => Ok(Self::AcmeSign),
                "/acme/jwk" => Ok(Self::AcmeJWK),
                _ => Err(ServerError::InvalidPath(input.to_string())),
            }
        }
    }

    impl std::fmt::Display for ConfigServerPath {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Self::GetCertToken => write!(f, "/cert/token"),
                Self::GetE3Token => write!(f, "/e3/token"),
                Self::PostTrxLogs => write!(f, "/trx/logs"),
                Self::Storage => write!(f, "/storage"),
                Self::AcmeSign => write!(f, "/acme/sign"),
                Self::AcmeJWK => write!(f, "/acme/jwk"),
            }
        }
    }
}

pub mod requests {
    use crate::{acme::jws::JwsResult, logging::TrxContext};

    use super::error::ServerResult;
    use serde::{Deserialize, Serialize};

    pub trait ConfigServerPayload: Sized + Serialize {
        fn into_body(self) -> ServerResult<hyper::Body> {
            Ok(hyper::Body::from(serde_json::to_vec(&self)?))
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetTokenRequestDataPlane;

    impl Default for GetTokenRequestDataPlane {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GetTokenRequestDataPlane {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl ConfigServerPayload for GetTokenRequestDataPlane {
        fn into_body(self) -> ServerResult<hyper::Body> {
            Ok(hyper::Body::empty())
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertTokenResponseDataPlane {
        token: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetE3TokenResponseDataPlane {
        token: String,
        token_id: String,
    }

    impl ConfigServerPayload for GetCertTokenResponseDataPlane {}
    impl ConfigServerPayload for GetE3TokenResponseDataPlane {}

    impl GetCertTokenResponseDataPlane {
        pub fn new(token: String) -> Self {
            Self { token }
        }

        pub fn token(&self) -> String {
            self.token.clone()
        }
    }

    impl GetE3TokenResponseDataPlane {
        pub fn new(token: String, token_id: String) -> Self {
            Self { token, token_id }
        }

        pub fn token(&self) -> String {
            self.token.clone()
        }

        pub fn token_id(&self) -> String {
            self.token_id.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertRequestDataPlane {
        attestation_doc: String,
    }

    impl ConfigServerPayload for GetCertRequestDataPlane {}

    impl GetCertRequestDataPlane {
        pub fn new(attestation_doc: String) -> Self {
            Self { attestation_doc }
        }

        pub fn attestation_doc(&self) -> String {
            self.attestation_doc.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct Secret {
        pub name: String,
        pub secret: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetCertResponseDataPlane {
        intermediate_cert: String,
        key_pair: String,
        pub secrets: Option<Vec<Secret>>,
        pub context: ProvisionerContext,
    }

    // TODO: remove "cage" usages in provisioner
    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct ProvisionerContext {
        pub cage_uuid: String,
        pub cage_name: String,
        pub team_uuid: String,
        pub app_uuid: String,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetSecretsResponseDataPlane {
        pub secrets: Vec<Secret>,
        pub context: ProvisionerContext,
    }

    impl ConfigServerPayload for GetCertResponseDataPlane {}

    impl GetCertResponseDataPlane {
        pub fn cert(&self) -> String {
            self.intermediate_cert.clone()
        }

        pub fn key_pair(&self) -> String {
            self.key_pair.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PostTrxLogsRequest {
        trx_logs: Vec<TrxContext>,
    }

    impl ConfigServerPayload for PostTrxLogsRequest {}

    impl PostTrxLogsRequest {
        pub fn new(trx_logs: Vec<TrxContext>) -> Self {
            Self { trx_logs }
        }

        pub fn trx_logs(&self) -> Vec<TrxContext> {
            self.trx_logs.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetObjectRequest {
        key: String,
    }

    impl ConfigServerPayload for GetObjectRequest {}

    impl GetObjectRequest {
        pub fn new(key: String) -> Self {
            Self { key }
        }

        pub fn key(&self) -> String {
            self.key.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct GetObjectResponse {
        body: String,
    }

    impl ConfigServerPayload for GetObjectResponse {}

    impl GetObjectResponse {
        pub fn new(body: String) -> Self {
            Self { body }
        }

        pub fn body(&self) -> String {
            self.body.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct PutObjectRequest {
        key: String,
        object: String,
    }

    impl ConfigServerPayload for PutObjectRequest {}

    impl PutObjectRequest {
        pub fn new(key: String, object: String) -> Self {
            Self { key, object }
        }

        pub fn key(&self) -> String {
            self.key.clone()
        }

        pub fn object(&self) -> String {
            self.object.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct DeleteObjectRequest {
        key: String,
    }

    impl ConfigServerPayload for DeleteObjectRequest {}

    impl DeleteObjectRequest {
        pub fn new(key: String) -> Self {
            Self { key }
        }

        pub fn key(&self) -> String {
            self.key.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    #[serde(rename_all = "lowercase")]
    pub enum SignatureType {
        HMAC,
        ECDSA,
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct JwsRequest {
        pub signature_type: SignatureType,
        pub url: String,
        pub nonce: Option<String>,
        pub payload: String,
        pub account_id: Option<String>,
    }

    impl JwsRequest {
        pub fn new(
            signature_type: SignatureType,
            url: String,
            nonce: Option<String>,
            payload: String,
            account_id: Option<String>,
        ) -> Self {
            Self {
                signature_type,
                url,
                nonce,
                payload,
                account_id,
            }
        }
    }

    impl ConfigServerPayload for JwsRequest {}

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct JwsResponse {
        pub protected: String,
        pub payload: String,
        pub signature: String,
    }

    impl ConfigServerPayload for JwsResponse {}

    impl From<&JwsResponse> for JwsResult {
        fn from(jws: &JwsResponse) -> Self {
            JwsResult {
                protected: jws.protected.clone(),
                payload: jws.payload.clone(),
                signature: jws.signature.clone(),
            }
        }
    }

    #[derive(Serialize, Deserialize, Debug, Clone)]
    pub struct JwkResponse {
        pub alg: String,
        pub crv: String,
        pub kty: String,
        #[serde(rename = "use")]
        pub _use: String,
        pub x: String,
        pub y: String,
    }

    impl ConfigServerPayload for JwkResponse {}
}
