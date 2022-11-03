use super::error;

pub mod routes {

    use super::error::{ServerError, ServerResult};

    use std::str::FromStr;

    pub enum ConfigServerPath {
        GetCertToken,
    }

    impl FromStr for ConfigServerPath {
        type Err = ServerError;

        fn from_str(input: &str) -> ServerResult<ConfigServerPath> {
            match input {
                "/cert/token" => Ok(Self::GetCertToken),
                _ => Err(ServerError::InvalidPath(input.to_string())),
            }
        }
    }

    impl std::fmt::Display for ConfigServerPath {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            match self {
                Self::GetCertToken => write!(f, "/cert/token"),
            }
        }
    }
}

pub mod requests {
    use super::error::ServerResult;
    use serde::{Deserialize, Serialize};

    pub trait ConfigServerPayload: Sized + Serialize {
        fn into_body(self) -> ServerResult<hyper::Body> {
            Ok(hyper::Body::from(serde_json::to_vec(&self)?))
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertTokenRequestDataPlane;

    impl Default for GetCertTokenRequestDataPlane {
        fn default() -> Self {
            Self::new()
        }
    }

    impl GetCertTokenRequestDataPlane {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl ConfigServerPayload for GetCertTokenRequestDataPlane {
        fn into_body(self) -> ServerResult<hyper::Body> {
            Ok(hyper::Body::empty())
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertTokenResponseDataPlane {
        token: String,
    }

    impl ConfigServerPayload for GetCertTokenResponseDataPlane {}

    impl GetCertTokenResponseDataPlane {
        pub fn new(token: String) -> Self {
            Self { token }
        }

        pub fn token(&self) -> String {
            self.token.clone()
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

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertResponseDataPlane {
        intermediate_cert: String,
        key_pair: String,
    }

    impl ConfigServerPayload for GetCertResponseDataPlane {}

    impl GetCertResponseDataPlane {
        pub fn new(intermediate_cert: String, key_pair: String) -> Self {
            Self {
                intermediate_cert,
                key_pair,
            }
        }

        pub fn cert(&self) -> String {
            self.intermediate_cert.clone()
        }

        pub fn key_pair(&self) -> String {
            self.key_pair.clone()
        }
    }
}
