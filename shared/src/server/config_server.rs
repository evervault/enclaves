use super::error;

pub mod routes {

    use super::error::{ServerError, ServerResult};

    use std::str::FromStr;
    pub enum ConfigServerPaths {
        GetCertToken,
        GetCert,
    }

    impl FromStr for ConfigServerPaths {
        type Err = ServerError;

        fn from_str(input: &str) -> ServerResult<ConfigServerPaths> {
            match input {
                "/cert/token" => Ok(ConfigServerPaths::GetCertToken),
                _ => Err(ServerError::InvalidPath(input.to_string())),
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
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertRequestDataPlane {
        attestation_doc: String,
    }

    impl ConfigServerPayload for GetCertRequestDataPlane {}

    impl GetCertRequestDataPlane {
        pub fn attestation_doc(&self) -> String {
            self.attestation_doc.clone()
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct GetCertResponseDataPlane {
        cert: String,
    }

    impl ConfigServerPayload for GetCertResponseDataPlane {}

    impl GetCertResponseDataPlane {
        pub fn new(cert: String) -> Self {
            Self { cert }
        }
    }
}
