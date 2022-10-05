use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod dns;
pub mod e3client;
pub mod error;
pub mod health;
#[cfg(feature = "tls_termination")]
pub mod server;

#[cfg(not(feature = "enclave"))]
use shared::server::TcpServer;
#[cfg(feature = "enclave")]
use shared::{server::VsockServer, ENCLAVE_CID};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CageContext {
    team_uuid: String,
    app_uuid: String,
    cage_name: String,
}

impl CageContext {
    pub fn new() -> std::result::Result<Self, std::env::VarError> {
        let app_uuid = std::env::var("EV_APP_UUID")?;
        let team_uuid = std::env::var("EV_TEAM_UUID")?;
        let cage_name = std::env::var("EV_CAGE_NAME")?;
        Ok(Self {
            app_uuid,
            team_uuid,
            cage_name,
        })
    }

    pub fn cage_name(&self) -> &str {
        &self.cage_name
    }

    pub fn app_uuid(&self) -> &str {
        &self.app_uuid
    }

    pub fn team_uuid(&self) -> &str {
        &self.team_uuid
    }

    pub fn get_cert_name(&self) -> String {
        format!("{}.{}", &self.cage_name, &self.app_uuid)
    }
}

#[cfg(not(feature = "enclave"))]
pub async fn get_tcp_server(
    port: u16,
) -> std::result::Result<TcpServer, shared::server::error::ServerError> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    TcpServer::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port)).await
}

#[cfg(feature = "enclave")]
pub async fn get_tcp_server(
    port: u16,
) -> std::result::Result<VsockServer, shared::server::error::ServerError> {
    println!("Creating VSock server");
    VsockServer::bind(ENCLAVE_CID, port.into()).await
}
