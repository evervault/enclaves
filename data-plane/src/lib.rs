use serde::{Deserialize, Serialize};

pub mod crypto;
pub mod dns;
pub mod e3client;
pub mod error;
pub mod server;

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
