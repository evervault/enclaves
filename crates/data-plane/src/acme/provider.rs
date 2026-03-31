#[derive(Debug, Clone)]
pub enum Provider {
    LetsEncrypt,
    ZeroSSL,
}

impl Provider {
    pub fn directory_path(&self) -> &str {
        match self {
            Provider::LetsEncrypt => "/directory",
            Provider::ZeroSSL => "/v2/DV90",
        }
    }

    pub fn hostname(&self) -> &str {
        match self {
            Provider::LetsEncrypt => "acme-v02.api.letsencrypt.org",
            Provider::ZeroSSL => "acme.zerossl.com",
        }
    }

    pub fn eab_required(&self) -> bool {
        match self {
            Provider::LetsEncrypt => false,
            Provider::ZeroSSL => true,
        }
    }

    pub fn get_stats_key(&self) -> &str {
        match &self {
            Self::LetsEncrypt => "acme.letsencrypt",
            Self::ZeroSSL => "acme.zerossl",
        }
    }
}
