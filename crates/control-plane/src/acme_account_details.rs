use crate::configuration;
use openssl::pkey::{PKey, Private};
use shared::acme::error::AcmeError;
use shared::acme::helpers;

#[derive(Debug, Clone)]
pub struct ExternalAccountBinding {
    key_id: String,
    //HMAC key
    private_key: PKey<Private>,
}

impl ExternalAccountBinding {
    pub fn new(key_id: String, private_key: PKey<Private>) -> Self {
        Self {
            key_id,
            private_key,
        }
    }

    pub fn key_id(&self) -> String {
        self.key_id.clone()
    }

    pub fn private_key(&self) -> PKey<Private> {
        self.private_key.clone()
    }
}

#[derive(Clone)]
pub struct AcmeAccountDetails {
    pub account_ec_key: PKey<Private>,
    //Used for CA's that require External Account Bindings (eg: zeroSSL)
    pub eab_config: Option<ExternalAccountBinding>,
}

impl AcmeAccountDetails {
    pub fn new(account_ec_key: PKey<Private>, eab_config: Option<ExternalAccountBinding>) -> Self {
        Self {
            account_ec_key,
            eab_config,
        }
    }

    pub fn new_from_env() -> Result<Self, AcmeError> {
        let ec_key = configuration::get_acme_ec_key();
        let hmac_key_id = configuration::get_acme_hmac_key_id();
        let hmac_key_raw = configuration::get_acme_hmac_key();
        let hmac_key = helpers::hmac_from_b64_string(&hmac_key_raw)?;

        let eab_config = ExternalAccountBinding::new(hmac_key_id, hmac_key);
        Ok(AcmeAccountDetails::new(ec_key, Some(eab_config)))
    }
}
