use crate::acme::helpers;
use openssl::pkey::{PKey, Private};

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

    pub fn from_env() -> Self {
        //TODO - Pull these from secrets manager env vars and parse;
        let ec = helpers::gen_ec_private_key().expect("Temporary - random EC key");
        let hmac_key =
            helpers::hmac_from_b64_string("placeholder").expect("Temporary - placeholder HMAC key");
        Self::new(
            ec,
            Some(ExternalAccountBinding::new("abc".into(), hmac_key)),
        )
    }
}
