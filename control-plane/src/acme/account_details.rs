use openssl::pkey::{PKey, Private};

// use crate::configuration;

use super::helpers;

#[derive(Clone)]
pub struct AcmeAccountDetails {
    pub account_ec_key: PKey<Private>,
    //Used for CA's that require External Account Bindings (eg: zeroSSL)
    pub account_hmac: Option<PKey<Private>>,
}

impl AcmeAccountDetails {
    pub fn new(account_ec_key: PKey<Private>, account_hmac: Option<PKey<Private>>) -> Self {
        Self {
            account_ec_key,
            account_hmac,
        }
    }

    pub fn from_env() -> Self {
        //TODO - Pull these from secrets manager env vars and parse;
        let ec = helpers::gen_ec_private_key().expect("Temporary - random EC key");
        let hmac_key =
            helpers::hmac_from_b64_string("placeholder").expect("Temporary - placeholder HMAC key");
        Self::new(ec, Some(hmac_key))
    }
}
