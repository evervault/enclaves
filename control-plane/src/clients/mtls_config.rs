use tokio_rustls::rustls::{Certificate, PrivateKey};

use crate::configuration;
use crate::error::{Result, ServerError};

#[derive(Clone)]
pub struct CertProvisionerMtlsCerts {
    root_certificate: Certificate,
    client_key_pair: (Vec<Certificate>, PrivateKey),
}

impl CertProvisionerMtlsCerts {
    pub fn from_env_vars() -> Result<Self> {
        let client_certs_raw =
            configuration::get_cert_provisioner_mtls_cert_env().map_err(ServerError::EnvError)?;
        let client_key_raw =
            configuration::get_cert_provisioner_mtls_key_env().map_err(ServerError::EnvError)?;
        let root_certificate_raw = configuration::get_cert_provisioner_mtls_root_cert_env()
            .map_err(ServerError::EnvError)?;

        let client_certs_parsed = parse_client_certs(client_certs_raw.as_bytes())?;
        let client_key_parsed = parse_client_key(client_key_raw.as_bytes())?;
        let root_certificate_parsed = parse_root_cert(root_certificate_raw.as_bytes())?;

        Ok(Self {
            root_certificate: root_certificate_parsed,
            client_key_pair: (client_certs_parsed, client_key_parsed),
        })
    }

    pub fn root_cert(&self) -> Certificate {
        self.root_certificate.clone()
    }

    pub fn client_key_pair(&self) -> (Vec<Certificate>, PrivateKey) {
        self.client_key_pair.clone()
    }
}

fn parse_client_certs(mut client_cert_raw: &[u8]) -> Result<Vec<Certificate>> {
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut client_cert_raw)
        .map(|certs| certs.into_iter().map(Certificate).collect())
        .map_err(|err| {
            ServerError::CertProvisionerMtls(format!(
                "Couldn't parse cert-provisioner client cert. Error:   {err}"
            ))
        })?;

    if certs.is_empty() {
        return Err(ServerError::CertProvisionerMtls(
            "No client certs present in input to parse.".to_string(),
        ));
    };

    Ok(certs)
}

fn parse_client_key(mut client_key_raw: &[u8]) -> Result<PrivateKey> {
    let parsed_keys = rustls_pemfile::pkcs8_private_keys(&mut client_key_raw).map_err(|err| {
        ServerError::CertProvisionerMtls(format!(
            "Couldn't parse cert-provisioner client key from secrets. Error: {err}"
        ))
    })?;

    if parsed_keys.is_empty() {
        return Err(ServerError::CertProvisionerMtls(
            "No client key present in input to parse.".to_string(),
        ));
    };

    Ok(PrivateKey(parsed_keys[0].clone()))
}

fn parse_root_cert(mut root_cert_raw: &[u8]) -> Result<Certificate> {
    let certs: Vec<Certificate> = rustls_pemfile::certs(&mut root_cert_raw)
        .map(|certs| certs.into_iter().map(Certificate).collect())
        .map_err(|err| {
            ServerError::CertProvisionerMtls(format!(
                "Couldn't parse cert-provisioner root cert. Error: {err}"
            ))
        })?;

    if certs.len() != 1 {
        return Err(ServerError::CertProvisionerMtls(
            "Expected only a single root cert. ".to_string(),
        ));
    };

    Ok(certs[0].clone())
}

#[test]
pub fn test_parsing_client_cert_success() {
    // Cert generated for testing
    let raw_client_cert = r#"-----BEGIN CERTIFICATE-----
MIIDcDCCAligAwIBAgIUKwzqLPSEznL74Hv0MlMTsgxG8DYwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEwMTgxNDQyMDRaFw0yMjEx
MTcxNDQyMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDb5rnQweasuFlEUpPEvCBoXfzQkWYYb1Lk0QLBfgYX
QCeobHyVJ0Yti4df22n2DMoNaUtBLRA8vGZhOjQkH82//tLFKfwdP+PMDS4K5O/r
WVKj/Nsvp66Zmx1eJ1uddXirGoZOB2VMb0MKaPJSk4wTtPwVXlWOO0ryWivadPyK
f5i23Ng0N+rSxg7C/zbNiyz2jH42zPE50Hx3xGfr9n8mJ4C0NIrL+eDv6Y4B8eb8
Ka/KXaooQKfGwX17isQhYuC4Ssr/M5M6vEMHDcB+AySvXPFr7dFfVl7OUBDFyRL0
kE7ytrmfUoQJYBprYv9eHFedBEyU6aoOf0URuAJ6BoszAgMBAAGjWDBWMBQGA1Ud
EQQNMAuCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUalFvFQhYM4YMccZANNcbjiiLRuQw
HwYDVR0jBBgwFoAUXVzeATUyAuMDPORfa1xKM6sDnPAwDQYJKoZIhvcNAQELBQAD
ggEBAH8wS+C51IrZ17ydEOyalmWHOlsZhUkSLbRG+83BZIEGe25TkAWULCWSUQI4
8WRf+7+9gVe6Nf7Xhq+rzkPdRZNaetuD0dgajGDTVFE0E+h8THj2OjVkPdobDCOU
fJFswicNLenLhcsNvTJVnSFssMCEBDdvzXNjO8r5M71jFBjU1nWC1U4OG03ppOA2
KVPQzO2ZgTpgn+AWlCQ1j+4hR4dySbXqPSr30rsgWBmAQRXMk0/nE45E0N5M4+Xx
LXxrIkXSOvRiiF/y2JOp8a989nSJTpfL0UgbBblwNnMRbz7r/6H/jNgNftNqKiaf
7/4OIsvvQ71bkQfu4slvPD9L28w=
-----END CERTIFICATE-----
    "#
    .as_bytes();

    let result = parse_client_certs(raw_client_cert);

    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

pub fn test_parsing_client_cert_failure_when_invalid() {
    let raw_client_cert = r#"-----BEGIN CERTTE-----
MIIDcDCCAligAwIBAgIUKwzqLPSEznL74Hv0MlMTsgxG8DYwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEwMTgxNDQyMDRaFw0yMjEx
MTcxNDQyMDRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDb5rnQweasuFlEUpPEvCBoXfzQkWYYb1Lk0QLBfgYX
QCeobHyVJ0Yti4df22n2DMoNaUtBLRA8vGZhOjQkH82//tLFKfwdP+PMDS4K5O/r
WVKj/Nsvp66Zmx1eJ1uddXirGoZOB2VMb0MKaPJSk4wTtPwVXlWOO0ryWivadPyK
f5i23Ng0N+rSxg7C/zbNiyz2jH42zPE50Hx3xGfr9n8mJ4C0NIrL+eDv6Y4B8eb8
Ka/KXaooQKfGwX17isQhYuC4Ssr/M5M6vEMHDcB+AySvXPFr7dFfVl7OUBDFyRL0
kE7ytrmfUoQJYBprYv9eHFedBEyU6aoOf0URuAJ6BoszAgMBAAGjWDBWMBQGA1Ud
EQQNMAuCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUalFvFQhYM4YMccZANNcbjiiLRuQw
HwYDVR0jBBgwFoAUXVzeATUyAuMDPORfa1xKM6sDnPAwDQYJKoZIhvcNAQELBQAD
ggEBAH8wS+C51IrZ17ydEOyalmWHOlsZhUkSLbRG+83BZIEGe25TkAWULCWSUQI4
8WRf+7+9gVe6Nf7Xhq+rzkPdRZNaetuD0dgajGDTVFE0E+h8THj2OjVkPdobDCOU
fJFswicNLenLhcsNvTJVnSFssMCEBDdvzXNjO8r5M71jFBjU1nWC1U4OG03ppOA2
KVPQzO2ZgTpgn+AWlCQ1j+4hR4dySbXqPSr30rsgWBmAQRXMk0/nE45E0N5M4+Xx
LXxrIkXSOvRiiF/y2JOp8a989nSJTpfL0UgbBblwNnMRbz7r/6H/jNgNftNqKiaf
7/4OIsvvQ71bkQfu4slvPD9L28w=
-----END CERTIFICATE-----
    "#
    .as_bytes();

    let result = parse_client_certs(raw_client_cert);

    assert!(result.is_err());
}

#[test]
pub fn test_parsing_client_cert_failure_when_missing() {
    let raw_client_cert: &[u8] = &[];

    let result = parse_client_certs(raw_client_cert);

    assert!(result.is_err());
}

#[test]
pub fn test_parsing_client_key_success() {
    // Key generated for testing
    let raw_client_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDb5rnQweasuFlE
UpPEvCBoXfzQkWYYb1Lk0QLBfgYXQCeobHyVJ0Yti4df22n2DMoNaUtBLRA8vGZh
OjQkH82//tLFKfwdP+PMDS4K5O/rWVKj/Nsvp66Zmx1eJ1uddXirGoZOB2VMb0MK
aPJSk4wTtPwVXlWOO0ryWivadPyKf5i23Ng0N+rSxg7C/zbNiyz2jH42zPE50Hx3
xGfr9n8mJ4C0NIrL+eDv6Y4B8eb8Ka/KXaooQKfGwX17isQhYuC4Ssr/M5M6vEMH
DcB+AySvXPFr7dFfVl7OUBDFyRL0kE7ytrmfUoQJYBprYv9eHFedBEyU6aoOf0UR
uAJ6BoszAgMBAAECggEABDA5xkDeuzQOAPjWjkiL56JFXvUhNZba/MGQtCHZBZI6
glgRW8yOSEC3T9Ty5NG/5r2xQQe5rgccDZ2rPwMOYin4GTrBltEcuyE/S5jTTeeu
QSLVDgC7W3sHCozfuCSDOsSsoFFnYjCIZ7LQYfRhhxi5SaOgHao6SZfyH4YYtEHc
bAPwV60JoyipavK3369MopWBznaW4lVn8fZ3Sj/JHdCnIWpvsWHOKnGq9HiLg1FL
Wo8QdBF0TmF5K64BQ3WuW9+hZzP0/lXDefaVVyLbkyuJ3v0JSdeNsTq7sE8MZyRl
9bdr9DQrFKvHVa0fWGmjgc2tZ2J9NleUjWGzXmAIAQKBgQDlX01Y5uBpY2olAuXX
e166xUu++n/ceIkWRnoCx4wZbvfrhjvhEsqr7DtZr8hBRv/DLRqmuQSF7vYE/pqb
b6kAAOQH9OmaSMDeDWoLVF7ln+x5+m7CR5sj2kv/8nCJhDD7xD+brvOvefrFBb/f
9AJobSNXSet7Tgl5DBrsGhEoAQKBgQD1bfSpiueDj3aahhoMemeTiu6oR7/zuSrx
GFqhkdNUiIsdht7SB/2sWPwsik+dtGhVZNSzFFfxZQIxfjPNvv+O1LsW8BqGS7+f
Oerb+ixCx2omU5XMqnYgN7ezUpXnfS17BLSagbny6KlVrEHFvFXtDb9dGkla8xOn
BBKk9qOTMwKBgQCpjVpCtl/654cmFs9KCyNKUt+cK9XqZpuHgM9eUJ2qi1Huo0qO
JPL2RWjV8k/ImTAk2amSxr+mNa9cn8wvzEmT/BSUISGxb8hKHIZgG50OhroqrMnF
CWOQDCUT7OXtcW84HKicb6Yo97U8gPSGGvzQrqRqOPU+L8Bm32DjWJ2IAQKBgQDC
ujEq69jwmz1BMTEtwVi4yby9q9/y4nHdxLL0Cp2gLo4iKUZVYp20xw2d0UeGGwPE
7TGNvJBiKQBqgHVdwzNFAihG9M42y5cIII3lZ0MC4PGp4xuxvXXn7g1ErDvf5YPW
XU9mX5NH1a21Ge09lEagxQ2WMysMjFyFYUfhtwbl3QKBgQDP6KV8ZysHLNp6uB49
fo8FDINOAtifN/92B2c0fQA1Du2HyWJIWRFq2VII6gvnPPHc/BLTbUCBZknbEIqJ
mHjwED820pe9sMcwOuHhvEptuZccQNpRGdpbPdVX5gAKBAj8seSKtfZ7ATnXtZWX
K67w/LBeNEJwwo6342eNPC8nsw==
-----END PRIVATE KEY-----
    "#
    .as_bytes();

    let result = parse_client_key(raw_client_key);

    assert!(result.is_ok());
}

#[test]
pub fn test_parsing_client_key_failure_when_invalid() {
    let raw_client_key = r#"-----BEGIN PRI KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDb5rnQweasuFlE
UpPEvCBoXfzQkWYYb1Lk0QLBfgYXQCeobHyVJ0Yti4df22n2DMoNaUtBLRA8vGZh
OjQkH82//tLFKfwdP+PMDS4K5O/rWVKj/Nsvp66Zmx1eJ1uddXirGoZOB2VMb0MK
aPJSk4wTtPwVXlWOO0ryWivadPyKf5i23Ng0N+rSxg7C/zbNiyz2jH42zPE50Hx3
xGfr9n8mJ4C0NIrL+eDv6Y4B8eb8K
-----END PRIVATE KEY-----
    "#
    .as_bytes();

    let result = parse_client_key(raw_client_key);

    assert!(result.is_err());
}

#[test]
pub fn test_parsing_client_key_failure_when_missing() {
    let raw_client_key: &[u8] = &[];

    let result = parse_client_key(raw_client_key);

    assert!(result.is_err());
}

#[test]
pub fn test_parsing_root_cert_success() {
    // Cert generated for testing
    let raw_root_cert = r#"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBrpxnCgzGrTu6oze3LoRexApI6owDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEwMTgxNDQwNThaFw0yMjEx
MTcxNDQwNThaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC7A08e1WBqLlNMZNAVciDVC/c172E4v5LrCncXamLi
sqeG5Q0GvlM4bXJppoaLpQefxYd7o1CMyZx0FTRVvUqLYD5rkGfGH8nJirZm60R6
OAPimdGi9MfiuF0tYFPoeLqhYfhGgUeJdVU8acSH1fBWzMVjo5KrYMLCSQ+E4oEx
wLfvVkIDr1UpRReY4lTaUJVtR+EYQOPhhskrrRcQ7REfUoRuLX/Chm22vR7OW65T
1eZ1hEoI+tUVIfRFgwbyFU6E7FBrblI9DF2QqVhVtOy1iMkZEz69AT8kX0KmlM10
wd49Ffz1h3tZS1y7uKwWTpg56cTFhzmcIjypU10r/AoPAgMBAAGjUzBRMB0GA1Ud
DgQWBBRdXN4BNTIC4wM85F9rXEozqwOc8DAfBgNVHSMEGDAWgBRdXN4BNTIC4wM8
5F9rXEozqwOc8DAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBc
R+eUFE28qhTRgZvIdsYn722QN/3Nf1Z3gB382rRsdXpQOVVfdQNKnO04cELu/P3S
+j4VkCLlsYj7O+fK3iBEHchPJkupKdoW8LnJbQB5FzbEBdB39FxRDetM3mLxzy/f
bPWsNWGrRg7rK7cQP31U3InUrwJg9E/rEXl8nBPP2jCOOaXVexr25PsxOe/X6f+z
cMMUrFHMSJi1omxeEkRFQMLgO+Bsef0AAL7G3wahGiqn540+U/2VmAglL8h7qcbW
Kkn+MDfmc9hsLah0btbiBdjr0X9txAOIo3vMl1mRTLMaWt9X3Ylb9JNFE9OT2z90
RYiTk2wITWKgcj+iRRhL
-----END CERTIFICATE-----
    "#
    .as_bytes();

    let result = parse_root_cert(raw_root_cert);

    assert!(result.is_ok());
}

#[test]
pub fn test_parsing_root_cert_failure_when_invalid() {
    let raw_root_cert = r#"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUBrpxnCgzGrTu6oze3LoRexApI6owDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjEwMTgxNDQwNThaFw0yMjEx
MTcxNDQwNThaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhTLMaWt9X3Ylb9JNFE9OT2z90
RYiTk2wITWKgcj+iRRhL
-----END CERTI-----
    "#
    .as_bytes();

    let result = parse_root_cert(raw_root_cert);

    assert!(result.is_err());
}

#[test]
pub fn test_parsing_root_cert_failure_when_missing() {
    let raw_root_cert: &[u8] = &[];

    let result = parse_root_cert(raw_root_cert);

    assert!(result.is_err());
}
