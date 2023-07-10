use crate::error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

pub type AsyncDnsResolver =
    AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub fn get_internal_dns_resolver(
) -> Result<AsyncDnsResolver, trust_dns_resolver::error::ResolveError> {
    let aws_internal_dns_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253));
    AsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[aws_internal_dns_ip], 53, true),
        ),
        ResolverOpts::default(),
    )
}

#[cfg(feature = "enclave")]
pub async fn get_ip_for_host_with_dns_resolver(
    dns_resolver: &AsyncDnsResolver,
    host: &str,
    port: u16,
) -> error::Result<SocketAddr> {
    use crate::error::ServerError;
    use rand::prelude::IteratorRandom;

    let addr = dns_resolver
        .lookup_ip(host)
        .await?
        .iter()
        .choose(&mut rand::thread_rng())
        .map(|ip| SocketAddr::new(ip, port));

    addr.ok_or(ServerError::DNSNotFound)
}

#[cfg(not(feature = "enclave"))]
pub fn get_ip_for_localhost(port: u16) -> error::Result<SocketAddr> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

    Ok(addr)
}
