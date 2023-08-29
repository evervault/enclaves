use crate::error;
use rand::prelude::IteratorRandom;
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::AsyncResolver;

pub type AsyncDnsResolver =
    AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>;

pub struct InternalAsyncDnsResolver {}
pub struct ExternalAsyncDnsResolver {}

impl InternalAsyncDnsResolver {
    pub fn new_resolver() -> Result<AsyncDnsResolver, trust_dns_resolver::error::ResolveError> {
        let dns_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253));
        let dns_resolver = get_dns_resolver(dns_ip)?;
        Ok(dns_resolver)
    }
}

impl ExternalAsyncDnsResolver {
    pub fn new_resolver() -> Result<AsyncDnsResolver, trust_dns_resolver::error::ResolveError> {
        let dns_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let dns_resolver = get_dns_resolver(dns_ip)?;
        Ok(dns_resolver)
    }
}

fn get_dns_resolver(
    dns_ip: IpAddr,
) -> Result<AsyncDnsResolver, trust_dns_resolver::error::ResolveError> {
    AsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[dns_ip], 53, true),
        ),
        ResolverOpts::default(),
    )
}

pub async fn get_ip_for_host_with_dns_resolver(
    dns_resolver: &AsyncDnsResolver,
    host: &str,
    port: u16,
) -> error::Result<Option<SocketAddr>> {
    let addr = dns_resolver
        .lookup_ip(host)
        .await?
        .iter()
        .choose(&mut rand::thread_rng())
        .map(|ip| SocketAddr::new(ip, port));

    Ok(addr)
}

#[cfg(not(feature = "enclave"))]
pub fn get_ip_for_localhost(port: u16) -> error::Result<Option<SocketAddr>> {
    let addr = Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
    ));

    Ok(addr)
}
