use crate::error;
use rand::prelude::IteratorRandom;
use std::net::Ipv4Addr;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig};
use trust_dns_resolver::TokioAsyncResolver;

pub struct InternalAsyncDnsResolver {}
pub struct ExternalAsyncDnsResolver {}

impl InternalAsyncDnsResolver {
    pub fn new_resolver() -> TokioAsyncResolver {
        let dns_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253));
        get_dns_resolver(dns_ip)
    }
}

impl ExternalAsyncDnsResolver {
    pub fn new_resolver() -> TokioAsyncResolver {
        let dns_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        get_dns_resolver(dns_ip)
    }
}

fn get_dns_resolver(dns_ip: IpAddr) -> TokioAsyncResolver {
    TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[dns_ip], 53, true),
        ),
        ResolverOpts::default(),
    )
}

pub async fn get_ip_for_host_with_dns_resolver(
    dns_resolver: &TokioAsyncResolver,
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
