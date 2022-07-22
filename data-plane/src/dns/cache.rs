lazy_static::lazy_static! {
  static ref HOST_TO_IP: dashmap::DashMap<String, Vec<String>> = dashmap::DashMap::new();
}

pub struct Cache;

impl Cache {
    pub fn store_ip(domain: String, records: Vec<String>) {
        HOST_TO_IP.insert(domain, records);
    }

    pub fn get_ip(domain: String) -> Option<Vec<String>> {
        let fqdn = format!("{}.", &domain);
        HOST_TO_IP.get(&fqdn).map(|rr| rr.clone())
    }
}
