use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;
use trust_dns_resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::Resolver;

pub struct DNSResolver {
    resolver:Resolver
}

impl DNSResolver {

    /// 构造dns解析器
    pub fn new() -> DNSResolver {

        DNSResolver {
            resolver: Resolver::new(ResolverConfig::default(),
                                    ResolverOpts::default()).map_err(|_|{

                eprintln!("Unable to start DNS resolver");
                exit(1)
            }).unwrap(),
        }

    }

    /// 域名 => ipv4地址列表
    pub fn domain_to_v4(&self, domain:&str) -> Result<Vec<Ipv4Addr>, ResolveError>{

        let mut v4_array = vec![];

        let res = self.resolver.ipv4_lookup(domain)?;

        for i in res.into_iter() {

            v4_array.push(i.0);
        }

        Ok(v4_array)
    }

    /// 域名 => ipv4地址(只有一个)
    pub fn domain_to_v4_one(&self, domain:&str) -> Result<Option<Ipv4Addr>, ResolveError> {

        let res = self.resolver.ipv4_lookup(domain)?;

        let v4_one = res.iter().next();

        match v4_one {

            Some(a) => Ok(Some(a.0)),

            None => Ok(None)
        }

    }

    /// 域名 => ipv6列表
    pub fn domain_to_v6(&self, domain:&str) -> Result<Vec<Ipv6Addr>, ResolveError> {

        let mut v6_array = vec![];

        let res = self.resolver.ipv6_lookup(domain)?;

        for i in res.into_iter() {

            v6_array.push(i.0);
        }

        Ok(v6_array)
    }

    /// 域名 => ipv6地址(只有一个)
    pub fn domain_to_v6_one(&self, domain:&str) -> Result<Option<Ipv6Addr>, ResolveError> {

        let res = self.resolver.ipv6_lookup(domain)?;

        let v6_one = res.iter().next();

        match v6_one {

            Some(aaaa) => Ok(Some(aaaa.0)),

            None => Ok(None)
        }

    }



}