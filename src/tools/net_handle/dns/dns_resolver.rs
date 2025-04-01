use std::net::{Ipv4Addr, Ipv6Addr};
use hickory_resolver::{ResolveError, Resolver};
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::config::*;
use hickory_resolver::proto::runtime::TokioRuntimeProvider;

pub struct DNSResolver {
    resolver:Resolver<GenericConnector<TokioRuntimeProvider>>
}

impl DNSResolver {

    /// 构造dns解析器
    pub fn new() -> DNSResolver {

        DNSResolver {
            resolver: Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioConnectionProvider::default()
            ).build()
        }
    }

    /// 域名 => ipv4地址列表
    pub fn domain_to_v4(&self, domain:&str) -> Result<Vec<Ipv4Addr>, ResolveError>{

        let mut v4_array = vec![];

        // 创建临时运行时
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
        // 阻塞执行异步操作
        let res = rt.block_on(async {
            let res = self.resolver.ipv4_lookup(domain).await;
            res
        })?;

        for i in res.into_iter() {
            v4_array.push(i.0);
        }

        Ok(v4_array)
    }

    /// 域名 => ipv4地址(只有一个)
    pub fn domain_to_v4_one(&self, domain:&str) -> Result<Option<Ipv4Addr>, ResolveError> {

        // 创建临时运行时
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
        // 阻塞执行异步操作
        let res = rt.block_on(async {
            let res = self.resolver.ipv4_lookup(domain).await;
            res
        })?;

        let v4_one = res.iter().next();

        match v4_one {
            Some(a) => Ok(Some(a.0)),
            None => Ok(None)
        }

    }

    /// 域名 => ipv6列表
    pub fn domain_to_v6(&self, domain:&str) -> Result<Vec<Ipv6Addr>, ResolveError> {

        let mut v6_array = vec![];

        // 创建临时运行时
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
        // 阻塞执行异步操作
        let res = rt.block_on(async {
            let res = self.resolver.ipv6_lookup(domain).await;
            res
        })?;

        for i in res.into_iter() {
            v6_array.push(i.0);
        }

        Ok(v6_array)
    }

    /// 域名 => ipv6地址(只有一个)
    pub fn domain_to_v6_one(&self, domain:&str) -> Result<Option<Ipv6Addr>, ResolveError> {

        // 创建临时运行时
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
        // 阻塞执行异步操作
        let res = rt.block_on(async {
            let res = self.resolver.ipv6_lookup(domain).await;
            res
        })?;

        let v6_one = res.iter().next();

        match v6_one {
            Some(aaaa) => Ok(Some(aaaa.0)),
            None => Ok(None)
        }

    }
}