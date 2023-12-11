use std::net::Ipv6Addr;
use std::process::exit;
use log::error;
use crate::SYS;

pub struct SourceIpIterV6 {

    addrs:Vec<u128>,

    len:usize,
    index:usize
}


impl SourceIpIterV6 {


    pub fn new(addrs:&Vec<Ipv6Addr>) -> Self {

        if addrs.len() == 0 {
            error!("{}", SYS.get_info("err", "source_ips_is_null_v6"));
            exit(1)
        }

        let mut addrs_u128 = vec![];
        for i in addrs {
            addrs_u128.push(u128::from(*i));
        }

        Self {
            addrs:addrs_u128,
            len: addrs.len(),
            index: 0,
        }

    }


    /// 从下标1开始按顺序取出源地址, 每取出一次下标加一, 取完后下标重新从0开始
    pub fn get_src_ip_with_change(&mut self) -> u128 {

        self.index = (self.index + 1) % self.len;

        self.addrs[self.index]
    }



    /// 按当前下标取出源地址
    #[allow(dead_code)]
    pub fn get_src_ip(&self) -> u128 {

        self.addrs[self.index]
    }

    /// 将下标加一, 如果超出下标范围, 重新从0开始
    #[allow(dead_code)]
    pub fn index_add_one(&mut self){
        self.index = (self.index + 1) % self.len;
    }





}