

use ahash::{AHashMap, AHashSet};
use crate::tools::check_duplicates::{DuplicateCheckerV6Port, ExtractActPortsV6};

pub struct HashSetV6Port {
    map:AHashMap<u128, AHashSet<u16>>
}


impl HashSetV6Port {
    pub fn new(ip_num:usize) -> Self {
        Self {
            map: AHashMap::with_capacity(ip_num),
        }
    }
}


impl DuplicateCheckerV6Port for HashSetV6Port {
    #[inline]
    fn set(&mut self, ip: u128, port: u16) {
        match self.map.get_mut(&ip) {
            Some(set) => {
                set.insert(port);
            }
            None => {
                let mut set = AHashSet::new();
                set.insert(port);
                self.map.insert(ip, set);
            }
        }
    }

    /// 警告: 哈希查重器无法验证是否在目标范围
    #[inline]
    fn not_marked_and_valid(&self, ip: u128, port: u16) -> bool {

        match self.map.get(&ip) {
            None => true,
            Some(set) => !set.contains(&port),
        }
    }
}


impl ExtractActPortsV6 for HashSetV6Port {

    #[inline]
    fn get_active_ports_u16_string(&self, ip: u128) -> (Vec<u16>, String) {

        match self.map.get(&ip){
            None => (Vec::new(), String::new()),
            Some(set) => {

                let mut act_ports:Vec<u16> = Vec::new();
                let mut act_ports_str:String = String::new();

                for port in set.iter() {
                    act_ports.push(*port);
                    act_ports_str.push_str(&format!("{}|", *port));
                }

                // 如果某个ip有对应集合, 其数量肯定不是零
                act_ports_str.pop();

                (act_ports, act_ports_str)
            }
        }
    }

    #[inline]
    fn get_active_ports_string(&self, ip: u128) -> (String, usize) {

        match self.map.get(&ip){
            None => (String::new(), 0),
            Some(set) => {
                let mut act_ports_str:String = String::new();

                for port in set.iter() {
                    act_ports_str.push_str(&format!("{}|", *port));
                }

                // 如果某个ip有对应集合, 其数量肯定不是零
                act_ports_str.pop();

                (act_ports_str, set.len())
            }
        }

    }
}

