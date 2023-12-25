pub mod bit_map;
pub mod hash_set;


pub trait DuplicateCheckerV4 {

    /// 对ip进行存在标记
    fn set(&mut self, ip:u32);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u32) -> bool;
}


pub trait DuplicateCheckerV6 {

    /// 对ip进行存在标记
    fn set(&mut self, ip:u128);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u128) -> bool;
}


pub trait DuplicateCheckerV4Port {

    /// 对ip端口对进行存在标记
    fn set(&mut self, ip:u32, port:u16);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u32, port:u16) -> bool;
}

pub trait DuplicateCheckerV6Port {

    /// 对ip端口对进行存在标记
    fn set(&mut self, ip:u128, port:u16);

    /// 如果没被标记,返回true
    /// 如果被标记或超出目标范围,返回false
    fn not_marked_and_valid(&self, ip:u128, port:u16) -> bool;
}



pub trait ExtractActPortsV4 {
    fn get_active_ports_u16_string(&self, ip:u32) -> (Vec<u16>, String);
    fn get_active_ports_string(&self, ip:u32) -> (String, usize);
}

pub trait ExtractActPortsV6 {
    fn get_active_ports_u16_string(&self, ip:u128) -> (Vec<u16>, String);
    fn get_active_ports_string(&self, ip:u128) -> (String, usize);
}

pub trait NotMarkedV4 {
    fn is_not_marked(&self, ip: u32) -> bool;
}

pub trait NotMarkedV6 {
    fn is_not_marked(&self, ip: u128) -> bool;
}

