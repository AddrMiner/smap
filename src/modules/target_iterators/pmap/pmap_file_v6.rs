
use crate::modules::target_iterators::pmap::ip::IpStruct;

pub struct PmapFileIterV6 {

    // 目标ip地址队列
    pub tar_ips: Vec<u128>,

    // ip结构体队列
    // 注意: 该队列顺序需要和目标地址队列保持一致
    pub ips_struct:Vec<IpStruct>,

}


impl PmapFileIterV6 {


    /// 注意: 传入的迭代器必须在初始状态下
    pub fn new(tar_ips:Vec<u128>) -> Self {

        let cap = tar_ips.len();

        Self {
            tar_ips,
            ips_struct: Vec::with_capacity(cap),
        }
    }
}