
mod v4;
mod helper_mode;
mod v6;
mod mix;
mod macros;

use std::process::exit;
use crate::core::conf::args::Args;
use crate::modes::helper_mode::helper;

pub struct Mode {}
pub use helper_mode::Helper;

/// 激活的所有模块
const MODES: [&str; 18] = ["c4",
                          "c6",
                          "c6p",
                          "f4",
                          "f6",
                          "c46",
                          "p4",
                          "p6",
                          "pf6",
                          "t4",
                          "t6",
                          "ipv6_addrs_gen",
                          "ac6",
                          "ipv6_double_tree_test", 
                          "tt6", "s6", "a6","e6"];
impl Mode {

    pub fn new(args:&Args) -> Box<dyn ModeMethod> {

        let mode = match args.mode.clone() {
            Some(m) => m,
            // 没有设置模式
            None => { helper(args); exit(0) }
        };

        match mode.as_str() {


            "c4"  => Box::new(v4::CycleV4::new(args)),

            "c6" => Box::new(v6::CycleV6::new(args)),

            "c6p" => Box::new(v6::CycleV6Pattern::new(args)),

            "f4"  => Box::new(v4::V4FileReader::new(args)),

            "f6"  => Box::new(v6::V6FileReader::new(args)),

            "c46" => Box::new(mix::CycleV4V6::new(args)),

            "p4" => Box::new(v4::PmapV4::new(args)),

            "p6" => Box::new(v6::PmapV6::new(args)),

            "pf6" => Box::new(v6::PmapFileV6::new(args)),

            "t4" => Box::new(v4::Topo4::new(args)),
            
            "t6" => Box::new(v6::Topo6::new(args)),

            "ipv6_addrs_gen" => Box::new(v6::SpaceTree6::new(args)),

            "ac6" => Box::new(v6::IPv6AliasedCheck::new(args)),

            // 暂时废弃， 但是其中包含可重用的算法代码
            "ipv6_prefix_tree" => Box::new(v6::PrefixTree6::new(args)),
            "ipv6_prefix_fixed_tree" => Box::new(v6::PrefixFixedTree6::new(args)),

            // 警告: 该模式只用作测试, 请及时删除
            "ipv6_double_tree_test" => Box::new(v6::DoubleTreeTest::new(args)),

            "tt6" => Box::new(v6::TreeTrace6::new(args)),

            "s6" => Box::new(v6::Scour6::new(args)),
            
            "a6" => Box::new(v6::Asset6::new(args)),
            
            "e6" => Box::new(v6::Edge6::new(args)),

            _ => {
                // 未查询到有效模式
                helper(args);
                exit(0)
            }
        }

    }


}



pub trait ModeMethod {

    // 执行函数
    fn execute(&self);

}



