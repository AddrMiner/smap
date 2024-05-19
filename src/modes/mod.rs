
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
const MODES: [&str; 21] = ["cycle_v4","c4",
                          "cycle_v6", "c6",
                          "cycle_v6_pattern", "c6p",
                          "file_v4", "f4",
                          "file_v6", "f6",
                          "cycle_v4_v6", "c46",
                          "pmap_v4", "p4",
                          "pmap_v6", "p6",
                          "topo_v4", "t4",
                          "topo_v6", "t6",
                          "ipv6_addrs_gen"];
impl Mode {

    pub fn new(args:&Args) -> Box<dyn ModeMethod> {

        let mode = match args.mode.clone() {
            Some(m) => m,
            // 没有设置模式
            None => { helper(args); exit(0) }
        };

        match mode.as_str() {


            "cycle_v4" | "c4"  => Box::new(v4::CycleV4::new(args)),

            "cycle_v6" | "c6" => Box::new(v6::CycleV6::new(args)),

            "cycle_v6_pattern" | "c6p" => Box::new(v6::CycleV6Pattern::new(args)),

            "file_v4" | "f4"  => Box::new(v4::V4FileReader::new(args)),

            "file_v6" | "f6"  => Box::new(v6::V6FileReader::new(args)),

            "cycle_v4_v6" | "c46" => Box::new(mix::CycleV4V6::new(args)),

            "pmap_v4" | "p4" => Box::new(v4::PmapV4::new(args)),

            "pmap_v6" | "p6" => Box::new(v6::PmapV6::new(args)),

            "topo_v4" | "t4" => Box::new(v4::Topo4::new(args)),
            
            "topo_v6" | "t6" => Box::new(v6::Topo6::new(args)),

            "ipv6_addrs_gen" => Box::new(v6::SpaceTree6::new(args)),

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



