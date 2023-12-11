
mod v4;
mod helper_mode;
mod v6;
mod mix;

use std::process::exit;
use crate::core::conf::args::Args;
use crate::modes::helper_mode::helper;

pub struct Mode {}
pub use helper_mode::Helper;

/// 激活的所有模块
const MODES: [&str; 12] = ["cycle_v4","c4",
                          "cycle_v6", "c6",
                          "cycle_v6_pattern", "c6p",
                          "file_v4", "f4",
                          "file_v6", "f6",
                          "cycle_v4_v6", "c46"];
impl Mode {

    pub fn new(args:&Args) -> Box<dyn ModeMethod> {


        let mode = match (args.mode).clone() {
            Some(m) => m,
            None => {
                // 没有设置模式
                helper(args);
                exit(0)
            }
        };


        match mode.as_str() {


            "cycle_v4" | "c4"  => Box::new(v4::CycleV4::new(args)),

            "cycle_v6" | "c6" => Box::new(v6::CycleV6::new(args)),

            "cycle_v6_pattern" | "c6p" => Box::new(v6::CycleV6Pattern::new(args)),

            "file_v4" | "f4"  => Box::new(v4::V4FileReader::new(args)),

            "file_v6" | "f6"  => Box::new(v6::V6FileReader::new(args)),

            "cycle_v4_v6" | "c46" => Box::new(mix::CycleV4V6::new(args)),

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



