use crate::core::conf::args::Args;
use crate::core::conf::tools::args_parse::others::{parse_summary_file};
use crate::core::conf::tools::net::interface::InterfaceConf;
use crate::tools::encryption_algorithm::aes::AesRand;


pub struct BaseConf {

    // 网络接口设置
    pub interface:Vec<InterfaceConf>,

    // 加密机 和 随机数发生器
    pub aes_rand:AesRand,

    // 配置与结果保存文件
    pub summary_file:Option<String>,

}

impl BaseConf {

    /// 构造基础配置
    /// 包括: 网络接口, 配置与结果保存文件, 加密机 和 随机数发生器
    pub fn new(args:&Args) -> Self {

        let interface_arg = &args.interface;

        // 生成接口配置信息
        let mut interface:Vec<InterfaceConf> = vec![];
        if interface_arg.len() == 0 {
            // 未指定接口, 由系统指定一个默认接口
            interface.push(InterfaceConf::new(None));
        } else {
            // 如果指定一个接口就设置一个接口, 如果指定多个接口就设置多个接口
            for interface_name in interface_arg.clone() {
                interface.push(InterfaceConf::new(Some(interface_name)));
            }

        }


        Self {
            interface,
            summary_file: parse_summary_file(&args.summary_file),
            aes_rand: AesRand::new(args.seed),
        }

    }

}


