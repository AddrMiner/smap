use std::env;
use log::{error, warn};
use crate::core::conf::args::Args;
use crate::modes::helper_mode::modules_helper::{mode_help, output_help, probe_v4_help, probe_v6_help};
use crate::modes::helper_mode::print_modules::{print_modes, print_output_modules, print_probe_v4_modules, print_probe_v6_modules};
use crate::SYS;

mod print_modules;
mod modules_helper;

pub trait Helper {
    fn print_help() -> String;
}


pub fn helper(args:&Args){

    // 如果输入了 模式帮助 的 模式名称
    if let Some(mode_name) = &args.mode_help {
        println!("{}", mode_help(mode_name));
        return;
    }

    // 如果输入了 ipv4探测模块 的 探测模块名称
    if let Some(probe_name) = &args.probe_v4_help {
        println!("{}", probe_v4_help(probe_name));
        return;
    }

    // 如果输入了 ipv6探测模块 的 探测模块名称
    if let Some(probe_name) = &args.probe_v6_help {
        println!("{}", probe_v6_help(probe_name));
        return;
    }

    // 如果输入了 输出模块 的 输出模块名称
    if let Some(output_name) = &args.output_help {
        println!("{}", output_help(output_name));
        return;
    }


    // 如果没有设置模式 或 不存在该模式 (没有有效模式)， 提示警告信息，并提示目前支持的 各类模块
    warn!("{}", SYS.get_info("warn", "no_mode"));

    // 打印全部 模式 名称
    print_modes();

    // 打印全部 Ipv4探测模块 名称
    print_probe_v4_modules();

    // 打印全部 Ipv6探测模块 名称
    print_probe_v6_modules();

    // 打印全部 输出模块 名称
    print_output_modules();

    // 打印当前程序安装路径
    match env::current_exe() {
        Ok(mut p) => {
            p.pop(); p.pop();
            println!("{} {:?}", SYS.get_info("print", "install_path_info"), p);
        }
        Err(_) => { error!("{}", SYS.get_info("err", "get_install_path_failed")); }
    }

}