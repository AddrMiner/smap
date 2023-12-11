

mod core;
mod modes;
mod modules;
mod tools;

use once_cell::sync::Lazy;
use crate::core::conf::args::Args;
use crate::core::conf::sys_config::SysConf;
use crate::core::sys::logger::set_logger;
use crate::modes::{Mode};
use crate::tools::net_handle::dns::dns_resolver::DNSResolver;

// 在编译时获取 系统配置 和 提示信息
pub static SYS: Lazy<SysConf> = Lazy::new(|| {
    SysConf::new()
});

// 全局 DNS 解析器
pub static DNS: Lazy<DNSResolver> = Lazy::new(|| {
   DNSResolver::new()
});

fn main() {
    
    // 定义模式
    let mode;
    {
        // 获取命令行参数
        let args = Args::get_args();

        // 配置 系统日志
        set_logger(&args);

        // 选择并创建模式
        mode = Mode::new(&args);
    }

    // 执行模式
    mode.execute();
}
