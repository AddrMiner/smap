use std::sync::Arc;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modes::Helper;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6AliaChecker;
use crate::SYS;

mod execute;
mod new;





pub struct IPv6AliasedCheck {
    // 探测器基础配置
    pub base_conf:Arc<BaseConf>,
    pub sender_conf:Arc<SenderBaseConf>,
    pub receiver_conf:Arc<ReceiverBaseConf>,

    // 进行 区域编码 的 ipv6探测模块
    pub probe:Arc<CodeProbeModV6>,
    
    // ipv6 别名检测器
    pub ipv6_aliased_checker:IPv6AliaChecker,

    // 是否输出 别名地址
    pub output_alia_addrs:bool,
}



impl Helper for IPv6AliasedCheck {
    fn print_help() -> String {
        SYS.get_info("help", "IPv6AliasedCheck")
    }
}