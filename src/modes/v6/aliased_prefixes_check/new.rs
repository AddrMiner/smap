use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::{get_conf_from_mod_or_sys, write_to_summary};
use crate::modes::v6::aliased_prefixes_check::IPv6AliasedCheck;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6AliaChecker;

impl IPv6AliasedCheck {


    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数   注意: 这里将编码长度设为四个字节
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["payload_len=4".to_string()]);
        
        // 获取自定义参数: 前缀长度, 前缀数量, 每个前缀随机地址的数量, 占比多少会被计为别名前缀, 是否输出别名地址, 每轮次探测前缀的数量
        get_conf_from_mod_or_sys!(module_conf; prefix_len, prefix_count, rand_addr_len, alia_ratio, output_alia_addrs, prefixes_len_per_batch);
        
        // 初始化 别名前缀检查器
        let ipv6_aliased_checker = IPv6AliaChecker::new(TarIterBaseConf::parse_targets_file(&args.target_file), 
                                                        prefix_len, prefix_count, rand_addr_len, alia_ratio, prefixes_len_per_batch);
        
        //  ipv6探测模块(区域编码)
        let probe = CodeProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_code_probe_mod_v6"), module_conf
        );

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, None, None,
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "IPv6AliasedChecker"; "args"; args;);
        
        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),
            
            ipv6_aliased_checker,
            output_alia_addrs,
        }
        
    }
    
    
    
    
}