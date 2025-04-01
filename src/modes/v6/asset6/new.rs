use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::{get_conf_from_mod_or_sys, write_to_summary};
use crate::modes::v6::asset6::Asset6;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6PortSpaceTree;

impl Asset6 {


    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数   注意: 这里编码长度只能为四个字节
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["payload_len=4".to_string()]);

        // 预算, 每轮次的地址数量, 划分维度, 聚类区域数量上限, 不允许生成种子地址, 学习率, 区域提取数量, 种子地址默认数量
        get_conf_from_mod_or_sys!(module_conf; budget, batch_size, divide_dim, max_leaf_size, no_allow_gen_seeds, 
            learning_rate, region_extraction_num, seeds_num, port_entropy_mul, aliased_threshold, 
            no_allow_gen_seeds_from_file, aliased_prefixes_check, aliased_prefixes_path, max_port_num);
        
        // 初始化 ipv6-port 空间树
        let ipv6_port_space_tree = IPv6PortSpaceTree::new(
            divide_dim, max_leaf_size, no_allow_gen_seeds, port_entropy_mul, aliased_threshold, learning_rate, region_extraction_num,
            TarIterBaseConf::parse_targets_file(&args.target_file), seeds_num, no_allow_gen_seeds_from_file, aliased_prefixes_path
        );

        //  ipv6探测模块(区域编码)
        let probe = CodeProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_asset6_probe_mod"), module_conf
        );
        
        let wait_count = (budget / batch_size) as i64 + 1;
        let wait_count = if aliased_prefixes_check { 2 * wait_count } else { wait_count };

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, Some(budget), Some(wait_count),
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "Asset6"; "args"; args;);
        
        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),
            
            budget,
            batch_size,
            addr_port_space_tree: ipv6_port_space_tree,
            aliased_prefixes_check,
            max_port_num,
        }
    }
    
}