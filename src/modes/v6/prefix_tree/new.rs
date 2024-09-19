use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::{get_conf_from_mod_or_sys, SYS, write_to_summary};
use crate::modes::v6::prefix_tree::{PrefixTree6, SplitNodeSelectType};
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::IPv6PrefixTree;



impl PrefixTree6 {
    
    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec![]);
        let split_node_select_type:String = module_conf.get_conf_or_from_sys(&String::from("split_node_select_type"));
        get_conf_from_mod_or_sys!(module_conf; budget, divide_dim, max_prefix_len, learning_rate, seeds_path, min_target_num, rand_ord, allow_supplement_scan,
                prefix_path, min_prefix_len, threshold, extra_node_num, initial_ttl, gap_limit, prefix_tree_max_ttl, allow_leaf_expand, child_max_size);

        let prefix_tree =  IPv6PrefixTree::new(divide_dim, threshold, seeds_path, prefix_path, min_prefix_len,
                                                      max_prefix_len, learning_rate, extra_node_num, allow_leaf_expand, rand_ord, child_max_size);

        // ipv6 拓扑探测模块
        let probe = TopoModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "topo6_default_probe_mod"), module_conf.clone());

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, None, None,
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);
        
        let select_type = match split_node_select_type.as_str(){
            "cascade" => SplitNodeSelectType::CASCADE,
            "independent" => SplitNodeSelectType::INDEPENDENT,
            _ => {
                error!("{}", SYS.get_info("err", "ipv6_prefix_split_type_not_found")); exit(1)
            },
        };

        write_to_summary!(base_conf; "PrefixTree6"; "args"; args;);
        
        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),

            split_node_select_type: select_type,
            budget,
            max_ttl: prefix_tree_max_ttl,
            probe: probe.into(),
            prefix_tree,
            
            initial_ttl,
            gap_limit,
            min_target_num,
            
            allow_supplement_scan,
        }
    }
}