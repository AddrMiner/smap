use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::{get_conf_from_mod_or_sys, SYS, write_to_summary};
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::space_tree::SpaceTree6;
use crate::modules::probe_modules::active_probe_ipv6_code::CodeProbeModV6;
use crate::modules::target_iterators::IPv6SpaceTree;

pub enum SpaceTreeType {
    DENSITY
}

impl SpaceTree6 {


    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数   注意: 这里将编码长度设为两个字节
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["payload_len=2".to_string()]);
        let space_tree_type:String = module_conf.get_conf_or_from_sys(&String::from("space_tree_type"));
        // 预算, 每轮次的地址数量, 划分维度, 分割范围, 聚类区域数量上限, 不允许生成种子地址, 学习率, 区域提取数量, 种子地址默认数量
        get_conf_from_mod_or_sys!(module_conf; budget, batch_size, divide_dim, divide_range, max_leaf_size, no_allow_gen_seeds, learning_rate, region_extraction_num, seeds_num, no_allow_gen_seeds_from_file);
        
        // 初始化 ipv6地址空间树
        let space_tree = IPv6SpaceTree::new(
            divide_dim, divide_range, max_leaf_size, no_allow_gen_seeds, learning_rate, region_extraction_num, 
            TarIterBaseConf::parse_targets_file(&args.target_file), seeds_num, no_allow_gen_seeds_from_file
        );

        // 生成 ipv6地址空间树
        let tree_type= match space_tree_type.as_str() {
            // 生成 密度空间树
            "den" => SpaceTreeType::DENSITY,
            // 暂不支持的空间树类型
            _ => { error!("{}", SYS.get_info("err", "ipv6_space_tree_no_exist")); exit(1) }
        };
        
        //  ipv6探测模块(区域编码)
        let probe = CodeProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_code_probe_mod_v6"), module_conf
        );

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, Some(budget),
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "SpaceTree6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),
            
            budget,
            batch_size,
            space_tree_type: tree_type,
            space_tree,
        }
    }
}