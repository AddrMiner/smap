use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::{get_conf_from_mod_or_sys, write_to_summary};
use crate::modes::v6::topo_test::DoubleTreeTest;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::IPv6FixedPrefixTree;

impl DoubleTreeTest {


    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec![]);
        // 预算(注意与ipv6活跃地址生成算法共用), 划分维度, 最大前缀长度, 学习率, 种子地址路径, 
        // 前缀列表路径, 最小前缀长度, 有效节点q_value阀限, 节点抽取数量, 起始ttl, 最大连续沉默数量
        get_conf_from_mod_or_sys!(module_conf; budget, divide_dim, max_prefix_len, learning_rate, seeds_path, min_target_num, rand_ord,
            prefix_path, min_prefix_len, threshold, extra_node_num, initial_ttl, gap_limit, prefix_tree_max_ttl, allow_leaf_expand, 
            allow_layer_expand, layer_expand_ratio);

        // 初始化 ipv6前缀空间树
        let prefix_tree = IPv6FixedPrefixTree::new(divide_dim, max_prefix_len, learning_rate, 
                                              seeds_path, prefix_path, min_prefix_len, threshold, 
                                              extra_node_num, allow_leaf_expand,allow_layer_expand, 
                                              layer_expand_ratio, rand_ord);

        // ipv6 拓扑探测模块
        let probe = TopoModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "topo6_default_probe_mod"), module_conf.clone());

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, None, None,
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "TestTree6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),

            budget,
            max_ttl: prefix_tree_max_ttl,
            probe: probe.into(),
            prefix_tree,

            initial_ttl,
            gap_limit,
            min_target_num,
        }
    }
    
}