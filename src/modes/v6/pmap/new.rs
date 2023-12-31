use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::ip::ipv6_binary_pattern::parse_ipv6_binary_pattern;
use crate::core::conf::tools::args_parse::ip::ipv6_pattern::parse_ipv6_pattern;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::{get_conf_from_mod_or_sys, SYS, write_to_summary};
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::modes::v6::pmap::PmapV6;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{CycleIpv6Pattern};
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;

impl PmapV6 {


    pub fn new(args:&Args) -> Self {

        // 获取 探测目标
        let tar_ips_str = &TarIterBaseConf::parse_tar_ip(&args.tar_ips);
        let (ip_bits_num, base_ip_val, mask, parts, max_ip) = if tar_ips_str.contains('@'){
            parse_ipv6_pattern(tar_ips_str)  // 如果字符串中包含 @ 字符, 当作 一般模式字符串 处理
        } else { parse_ipv6_binary_pattern(tar_ips_str) }; // 如果不包含 @ 字符, 当作二进制字符串处理
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "pmap_default_ports");
        let tar_ip_num = TarIterBaseConf::get_tar_ip_num_binary(ip_bits_num);

        // 基础配置
        let mut base_conf = BaseConf::new(args);

        // 解析自定义参数    注意: 这里强制所有探测模块检查接收数据包的源端口
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["not_check_sport=false".to_string()]);

        // 创建 无端口目标迭代器
        let tar_iter_without_port = CycleIpv6Pattern::new(ip_bits_num, base_ip_val, parts.clone(), &mut base_conf.aes_rand.rng);

        // 计算 完全扫描(预扫描)最终索引
        let full_scan_last_index = Self::get_sample_last_index(&module_conf, tar_ip_num, tar_iter_without_port.p_sub_one,
                                                               // 自定义参数名称
                                                               "pmap_sampling_pro", "pmap_min_sample_num");

        // 从 自定义参数 或 系统配置 中读取 预算 和 推荐轮次, 是否允许概率相关图迭代
        get_conf_from_mod_or_sys!(module_conf; pmap_budget, pmap_batch_num, pmap_allow_graph_iter, pmap_use_hash_recorder);

        // ipv6 探测模块
        let probe = ProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "pmap_default_probe_mod_v6"),
            module_conf, &tar_ports, base_conf.aes_rand.seed, &args.fields);

        // 如果 目标探测模块不使用端口, 直接报错并退出
        if !probe.use_tar_ports { error!("{}", SYS.get_info("err", "probe_not_use_ports")); exit(1) }

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             SenderBaseConf::get_tar_num(tar_ip_num, tar_ports.len()),
                                             probe.max_packet_length_v6, false, true);

        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV6::new(&args.black_list_v6, &args.white_list_v6, false);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "PmapV6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),

            tar_iter_without_port,
            full_scan_last_index,

            pmap_budget,
            pmap_batch_num,
            pmap_allow_graph_iter,
            pmap_use_hash_recorder,

            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),

            tar_ip_num,
            ip_bits_num,
            base_ip_val,
            mask,
            parts,
            tar_ports,
            blocker: blocker.gen_local_constraints(base_ip_val, max_ip),
        }
    }
}