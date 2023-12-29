use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::ip::ipv4::parse_ipv4_cycle_group;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v4::pmap::PmapV4;
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::target_iterators::CycleIpv4;
use crate::{get_conf_from_mod_or_sys, SYS, write_to_summary};
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;

impl PmapV4 {


    pub fn new(args:&Args) -> Self {

        // 获取 探测目标
        // 注意:  必须是 ipv4范围或子网     目标端口为有效端口范围, 其它端口将被忽略, 一般默认为全部端口
        let (start_ip, end_ip, tar_ip_num) = parse_ipv4_cycle_group(&TarIterBaseConf::parse_tar_ip(&args.tar_ips));
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "pmap_default_ports"); // 注意这里由 pmap专门的参数指定, 下同

        // 基础配置
        let mut base_conf = BaseConf::new(args);

        // 解析自定义参数    注意: 这里强制所有探测模块检查接收数据包的源端口
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["not_check_sport=false".to_string()]);

        // 创建 无端口目标迭代器
        let tar_iter_without_port = CycleIpv4::new(start_ip, tar_ip_num, &mut base_conf.aes_rand.rng);

        // 计算 完全扫描(预扫描)最终索引
        let full_scan_last_index = Self::get_sample_last_index(&module_conf, tar_ip_num, tar_iter_without_port.p_sub_one,
                                                        // 自定义参数名称
                                                        "pmap_sampling_pro", "pmap_min_sample_num");

        // 从 自定义参数 或 系统配置 中读取 预算 和 推荐轮次, 是否允许概率相关图迭代
        get_conf_from_mod_or_sys!(module_conf; pmap_budget, pmap_batch_num, pmap_allow_graph_iter, pmap_use_hash_recorder);

        // ipv4 探测模块
        let probe = ProbeModV4::new(                            // 一般默认为 tcp_syn
            &SenderBaseConf::parse_probe_v4(&args.probe_v4, "pmap_default_probe_mod_v4"),
            module_conf, &tar_ports, base_conf.aes_rand.seed, &args.fields);

        // 如果 目标探测模块不使用端口, 直接报错并退出
        if !probe.use_tar_ports { error!("{}", SYS.get_info("err", "probe_not_use_ports")); exit(1) }

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             SenderBaseConf::get_tar_num(tar_ip_num, tar_ports.len()),
                                             probe.max_packet_length_v4, true, false);

        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV4::new(&args.black_list_v4, &args.white_list_v4, false);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v4.clone()]);

        write_to_summary!(base_conf; "PmapV4"; "args"; args;);

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

            start_ip,
            end_ip,
            tar_ip_num,
            tar_ports,
            blocker: blocker.gen_local_constraints(start_ip, end_ip),
        }
    }

}



