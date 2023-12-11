use chrono::Local;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::{SenderBaseConf};
use crate::core::conf::tools::args_parse::ip::ipv6_binary_pattern::parse_ipv6_binary_pattern;
use crate::core::conf::tools::args_parse::ip::ipv6_pattern::parse_ipv6_pattern;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::cycle_pattern::CycleV6Pattern;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{CycleIpv6Pattern};
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;
use crate::tools::file::write_to_file::write_record;


impl CycleV6Pattern {

    /// zmap_v6 构造器
    pub fn new(args:&Args) -> Self {

        // 获取 探测目标
        let tar_ips_str = &TarIterBaseConf::parse_tar_ip(&args.tar_ips);
        let (ip_bits, base_ip_val, mask, parts, max_ip) = if tar_ips_str.contains('@'){
            // 如果字符串中包含 @ 字符, 当作 一般模式字符串 处理
            parse_ipv6_pattern(tar_ips_str)
        } else {
            // 如果不包含 @ 字符, 当作二进制字符串处理
            parse_ipv6_binary_pattern(tar_ips_str)
        };

        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports);

        // 基础配置
        let mut base_conf = BaseConf::new(args);


        // ipv6 探测模块
        let probe = ProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6),  ModuleConf::new_from_vec_args(&args.probe_args),
            &tar_ports, base_conf.aes_rand.seed, &args.fields);



        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             SenderBaseConf::get_tar_num(TarIterBaseConf::get_tar_ip_num_binary(ip_bits),tar_ports.len()),
                                             probe.max_packet_length_v6, false, true);

        // 创建目标迭代器
        let target_iter = CycleIpv6Pattern::new(ip_bits, base_ip_val, parts.clone(), tar_ports, &mut base_conf.aes_rand.rng);

        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV6::new(
            &args.black_list_v6, &args.white_list_v6, false);


        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        if let Some(summary_path) = &base_conf.summary_file {
            // 将 所有输入参数 写入记录文件
            let header = vec!["time", "args"];
            let val = vec![ Local::now().to_string(), format!("{:?}", args).replace(",", " ")];

            write_record("CycleV6Pattern", "args", summary_path, header, val);
        }

        let p_sub_one = target_iter.p_sub_one;
        let send_thread_num = sender_conf.send_thread_num as u128;
        Self {
            base_conf: base_conf.into(),
            target_iter: target_iter.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),

            probe: probe.into(),

            ip_bits_num: ip_bits,
            base_ip_val,
            mask,
            parts,

            assigned_target_range: TarIterBaseConf::cycle_group_assign_targets_u128(p_sub_one, send_thread_num),

            // 使用输入范围优化约束条件, 使得只有对探测范围造成影响的约束起效
            blocker: blocker.gen_local_constraints(base_ip_val, max_ip),

        }
    }


}