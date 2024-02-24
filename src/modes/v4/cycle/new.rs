use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::{SenderBaseConf};
use crate::core::conf::tools::args_parse::ip::ipv4::parse_ipv4_cycle_group;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v4::cycle::CycleV4;
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::target_iterators::{CycleIpv4, CycleIpv4Port, CycleIpv4Type};
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::write_to_summary;


impl CycleV4 {

    /// zmap_v4 构造器
    pub fn new(args:&Args) -> Self {

        // 获取 探测目标
        let (start_ip, end_ip, tar_ip_num) = parse_ipv4_cycle_group(&TarIterBaseConf::parse_tar_ip(&args.tar_ips));
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "default_ports");

        // 基础配置
        let mut base_conf = BaseConf::new(args);

        // ipv4 探测模块
        let probe = ProbeModV4::new(
            &SenderBaseConf::parse_probe_v4(&args.probe_v4, "default_probe_mod_v4"),
            ModuleConf::new_from_vec_args(&args.custom_args, vec![]),
            &tar_ports, base_conf.aes_rand.seed, &args.fields);

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             SenderBaseConf::get_tar_num(tar_ip_num, tar_ports.len()),
                                             probe.max_packet_length_v4, true, false);

        // 创建目标迭代器
        let p_sub_one;
        let target_iter = if probe.use_tar_ports {
            let c4p = CycleIpv4Port::new(start_ip, tar_ip_num, tar_ports, &mut base_conf.aes_rand.rng);
            p_sub_one = c4p.p_sub_one;
            CycleIpv4Type::CycleIpv4Port(c4p)
        } else {
            let c4 = CycleIpv4::new(start_ip,tar_ip_num, &mut base_conf.aes_rand.rng);
            p_sub_one = c4.p_sub_one;
            CycleIpv4Type::CycleIpv4(c4)
        };


        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV4::new(
            &args.black_list_v4, &args.white_list_v4, false);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v4.clone()]);
        
        let ttl = args.ttl;

        // 将 所有输入参数 写入记录文件
        write_to_summary!(base_conf; "CycleV4"; "args"; args;);

        let send_thread_num = sender_conf.send_thread_num as u64;
        Self {
            base_conf: base_conf.into(),
            target_iter: target_iter.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),

            probe: probe.into(),

            start_ip,
            end_ip,
            tar_ip_num,

            ttl,
            assigned_target_range: TarIterBaseConf::cycle_group_assign_targets_u64(p_sub_one, send_thread_num),

            // 使用输入范围优化约束条件, 使得只有对探测范围造成影响的约束起效
            blocker: blocker.gen_local_constraints(start_ip, end_ip),
        }
    }


}