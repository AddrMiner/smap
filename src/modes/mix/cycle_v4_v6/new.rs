use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::ip::mix::parse_mix_v4_v6_cycle_group;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::mix::cycle_v4_v6::CycleV4V6;
use crate::modules::probe_modules::probe_mod_v4::ProbeModV4;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{CycleIpv4Port, CycleIpv6Port};
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;
use crate::write_to_summary;

impl CycleV4V6 {

    pub fn new(args:&Args) -> Self {

        //  获取探测目标
        //  v4,v6:(start_ip, end_ip, tar_ip_num)
        //  ips_v4, ips_v6: (min_ip, max_ip, 总数量),  total_ip_num: ipv4 和 ipv6的总数量之和
        let (v4_ranges, v6_ranges, ips_v4, ips_v6, total_ip_num) =
        parse_mix_v4_v6_cycle_group(&TarIterBaseConf::parse_tar_ip(&args.tar_ips));
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "default_ports");

        // 基础配置
        let mut base_conf = BaseConf::new(args);

        // ipv4 ipv6 探测模块
        let probe_v4;
        let probe_v6;
        let max_packet_length;
        {
            let probe_args = ModuleConf::new_from_vec_args(&args.custom_args, vec![]);

            probe_v4 = ProbeModV4::new(
                &SenderBaseConf::parse_probe_v4(&args.probe_v4, "default_probe_mod_v4"),
                probe_args.clone(),
                &{
                    // 如果不存在ipv4目标, 就将 ipv4探测模块的 目标地址强制设为 0, 绕过icmp模块合法性检查
                    // 警告: 如果默认探测模块为 非网络层探测模块时, 此处会可能会报错
                    // 此处的唯一作用是绕过探测模块合法性检查
                    if ips_v4.2 == 0 { vec![0] } else { tar_ports.clone() }
                }, base_conf.aes_rand.seed,  &args.fields);

            probe_v6 = ProbeModV6::new(
                &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_probe_mod_v6"),
                probe_args,
                &{
                    if ips_v6.2 == 0 { vec![0] } else { tar_ports.clone() }
                }, base_conf.aes_rand.seed, &args.fields);

            // 将 两种模块 捕获数据包的最大长度中的最大值 作为 捕获数据包的最大长度
            if ips_v4.2 != 0 && ips_v6.2 != 0 {
                max_packet_length = if probe_v4.max_packet_length_v4 > probe_v6.max_packet_length_v6 {
                    probe_v4.max_packet_length_v4 } else { probe_v6.max_packet_length_v6 };
            } else if ips_v4.2 != 0 {
                max_packet_length = probe_v4.max_packet_length_v4;
            } else {
                // 此处必定存在 ipv4, ipv6中的一种
                max_packet_length = probe_v6.max_packet_length_v6;
            }
        }

        // 生成 ipv4 目标迭代器群, 每个范围对应一个迭代器, 迭代器数量 = 对应范围数量
        let mut target_iters_v4:Vec<CycleIpv4Port> = vec![];
        let mut total_p_sub_one_v4:u128 = 0;
        let mut p_sub_one_vec_v4:Vec<u64> = vec![];

        // 生成 ipv6 目标迭代器群
        let mut target_iters_v6:Vec<CycleIpv6Port> = vec![];
        let mut total_p_sub_one_v6:u128 = 0;
        let mut p_sub_one_vec_v6:Vec<u128> = vec![];
        {
            for (start_ip, _, tar_ip_num) in v4_ranges.iter() {
                let ipv4_iter = CycleIpv4Port::new(*start_ip, *tar_ip_num, tar_ports.clone(),
                                               &mut base_conf.aes_rand.rng);
                total_p_sub_one_v4 += ipv4_iter.p_sub_one as u128;
                p_sub_one_vec_v4.push(ipv4_iter.p_sub_one);
                target_iters_v4.push(ipv4_iter);
            }

            for (start_ip, _, tar_ip_num) in v6_ranges.iter() {
                let ipv6_iter = CycleIpv6Port::new(*start_ip, *tar_ip_num, tar_ports.clone(),
                                               &mut base_conf.aes_rand.rng);
                total_p_sub_one_v6 += ipv6_iter.p_sub_one;
                p_sub_one_vec_v6.push(ipv6_iter.p_sub_one);
                target_iters_v6.push(ipv6_iter);
            }
        }

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             SenderBaseConf::get_tar_num(total_ip_num, tar_ports.len()),
                                             max_packet_length, total_p_sub_one_v4 != 0, total_p_sub_one_v6 != 0);

        // 计算为 ipv4 和 ipv6分配的发送线程数量
        let (thread_num_v4, thread_num_v6) = TarIterBaseConf::assign_threads_for_v4_v6(total_p_sub_one_v4, total_p_sub_one_v6, sender_conf.send_thread_num);

        let (assigned_tasks_v4, assigned_tasks_v6) = TarIterBaseConf::cycle_group_assign_targets_mix(
             p_sub_one_vec_v4, p_sub_one_vec_v6, thread_num_v4, thread_num_v6
        );

        // 定义全局 黑白名单拦截器
        let blocker_v4 = BlackWhiteListV4::new(
            &args.black_list_v4, &args.white_list_v4, false);
        let blocker_v6 = BlackWhiteListV6::new(
            &args.black_list_v6, &args.white_list_v6, false);

        // 接收模块基础配置
        let receiver_conf= if ips_v4.2 != 0 && ips_v6.2 != 0 {
            ReceiverBaseConf::new(args, vec![probe_v4.filter_v4.clone(), probe_v6.filter_v6.clone()])
        } else if ips_v4.2 != 0 {
            ReceiverBaseConf::new(args, vec![probe_v4.filter_v4.clone()])
        } else { ReceiverBaseConf::new(args, vec![probe_v6.filter_v6.clone()]) };
        
        let ttl = args.ttl;

        write_to_summary!(base_conf; "CycleV4V6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe_v4: probe_v4.into(),
            probe_v6: probe_v6.into(),

            target_iters_v4, target_iters_v6,


            // 注意: 这里计算的范围大小是从 最小ip 到 最大ip 之间的范围大小, 用来设置 接收线程的位图
            tar_num_v4: SenderBaseConf::get_tar_num_without_option(ips_v4.2, tar_ports.len()),
            tar_num_v6: SenderBaseConf::get_tar_num_without_option(ips_v6.2, tar_ports.len()),

            // 外层向量长度为 ipv4线程数量,  内层向量长度为 ipv4范围数量

            assigned_target_range_v4: assigned_tasks_v4,

            // 外层向量长度为 ipv6线程数量,  内层向量长度为 ipv6范围数量
            assigned_target_range_v6: assigned_tasks_v6,

            // 使用 最小 和 最大 ip, 来优化拦截器约束范围
            blocker_v4: blocker_v4.gen_local_constraints(ips_v4.0, ips_v4.1),
            blocker_v6: blocker_v6.gen_local_constraints(ips_v6.0, ips_v6.1),

            v4_ranges,
            v6_ranges,
            ttl,
        }
    }
}