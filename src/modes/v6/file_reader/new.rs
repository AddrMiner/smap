use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::{SenderBaseConf};
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::file_reader::V6FileReader;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::modules::target_iterators::{TargetFileReader};
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;
use crate::write_to_summary;


impl V6FileReader {


    pub fn new(args:&Args) -> Self {

        // 获取 探测目标   文件迭代器不需要单独创建迭代器
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "default_ports");
        let mut targets = TargetFileReader::new(&TarIterBaseConf::parse_targets_file(&args.target_file));
        let (tar_ip_num, range_is_valid, first_tar, end_tar) = targets.parse_file_info_v6();

        // 基础配置
        let base_conf = BaseConf::new(args);

        // ipv6 探测模块
        let probe = ProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_probe_mod_v6"),
            ModuleConf::new_from_vec_args(&args.custom_args, vec![]),
            &tar_ports, base_conf.aes_rand.seed, &args.fields);

        // 发送模块基础配置
        let tar_num = SenderBaseConf::get_tar_num_with_option(tar_ip_num, tar_ports.len());
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface,
                                             tar_num, probe.max_packet_length_v6, false, true);


        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV6::new(
            &args.black_list_v6, &args.white_list_v6, false);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);
        
        let ttl = args.ttl;

        write_to_summary!(base_conf; "V6FileReader"; "args"; args;);

        if range_is_valid {

            Self {
                base_conf: base_conf.into(),
                assigned_target_range: targets.assign(sender_conf.send_thread_num as u64),
                target_iter: targets,
                sender_conf: sender_conf.into(),
                receiver_conf: receiver_conf.into(),

                probe: probe.into(),

                // 使用输入范围优化约束条件, 使得只有对探测范围造成影响的约束起效
                tar_num,
                tar_ports,
                blocker: blocker.gen_local_constraints(first_tar, end_tar),
                ttl,
            }

        } else {

            Self {
                base_conf: base_conf.into(),
                assigned_target_range: targets.assign(sender_conf.send_thread_num as u64),
                target_iter: targets,
                sender_conf: sender_conf.into(),
                receiver_conf: receiver_conf.into(),

                probe: probe.into(),

                tar_num,
                tar_ports,
                blocker,
                ttl,
            }
        }
    }


}