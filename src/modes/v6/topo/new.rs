use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::{get_conf_from_mod_or_sys, SYS, write_to_summary};
use crate::modes::v6::topo::Topo6;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoModV6;
use crate::modules::target_iterators::CycleIpv6Pattern;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;

impl Topo6 {

    pub fn new(args:&Args) -> Self {

        // 基础配置
        let mut base_conf = BaseConf::new(args);

        // 解析自定义参数
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec![]);
        // 从 自定义参数 或 系统配置 中读取
        get_conf_from_mod_or_sys!(module_conf; topo6_rand_bits, topo_max_ttl);
        if topo_max_ttl > 64 { error!("{}", SYS.get_info("err", "topo_max_ttl_err")); exit(1) }

        // 获取 探测目标
        let tar_ips_str = &TarIterBaseConf::parse_tar_ip(&args.tar_ips);
        let (ip_bits_num, base_ip_val, mask, parts, max_ip) =
            Self::topo6_get_target_ips(tar_ips_str, topo6_rand_bits, &mut base_conf.aes_rand.rng);

        // ipv6 拓扑探测模块
        let topo_probe = TopoModV6::new(&SenderBaseConf::parse_probe_v6(&args.probe_v6, "topo6_default_probe_mod"), module_conf.clone());

        // ipv6 辅助拓扑探测模块    用于对预探测进行加强
        let topo_sub_probe = Self::get_sub_probe("topo_sub_probe_v6", module_conf);
        
        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, // 警告: 预测时间估算和速率控制按照  总数量=目标地址数量*最大ttl进行计算
                                             SenderBaseConf::get_tar_num(TarIterBaseConf::get_tar_ip_num_binary(ip_bits_num), topo_max_ttl),
                                             topo_probe.max_packet_length_v6, false, true);

        // 定义全局 黑白名单拦截器
        let blocker = BlackWhiteListV6::new(&args.black_list_v6, &args.white_list_v6, false);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![topo_probe.filter_v6.clone()]);

        let tar_iter = CycleIpv6Pattern::new(ip_bits_num, base_ip_val,
                                             parts.clone(), &mut base_conf.aes_rand.rng);

        write_to_summary!(base_conf; "Topo_v6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),

            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: topo_probe.into(),

            sub_probe: topo_sub_probe,
            ip_bits_num,
            base_ip_val,
            mask,
            parts,

            max_ttl: topo_max_ttl as u8,
            tar_iter,
            blocker: blocker.gen_local_constraints(base_ip_val, max_ip),
        }

    }


}