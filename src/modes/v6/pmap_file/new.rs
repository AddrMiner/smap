use std::process::exit;
use log::error;
use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::pmap_file::PmapFileV6;
use crate::{get_conf_from_mod_or_sys, write_to_summary, SYS};
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::modules::probe_modules::probe_mod_v6::ProbeModV6;
use crate::tools::file::parse_context::count_file_lines;

impl PmapFileV6 {

    pub fn new(args:&Args) -> Self {
        
        let path = TarIterBaseConf::parse_targets_file(&args.target_file);
        
        // 获取目标端口范围
        let tar_ports = TarIterBaseConf::parse_tar_port(&args.tar_ports, "pmap_default_ports");

        // 基础配置
        let base_conf = BaseConf::new(args);
        // 解析自定义参数    注意: 这里强制所有探测模块检查接收数据包的源端口
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["not_check_sport=false".to_string()]);

        // 从 自定义参数 或 系统配置 中读取 预算 和 推荐轮次, 是否允许概率相关图迭代
        get_conf_from_mod_or_sys!(module_conf; pmap_budget, pmap_batch_num, pmap_allow_graph_iter, 
            pmap_sampling_pro, pmap_min_sample_num, pmap_port_num_limit);

        // ipv6 探测模块
        let probe = ProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "pmap_default_probe_mod_v6"),
            module_conf, &tar_ports, base_conf.aes_rand.seed, &args.fields);
        // 如果 目标探测模块不使用端口, 直接报错并退出
        if !probe.use_tar_ports { error!("{}", SYS.get_info("err", "probe_not_use_ports")); exit(1) }
        
        // 推测出的目标数量
        let guess_tar_num = if cfg!(target_os = "windows") { None } else { count_file_lines(&path) };

        // 发送模块基础配置
        let sender_conf= match guess_tar_num { 
            Some(g) => {
                // 推测出的 抽样数量
                let guess_sample_num = Self::get_sample_num(g as usize, pmap_sampling_pro, pmap_min_sample_num) as u64;
                // 需要进行推荐扫描
                let recommend_scan = guess_sample_num < g;
                
                // 实际发送的数据包数量
                let guess_packet_num = if recommend_scan { 
                    guess_sample_num * (tar_ports.len() as u64) + (g - guess_sample_num) * (pmap_budget as u64) 
                } else { 
                    g * (tar_ports.len() as u64)
                };
                
                SenderBaseConf::new(args, &base_conf.interface, Some(guess_packet_num), 
                                    if recommend_scan {Some((pmap_batch_num as i64) * (pmap_budget as i64) + 1)} else { None }, 
                                    probe.max_packet_length_v6, false, true)
            }
            None => SenderBaseConf::new(args, &base_conf.interface, None, None, probe.max_packet_length_v6, false, true)
        };

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "PmapFileV6"; "args"; args;);
        
        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),
            
            pmap_budget,
            pmap_batch_num,
            pmap_allow_graph_iter,

            path,
            
            sampling_pro: pmap_sampling_pro,
            min_sample_num: pmap_min_sample_num,
            
            tar_ports,
            port_num_limit: pmap_port_num_limit,
        }
    }
    
    
}