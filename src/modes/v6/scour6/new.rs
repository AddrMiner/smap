use crate::core::conf::args::Args;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::set_conf::base_conf::BaseConf;
use crate::core::conf::set_conf::receiver_conf::ReceiverBaseConf;
use crate::core::conf::set_conf::sender_conf::SenderBaseConf;
use crate::{get_conf_from_mod_or_sys, write_to_summary};
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::Scour6;
use crate::modules::probe_modules::topo_mod_v6::CodeTopoProbeModV6;

impl Scour6 {
    
    pub fn new(args:&Args) -> Self {

        // 基础配置
        let base_conf = BaseConf::new(args);

        // 解析自定义参数   注意: 这里将编码长度设为三个字节
        let module_conf = ModuleConf::new_from_vec_args(&args.custom_args, vec!["payload_len=3".to_string()]);
        get_conf_from_mod_or_sys!(module_conf; budget, batch_size, expand_ttl_a, expand_ttl_b, sample_pow, show_prefix_num, window_size, start_hop_limit);

        // 探测模块
        let probe = CodeTopoProbeModV6::new(
            &SenderBaseConf::parse_probe_v6(&args.probe_v6, "default_code_topo_probe_mod_v6"), module_conf
        );

        // 发送模块基础配置
        let sender_conf= SenderBaseConf::new(args, &base_conf.interface, Some(budget), Some((budget / batch_size) as i64 + 1),
                                             probe.max_packet_length_v6, false, true);

        // 接收模块基础配置
        let receiver_conf= ReceiverBaseConf::new(args, vec![probe.filter_v6.clone()]);

        write_to_summary!(base_conf; "Scour6"; "args"; args;);

        Self {
            base_conf: base_conf.into(),
            sender_conf: sender_conf.into(),
            receiver_conf: receiver_conf.into(),
            probe: probe.into(),

            budget,
            batch_size,
            
            expand_ttl_a,
            expand_ttl_b,

            sample_pow,
            
            path: TarIterBaseConf::parse_targets_file(&args.target_file),
            
            window_size,
            start_hop_limit,
            show_prefix_num,
        }
    }
    
}