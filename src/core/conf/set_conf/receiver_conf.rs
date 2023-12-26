
use crate::core::conf::args::Args;
use crate::modules::output_modules::OutputMod;

pub struct ReceiverBaseConf {

    // 初始化输出模块
    pub output_v4:OutputMod,
    pub output_v6:OutputMod,

    // 接收过滤器
    pub filter:Option<String>,

    // 允许探测失败的结果输出, 如 icmp差错报文包裹原始数据包, rst标志数据包等
    pub allow_no_succ:bool,

}


impl ReceiverBaseConf {


    pub fn new(args:&Args, probe_filter:Vec<String>) -> Self {


        let probe_filter = if probe_filter.len() == 0 {
            // 如果不存在探测模块过滤规则
            None
        } else {
            // 如果存在 一个或多个探测模块过滤规则, 将它们组合成以下形式
            // 规则1 || 规则2 || 规则3
            let mut probe_filter_str = String::new();
            for filter in probe_filter.iter() {
                probe_filter_str += &format!("( {} ) || ", filter);
            }

            probe_filter_str = probe_filter_str.trim_end_matches(|c| c == '|' || c == ' ').parse().unwrap();
            Some(probe_filter_str)
        };



        let filter = match probe_filter {
            None => {
                match &args.filter {
                    // 用户未设置过滤规则, 且探测模块不包含过滤规则
                    None => None,
                    // 用户设置了过滤规则, 探测模块不包含过滤规则
                    Some(a_f) => Some((*a_f).clone())
                }
            }
            Some(p_f) => {
                match &args.filter {
                    // 用户未设置过滤规则, 探测模块包含过滤规则
                    None => Some(p_f),
                    // 用户设置了过滤规则, 且探测模块包含过滤规则
                    Some(a_f) => Some(format!("{} && ( {} )", a_f, p_f))
                }
            }
        };


        Self {
            output_v4: OutputMod::new(&Self::parse_output_mod(&args.output_mod), None, &args.output_file_v4, false),
            output_v6: OutputMod::new(&Self::parse_output_mod(&args.output_mod), None, &args.output_file_v6, true),
            filter,
            allow_no_succ: args.allow_no_succ,
        }

    }



}