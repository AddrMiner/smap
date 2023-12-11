use std::net::{Ipv4Addr, Ipv6Addr};
use crate::core::conf::args::Args;
use crate::core::conf::tools::net::interface::InterfaceConf;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;


pub struct RateGlobalConf {

    // 目标速度, 以 秒 为单位
    // 注意存储的是已经除以线程数量的值.
    // 使用默认分配机制,在不均衡状态下, 各线程的探测目标数量也不超过一. 可以近似为不存在误差
    pub tar_rate: f64,

    pub running_time: f64,

    // 每个 batch 必须暂停的时间
    pub must_sleep:u64,

    // 每个 发送batch 的大小
    pub batch_size:u64,
}


pub struct SenderBaseConf {


    // 源接口名称 和 对应的源地址, 注意下标是一一对应的
    pub source_interface_v4:Vec<String>,
    pub source_addrs_v4:Vec<Vec<Ipv4Addr>>,
    pub source_interface_v6:Vec<String>,
    pub source_addrs_v6:Vec<Vec<Ipv6Addr>>,

    // 源端口设置
    pub source_ports:Vec<u16>,

    // 如果发送失败, 最多会尝试多少次
    pub send_attempt_num:i32,

    // 执行发送任务的线程数量
    pub send_thread_num:usize,

    // 全局发送速率
    pub global_rate_conf:RateGlobalConf,

    // 所有发送线程结束后的冷却时间
    // 在发送线程结束后等待这段冷却时间之后才终止接收线程
    pub cool_seconds:i64,

}


impl SenderBaseConf {

    /// 构造<u>发送者</u>基础配置
    /// 包括: 源地址(ipv4, ipv6), 源端口, 发送重试次数, 发送线程数量
    pub fn new(args:&Args, interface:&Vec<InterfaceConf>,
               target_num:Option<u64>,max_packet_length:usize, have_v4:bool, have_v6:bool) -> Self {


        // 源地址拦截器, 主要用途是清除 用户设定 或 自动从系统中获取到的 无效源地址, 比如私有地址, 特殊用途的地址等
        let source_blocker_v4 = BlackWhiteListV4::new(&args.source_black_list_v4, &args.source_white_list_v4, true);
        let source_blocker_v6 = BlackWhiteListV6::new(&args.source_black_list_v6, &args.source_white_list_v6, true);

        // 源地址
        let source_addrs= Self::parse_source_addrs(&args.source_addrs,interface, have_v4, have_v6, &source_blocker_v4, &source_blocker_v6);

        let send_thread_num = Self::parse_send_thread_num(args.send_thread_num);

        let cool_seconds = Self::parse_cool_time(&args.cool_seconds);


        Self {

            // 设置源地址
            source_interface_v4: source_addrs.0,
            source_addrs_v4: source_addrs.1,
            source_interface_v6: source_addrs.2,
            source_addrs_v6: source_addrs.3,

            // 设置源端口
            source_ports: Self::parse_source_ports(&args.source_ports),

            // 设置 发送重试次数 和 发送线程
            send_attempt_num:Self::parse_send_attempt_num(args.send_attempt_num),
            send_thread_num,

            // 设置全局发送速率
            global_rate_conf: Self::parse_send_rate(args.send_rate, &args.band_width,
                                                    max_packet_length,args.batch_size,
                                                    args.must_sleep, target_num, send_thread_num, cool_seconds),
            cool_seconds,
        }


    }

}