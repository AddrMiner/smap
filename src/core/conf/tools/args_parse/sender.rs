use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;
use std::thread::available_parallelism;
use chrono::{DateTime, Local, TimeZone, Utc};
use log::{error, warn};
use crate::core::conf::set_conf::sender_conf::{RateGlobalConf, SenderBaseConf};
use crate::core::conf::tools::args_parse::ip::mix::parse_mix_ip_range_ipaddr;
use crate::core::conf::tools::args_parse::port::parse_ports_vec;
use crate::core::conf::tools::net::interface::InterfaceConf;
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;


impl SenderBaseConf {

    /// 解析 重试次数
    pub fn parse_send_attempt_num(att: Option<i32>) -> i32 {
        if let Some(a) = att {
            a
        } else {
            let a: i32 = SYS.get_conf("conf", "default_send_attempt_num");
            a
        }
    }

    /// 解析源地址
    pub fn parse_source_addrs(source_addr: &Option<String>, interfaces: &Vec<InterfaceConf>,
                              have_v4:bool, have_v6:bool,
                              blocker_v4:&BlackWhiteListV4, blocker_v6:&BlackWhiteListV6 )
                              -> (Vec<String>, Vec<Vec<Ipv4Addr>>, Vec<String>, Vec<Vec<Ipv6Addr>>) {

        // v4源接口 及其 对应源地址
        let mut send_source_interface_v4 = vec![];
        let mut send_source_addrs_v4 = vec![];

        // v6源接口 及其 对应源地址
        let mut send_source_interface_v6 = vec![];
        let mut send_source_addrs_v6 = vec![];


        if let Some(saddr) = source_addr {

            // 解析输入的源地址
            let (vec_v4, vec_v6) = parse_mix_ip_range_ipaddr(saddr);

            // 遍历所有网络接口
            for interface in interfaces {
                let mut tar_v4 = vec![];
                let mut tar_v6 = vec![];

                let i_v4 = &interface.local_ipv4;
                let i_v6 = &interface.local_ipv6;

                for arg_v4 in &vec_v4 {
                    if i_v4.contains(arg_v4) {
                        // 如果当前接口存在 目标源地址
                        if blocker_v4.ip_is_avail(u32::from(*arg_v4)) {
                            // 如果该地址不受 源地址拦截器阻止
                            tar_v4.push(*arg_v4);
                        } else {
                            warn!("{} {}", SYS.get_info("warn", "ignored_source_ip"), arg_v4);
                        }
                    }
                }

                for arg_v6 in &vec_v6 {
                    if i_v6.contains(arg_v6) {
                        // 如果当前接口存在 目标源地址
                        if blocker_v6.ip_is_avail(u128::from(*arg_v6)) {
                            // 如果该地址不受 源地址拦截器阻止
                            tar_v6.push(*arg_v6);
                        } else {
                            warn!("{} {}", SYS.get_info("warn", "ignored_source_ip"), arg_v6);
                        }
                    }
                }

                if tar_v4.len() != 0 {
                    send_source_interface_v4.push(interface.name_index.0.clone());
                    send_source_addrs_v4.push(tar_v4);
                }

                if tar_v6.len() != 0 {
                    send_source_interface_v6.push(interface.name_index.0.clone());
                    send_source_addrs_v6.push(tar_v6);
                }
            }
        } else {
            // 如果未指定源地址, 将使用所有 有效接口 和 其对应的所有源地址

            // 遍历所有网络接口
            for interface in interfaces {

                let mut tar_v4 = vec![];
                let mut tar_v6 = vec![];

                for ip_v4 in interface.local_ipv4.iter() {
                    if blocker_v4.ip_is_avail(u32::from(*ip_v4)) {
                        // 如果 当前目标不受 源地址拦截器 阻止
                        tar_v4.push(*ip_v4);
                    } else {
                        warn!("{} {}", SYS.get_info("warn", "ignored_source_ip"), ip_v4);
                    }
                }

                for ip_v6 in interface.local_ipv6.iter() {
                    if blocker_v6.ip_is_avail(u128::from(*ip_v6)) {
                        // 如果 当前目标不受 源地址拦截器 阻止
                        tar_v6.push(*ip_v6);
                    } else {
                        warn!("{} {}", SYS.get_info("warn", "ignored_source_ip"), ip_v6);
                    }
                }

                if tar_v4.len() != 0 {
                    send_source_interface_v4.push(interface.name_index.0.clone());
                    send_source_addrs_v4.push(tar_v4);
                }

                if tar_v6.len() != 0 {
                    send_source_interface_v6.push(interface.name_index.0.clone());
                    send_source_addrs_v6.push(tar_v6);
                }
            }
        }

        if have_v4 && send_source_addrs_v4.len() == 0 {
            // 如果  目标范围包括 ipv4,  且不存在有效ipv4源地址
            error!("{}", SYS.get_info("err", "source_ips_not_exist_v4"));
            exit(1)
        }

        if have_v6 && send_source_addrs_v6.len() == 0 {
            // 如果  目标范围包括 ipv6,  且不存在有效ipv6源地址
            error!("{}", SYS.get_info("err", "source_ips_not_exist_v6"));
            exit(1)
        }

        (send_source_interface_v4, send_source_addrs_v4, send_source_interface_v6, send_source_addrs_v6)
    }

    /// 解析 源端口
    pub fn parse_source_ports(source_ports: &Option<String>) -> Vec<u16> {
        if let Some(sports) = source_ports {
            parse_ports_vec(sports)
        } else {
            // 如果未指定源端口, 读取默认配置
            let sports_str = SYS.get_info("conf", "default_source_ports");
            parse_ports_vec(&sports_str)
        }
    }


    /// 配置 发送线程数量
    /// 手动设置为 0 时会报错。
    /// 如果不设置, 会根据系统线程数量设置发送线程数量
    /// 如果系统线程为 1，则直接设为 1
    /// 如果系统线程为 其他值, 则为系统线程数量 减1
    pub fn parse_send_thread_num(thread_num: Option<usize>) -> usize {
        if let Some(n) = thread_num {
            if n == 0 {
                error!("{}", SYS.get_info("err","send_thread_num_not_zero"));
                exit(1)
            }
            n
        } else {
            match available_parallelism() {
                Ok(n) => {
                    let sys_thread_num: usize = n.into();

                    if sys_thread_num == 1 {
                        1
                    } else {
                        sys_thread_num - 1
                    }
                },

                Err(_) => {
                    error!("{}", SYS.get_info("err","get_thread_num_failed"));
                    exit(1)
                }
            }
        }
    }

    /// 解析<u>ipv4探测模块名称</u>
    pub fn parse_probe_v4(probe_name: &Option<String>, default_probe_mod:&str) -> String {
        if let Some(p) = probe_name {
            p.to_string()
        } else {
            SYS.get_conf("conf", default_probe_mod)
        }
    }

    /// 解析<u>ipv6探测模块名称</u>
    pub fn parse_probe_v6(probe_name: &Option<String>, default_probe_mod:&str) -> String {
        if let Some(p) = probe_name {
            p.to_string()
        } else {
            SYS.get_conf("conf", default_probe_mod)
        }
    }


    /// 计算发送速率
    pub fn parse_send_rate(rate:Option<u64>,                // 最大包长度 由探测模块提供
                           band_width_arg:&Option<String>, max_packet_length:usize,
                           batch_size_arg:Option<u64>,
                           must_sleep_arg:Option<u64>,
                           target_num:Option<u64>, thread_num:usize, cool_time:i64)
    -> RateGlobalConf {

    let batch_size = batch_size_arg.unwrap_or_else(|| SYS.get_conf("conf", "default_batch_size"));

    // 设置每发送轮次的最短延迟时间, 以 微秒 计
    let must_sleep = must_sleep_arg.unwrap_or_else(|| SYS.get_conf("conf", "default_must_sleep"));

    match rate {
        Some(r) => {
            match band_width_arg {
                Some(_) => {
                    // rate 和 bandwidth 只能二选一
                    error!("{}", SYS.get_info("err", "rate_bandwidth_both_exist"));
                    exit(1)
                }
                None => {
                    // 按照 rate 进行发送
                    if r == 0 {
                        error!("{}", SYS.get_info("err", "rate_invalid"));
                        exit(1)
                    }

                    if let Some(tar_num) = target_num {
                        // 如果已知目标数量, 就可以估计需要运行的时间, 以及结束的时间

                        // 发送 需要运行的秒数
                        let seconds_need = tar_num / r;

                        let now_time = Utc::now().timestamp();
                        let end_time = now_time + (seconds_need as i64) + cool_time;

                        let end_time = DateTime::from_timestamp(end_time, 0).unwrap().naive_local();
                        let end_time: DateTime<Local> =  Local.from_utc_datetime(&end_time);

                        println!("{} {}", SYS.get_info("print", "forecast_completion_time"),
                                 end_time.format(&SYS.get_info("print", "forecast_completion_time_pattern")));
                    }

                    RateGlobalConf {
                        tar_rate: {
                            (r as f64) / (thread_num as f64)
                        },

                        // 运行时间 = (总数量 / 线程数量) / 发送速率
                        // 由于强制了发送速率, 所以此项无效, 为-1
                        running_time: -1.0,
                        must_sleep,
                        batch_size,
                    }
                }
            }
        }
        None => {
            // 未指定 rate
            match band_width_arg {
                Some(b) => {
                    // 指定了带宽( 每秒多少比特 位 )
                    let band_width = Self::parse_band_width(&b);

                    let mut pkt_len = (max_packet_length * 8) + (8 * 24);

                    // 如果小于以太网帧的最小尺寸，则调整计算长度
                    if pkt_len < 672 {
                        // 84 * 8
                        pkt_len = 672;
                    }

                    // 每秒多少位 / 每帧的位长度 = 每秒多少帧
                    let new_rate = (band_width as f64) / (pkt_len as f64);

                    if let Some(tar_num) = target_num {
                        // 如果已知目标数量, 就可以估计需要运行的时间, 以及结束的时间

                        // 发送 需要运行的秒数
                        let seconds_need = tar_num / (new_rate as u64);

                        let now_time = Utc::now().timestamp();
                        let end_time = now_time + (seconds_need as i64) + cool_time;

                        let end_time = DateTime::from_timestamp(end_time, 0).unwrap().naive_local();
                        let end_time: DateTime<Local> =  Local.from_utc_datetime(&end_time);

                        println!("{} {}", SYS.get_info("print", "forecast_completion_time"),
                                 end_time.format(&SYS.get_info("print", "forecast_completion_time_pattern")));
                    }

                    RateGlobalConf {
                        tar_rate: new_rate / (thread_num as f64),
                        // 由于强制了发送速率, 预期运行时间无效
                        running_time: -1.0,
                        must_sleep,
                        batch_size,
                    }
                }

                // 既没指定 rate, 也没指定 带宽
                None => {
                    match target_num {
                        Some(tar_num) => {
                            // 请求 用户 输入 运行时间 或 截止时间
                            println!("{}", SYS.get_info("print", "input_end_time"));

                            // 2023-10-26 21:15:00+08:00   注意时区
                            let mut input_end_time = String::new();
                            std::io::stdin().read_line(&mut input_end_time).map_err(
                                |_| {
                                    error!("{}", SYS.get_info("err","input_end_time_err"));
                                    exit(1)
                                }
                            ).unwrap();

                            // 目标时间 和 当前时间, 秒时间戳
                            let tar_time = input_end_time.parse::<DateTime<Utc>>()
                                .map_err(|_| {
                                    error!("{}", SYS.get_info("err", "parse_end_time_err"));
                                    exit(1)
                                }).unwrap().timestamp();
                            let now_time = Utc::now().timestamp();

                            // 计算 需要多少秒完成发送
                            let tar_running_time = tar_time - now_time - cool_time;

                            if tar_running_time <= 0 {
                                // 如果运行时间非法
                                error!("{}", SYS.get_info("err", "send_time_invalid"));
                                exit(1)
                            }
                            // 计算 每秒 需要发送多少帧
                            RateGlobalConf {
                                // 注意: 这里为全局参考速率, 具体的速率应由具体的线程根据目标数量独立计算
                                tar_rate: ((tar_num as f64) / (tar_running_time as f64)) / (thread_num as f64),

                                // 线程发送速率 = 各线程分配的探测目标总量 / 探测时间
                                running_time: tar_running_time as f64,
                                must_sleep,
                                batch_size,
                            }
                        }
                        None => {
                            // 既没指定速率, 也没指定带宽, 也无法获得探测目标总量

                            // 提示警告, 目标速率将被设为无限大 (仍处于管制状态, 速率控制器将消耗极少性能资源(可能几个微秒))
                            warn!("{}", SYS.get_info("warn","max_rate"));

                            RateGlobalConf {
                                tar_rate: f64::MAX,

                                running_time: -1.0,
                                must_sleep,
                                batch_size,
                            }
                        }
                    }
                }
            }
        }
    }
    }


    /// 解析带宽字符串
    pub fn parse_band_width(band_str:&str) -> u64 {

        let band_str = band_str.trim();  // 清除首尾空格
        let band_l = band_str.len();    // 获取字符串长度

        let val:u64 = (&band_str[..band_l-1]).parse().map_err(
            // 获取前半部分
            |_|{  // 定义错误捕获封包
                error!("{} {}", SYS.get_info("err", "parse_band_width_err"), band_str);
                exit(1)
            }).unwrap();

        let last:char = (&band_str[band_l-1..]).parse().map_err(  // 截取最后字符
             |_|{  // 定义错误捕获封包
                 error!("{} {}", SYS.get_info("err", "parse_band_width_err"), band_str);
                 exit(1)
             }
        ).unwrap();

        match last {

            'G' | 'g' => val * 1_000_000_000,

            'M' | 'm' => val * 1_000_000,

            'K' | 'k' => val * 1_000,


            _ => {
                error!("{} {}", SYS.get_info("err", "parse_band_width_err"), band_str);
                exit(1)
            }

        }

    }


    /// 解析冷却时间
    pub fn parse_cool_time(cool_time:&Option<i64>) -> i64 {

        if let Some(c) = cool_time {
            *c
        } else {
            SYS.get_conf("conf", "default_cool_time")
        }
    }

    pub fn get_tar_num_with_option(tar_ip_num:Option<u64>, tar_ports_num:usize) -> Option<u64> {
        match tar_ip_num {
            None => None,
            Some(t) => {
                // 如果设定了多个端口, 就将目标数量设为 端口对数量 乘以 设定端口数量
                // 警告: 如果指定端口, 文件中的端口会被替换为设定端口
                // 同时也意味着, 如果存在重复ip, 同一个ip在同一个端口上发送多次

                let tar_num:u128 = (t as u128) * (tar_ports_num as u128);

                if tar_num > (u64::MAX as u128) {
                    // 超出范围限制
                    error!("{}", SYS.get_info("err", "tar_num_over_range"));
                    exit(1)
                }

                Some(tar_num as u64)
            }
        }
    }

    pub fn get_tar_num(tar_ip_num:u64, tar_repeat_num:usize) -> Option<u64> {

        let tar_num:u128 = (tar_ip_num as u128) * (tar_repeat_num as u128);

        if tar_num > (u64::MAX as u128) {
            // 超出范围限制
            error!("{}", SYS.get_info("err", "tar_num_over_range"));
            exit(1)
        }

        Some(tar_num as u64)
    }

    pub fn get_tar_num_without_option(tar_ip_num:u64, tar_ports_num:usize) -> u64 {

        let tar_num:u128 = (tar_ip_num as u128) * (tar_ports_num as u128);

        if tar_num > (u64::MAX as u128) {
            // 超出范围限制
            error!("{}", SYS.get_info("err", "tar_num_over_range"));
            exit(1)
        }

        tar_num as u64
    }

}