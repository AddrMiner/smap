use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v4::PmapV4;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::{CycleIpv4, Ipv4Iter, PmapGraph, PmapIterV4, PmapState};
use crate::{init_var, SYS};
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::check_duplicates::{ExtractActPortsV4, NotMarkedV4};


impl PmapV4 {

    pub fn get_sample_last_index(args:&ModuleConf, tar_ip_num:u64, p_sub_one:u64, pro:&str, min_num:&str) -> u64 {

        // 从 自定义参数 或 系统配置 中提取 抽样比例
        let sampling_pro:f64 = args.get_conf_or_from_sys(&pro.to_string());

        // 采样比例 小于等于 0  或  大于 1 均为非法
        if sampling_pro <= 0.0 ||  1.0 < sampling_pro {
            error!("{}", SYS.get_info("err", "sampling_pro_invalid"));
            exit(1)
        }

        if sampling_pro > 0.99 {
            // 当 采样比例 大于 0.99 时, 直接 取消端口推荐, 对 所有端口对 进行探测
            // 注意这里的最终索引为:  p-1
            p_sub_one
        } else {

            // 从 自定义参数 或 系统配置 中提取 最小采样数量
            let min_sample_num = args.get_conf_or_from_sys(&min_num.to_string());

            if tar_ip_num <= min_sample_num {
                // 如果 总目标数量  小于等于 最小采样数量
                // 对 所有端口对 进行探测, 注意这里的最终索引为:  p-1
                p_sub_one
            } else {

                // 计算   最小采样数量 在 探测目标总量 中的 相对比例, 作为最小采样比例
                // 相对比例 =  最小采样数量 / 探测目标总量
                let min_pro = (min_sample_num as f64) / (tar_ip_num as f64);

                // 取 设定的抽样比例 和 最小采样比例 中的最大值, 作为 最终采样比例
                let final_pro = if min_pro > sampling_pro { min_pro } else { sampling_pro };

                // 最终索引:   对[最终采样比例 * (p-1)]进行向下取整
                let last_index = (final_pro * (p_sub_one as f64)).floor() as u64;

                if last_index < 1 { 1 } else { last_index }
            }
        }
    }

    pub fn full_scan_output<T: Ipv4Iter, B:ExtractActPortsV4>(mut iter:T, res:&B, blocker:&BlackWhiteListV4,
                                                    out_mod:&mut Box<dyn OutputMethod>) -> (usize, usize) {

        // 存在活跃端口的ip计数
        let mut ip_count:usize = 0;
        // 活跃端口对计数
        let mut pair_count = 0;

        let mut cur_ip = iter.get_first_ip();
        loop {
            if cur_ip.0 {
                // 如果不是最终值
                if blocker.ip_is_avail(cur_ip.2) {
                    // 如果没被黑名单阻止

                    let (ports, ports_len) = res.get_active_ports_string(cur_ip.2);
                    if ports_len != 0 {

                        ip_count += 1;
                        pair_count += ports_len;

                        let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(),  ports];
                        out_mod.writer_line(&out_line);
                    }
                }

                cur_ip = iter.get_next_ip();
            } else {
                // 如果是最终值

                if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                    // 最终值有效  且  当前 ip 被放行

                    let (ports, ports_len) = res.get_active_ports_string(cur_ip.2);
                    if ports_len != 0 {

                        ip_count += 1;
                        pair_count += ports_len;

                        let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(),  ports];
                        out_mod.writer_line(&out_line);
                    }
                }

                // 关闭输出
                out_mod.close_output();

                return (ip_count, pair_count)
            }
        }
    }


    pub fn full_scan_output_and_train<T: Ipv4Iter, B:ExtractActPortsV4>(mut iter:T, res:&B, blocker:&BlackWhiteListV4,
                                                              out_mod:&mut Box<dyn OutputMethod>, graph:&mut PmapGraph)  -> (usize, usize){

        // 存在活跃端口的ip计数
        let mut ip_count:usize = 0;
        // 活跃端口对计数
        let mut pair_count = 0;

        let mut cur_ip = iter.get_first_ip();
        loop {
            if cur_ip.0 {
                // 如果不是最终值
                if blocker.ip_is_avail(cur_ip.2) {
                    // 如果没被黑名单阻止

                    let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip.2);

                    if ports.len() != 0 {
                        ip_count += 1;
                        pair_count += ports.len();

                        graph.update_from_ip(&ports);
                        let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), ports_str];
                        out_mod.writer_line(&out_line);
                    }
                }

                cur_ip = iter.get_next_ip();
            } else {
                // 如果是最终值

                if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                    // 最终值有效  且  当前 ip 被放行

                    let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip.2);

                    if ports.len() != 0 {
                        ip_count += 1;
                        pair_count += ports.len();

                        graph.update_from_ip(&ports);
                        let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), ports_str];
                        out_mod.writer_line(&out_line);
                    }
                }

                // 关闭输出
                out_mod.close_output();

                // 生成 绝对概率表
                graph.update_end();

                return (ip_count, pair_count)
            }
        }
    }


    pub fn create_pmap4_iter_queue(pre_last: u64, end_index: u64, thread_num: u64, guide_iter:&CycleIpv4) -> Vec<PmapIterV4> {

        // 创建 pmap_v4 迭代器队列
        let mut pmap_iter_queue = Vec::new();

        // 获取 多线程任务分配列表
        let recommend_scan_tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u64_part(pre_last, end_index, thread_num);

        for target_range in recommend_scan_tar_ranges {

            // 初始化 局部引导迭代器
            let local_guide_iter = guide_iter.init(target_range.0, target_range.1);
            pmap_iter_queue.push(PmapIterV4::new(target_range.2 as usize, local_guide_iter));
        }
        pmap_iter_queue
    }


    pub fn pmap_receive<B:NotMarkedV4>(res:&B, graph:&PmapGraph, states_map:&mut AHashMap<String, Arc<PmapState>>,
                        pmap_iter_queue:&mut Vec<PmapIterV4>, blocker:&BlackWhiteListV4){

        for pmap_iter in pmap_iter_queue.iter_mut() {

            let guide_iter = &mut pmap_iter.ipv4_guide_iter;
            let ips_struct = &mut pmap_iter.ips_struct;

            // 当前有效ip 对应的索引
            let mut cur_index = 0;
            let mut cur_ip = guide_iter.get_first_ip();

            'cur_iter:loop {
                if cur_ip.0 {
                    // 如果不是最终值
                    if blocker.ip_is_avail(cur_ip.2) {
                        // 如果没被黑名单阻止

                        ips_struct[cur_index].receive(res.is_not_marked(cur_ip.2), graph, states_map);
                        cur_index += 1;
                    }

                    cur_ip = guide_iter.get_next_ip();
                } else {
                    // 如果是最终值

                    if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                        // 最终值有效  且  当前 ip 被放行

                        ips_struct[cur_index].receive(res.is_not_marked(cur_ip.2), graph, states_map);
                    }
                    break 'cur_iter
                }
            }

            // 重置当前迭代器中的 引导迭代器
            pmap_iter.reset_guide_iter();
        }
    }

    pub fn recommend_scan_output_train(g_ptr:&mut PmapGraph, pmap_iter_queue:Vec<PmapIterV4>, out_mod:&mut Box<dyn OutputMethod>, blocker:&BlackWhiteListV4) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let mut guide_iter = pmap_iter.ipv4_guide_iter;
            let mut ips_struct = pmap_iter.ips_struct.into_iter();

            let mut cur_ip = guide_iter.get_first_ip();

            'cur_iter:loop {
                if cur_ip.0 {
                    // 如果不是最终值
                    if blocker.ip_is_avail(cur_ip.2) {
                        // 如果没被黑名单阻止

                        match ips_struct.next() {
                            Some(ip_struct) => {

                                if ip_struct.open_ports.len() != 0 {
                                    // 只有开放端口数量不为0的才有输出, 才参与概率相关图训练

                                    ip_count += 1;
                                    pair_count += ip_struct.open_ports.len();

                                    // 使用当前ip的活跃端口列表对概率相关图进行更新
                                    g_ptr.update_from_ip(&ip_struct.open_ports);

                                    // 生成 端口字符串
                                    let mut port_str = String::new();
                                    for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                                    port_str.pop();

                                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), port_str];
                                    out_mod.writer_line(&out_line);
                                }
                            }

                            // 注意: ip_struct 和 有效ip的索引永远保持一致
                            // 如果出现无法获取到 ip_struct 的情况, 说明出现错误
                            None => { error!("{}", SYS.get_info("err", "get_ip_struct_failed")); exit(1) }
                        }
                    }

                    cur_ip = guide_iter.get_next_ip();
                } else {
                    // 如果是最终值

                    if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                        // 最终值有效  且  当前 ip 被放行

                        match ips_struct.next() {
                            Some(ip_struct) => {

                                if ip_struct.open_ports.len() != 0 {
                                    // 只有开放端口数量不为0的才有输出, 才参与概率相关图训练

                                    ip_count += 1;
                                    pair_count += ip_struct.open_ports.len();

                                    // 使用当前ip的活跃端口列表对概率相关图进行更新
                                    g_ptr.update_from_ip(&ip_struct.open_ports);

                                    // 生成 端口字符串
                                    let mut port_str = String::new();
                                    for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                                    port_str.pop();

                                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), port_str];
                                    out_mod.writer_line(&out_line);
                                }
                            }

                            // 注意: ip_struct 和 有效ip的索引永远保持一致
                            // 如果出现无法获取到 ip_struct 的情况, 说明出现错误
                            None => { error!("{}", SYS.get_info("err", "get_ip_struct_failed")); exit(1) }
                        }
                    }
                    break 'cur_iter
                }
            }
        }

        // 关闭输出
        out_mod.close_output();
        // 生成 绝对概率表
        g_ptr.update_end();

        (ip_count, pair_count)
    }


    pub fn recommend_scan_output(pmap_iter_queue:Vec<PmapIterV4>, out_mod:&mut Box<dyn OutputMethod>, blocker:&BlackWhiteListV4) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let mut guide_iter = pmap_iter.ipv4_guide_iter;
            let mut ips_struct = pmap_iter.ips_struct.into_iter();

            let mut cur_ip = guide_iter.get_first_ip();

            'cur_iter:loop {
                if cur_ip.0 {
                    // 如果不是最终值
                    if blocker.ip_is_avail(cur_ip.2) {
                        // 如果没被黑名单阻止

                        match ips_struct.next() {
                            Some(ip_struct) => {

                                if ip_struct.open_ports.len() != 0 {
                                    // 只有开放端口数量不为0的才有输出, 才参与概率相关图训练

                                    ip_count += 1;
                                    pair_count += ip_struct.open_ports.len();

                                    // 生成 端口字符串
                                    let mut port_str = String::new();
                                    for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                                    port_str.pop();

                                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), port_str];
                                    out_mod.writer_line(&out_line);
                                }
                            }

                            // 注意: ip_struct 和 有效ip的索引永远保持一致
                            // 如果出现无法获取到 ip_struct 的情况, 说明出现错误
                            None => { error!("{}", SYS.get_info("err", "get_ip_struct_failed")); exit(1) }
                        }
                    }

                    cur_ip = guide_iter.get_next_ip();
                } else {
                    // 如果是最终值

                    if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                        // 最终值有效  且  当前 ip 被放行

                        match ips_struct.next() {
                            Some(ip_struct) => {

                                if ip_struct.open_ports.len() != 0 {
                                    // 只有开放端口数量不为0的才有输出, 才参与概率相关图训练

                                    ip_count += 1;
                                    pair_count += ip_struct.open_ports.len();

                                    // 生成 端口字符串
                                    let mut port_str = String::new();
                                    for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                                    port_str.pop();

                                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), port_str];
                                    out_mod.writer_line(&out_line);
                                }
                            }

                            // 注意: ip_struct 和 有效ip的索引永远保持一致
                            // 如果出现无法获取到 ip_struct 的情况, 说明出现错误
                            None => { error!("{}", SYS.get_info("err", "get_ip_struct_failed")); exit(1) }
                        }
                    }
                    break 'cur_iter
                }
            }
        }
        // 关闭输出
        out_mod.close_output();
        (ip_count, pair_count)
    }

}






