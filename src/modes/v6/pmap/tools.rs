use std::net::Ipv6Addr;
use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modes::v6::pmap::PmapV6;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::{CycleIpv6Pattern, Ipv6Iter, PmapGraph, PmapIterV6, PmapState};
use crate::{init_var, SYS};
use crate::tools::blocker::ipv6_blocker::BlackWhiteListV6;
use crate::tools::check_duplicates::{ExtractActPortsV6, NotMarkedV6Port};

impl PmapV6 {


    pub fn get_sample_last_index(tar_ip_num:u64, p_sub_one:u128, sampling_pro:f64, min_sample_num:u64) -> u128 {

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
                let last_index = (final_pro * (p_sub_one as f64)).floor() as u128;

                if last_index < 1 { 1 } else { last_index }
            }
        }
    }

    pub fn full_scan_output<T: Ipv6Iter, B:ExtractActPortsV6>(mut iter:T, res:&B, blocker:&BlackWhiteListV6,
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

                        let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(),  ports];
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

                        let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(),  ports];
                        out_mod.writer_line(&out_line);
                    }
                }

                // 关闭输出
                out_mod.close_output();

                return (ip_count, pair_count)
            }
        }
    }


    pub fn full_scan_output_and_train<T: Ipv6Iter, B:ExtractActPortsV6>(mut iter:T, res:&B, blocker:&BlackWhiteListV6,
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
                        let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), ports_str];
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
                        let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), ports_str];
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


    pub fn create_pmap6_iter_queue(pre_last: u128, end_index: u128, thread_num: u128, guide_iter:&CycleIpv6Pattern) -> Vec<PmapIterV6> {

        // 创建 pmap_v6 迭代器队列
        let mut pmap_iter_queue = Vec::new();

        // 获取 多线程任务分配列表
        let recommend_scan_tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u128_part(pre_last, end_index, thread_num);

        for target_range in recommend_scan_tar_ranges {

            // 初始化 局部引导迭代器
            let local_guide_iter = guide_iter.init(target_range.0, target_range.1);
            pmap_iter_queue.push(PmapIterV6::new(target_range.2 as usize, local_guide_iter));
        }
        pmap_iter_queue
    }


    pub fn pmap_receive<B:NotMarkedV6Port>(res:&B, graph:&PmapGraph, states_map:&mut AHashMap<Vec<u16>, Arc<PmapState>>,
                                       pmap_iter_queue:&mut Vec<PmapIterV6>, blocker:&BlackWhiteListV6){

        for pmap_iter in pmap_iter_queue.iter_mut() {

            let guide_iter = &mut pmap_iter.ipv6_guide_iter;
            let ips_struct = &mut pmap_iter.ips_struct;

            // 当前有效ip 对应的索引
            let mut cur_index = 0;
            let mut cur_ip = guide_iter.get_first_ip();

            'cur_iter:loop {
                if cur_ip.0 {
                    // 如果不是最终值
                    if blocker.ip_is_avail(cur_ip.2) {
                        // 如果没被黑名单阻止

                        let cur_struct_ptr = &mut ips_struct[cur_index];
                        let cur_sent_port = cur_struct_ptr.cur_sent_port;

                        cur_struct_ptr.receive(res.is_not_marked(cur_ip.2, cur_sent_port), graph, states_map);
                        cur_index += 1;
                    }

                    cur_ip = guide_iter.get_next_ip();
                } else {
                    // 如果是最终值

                    if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                        // 最终值有效  且  当前 ip 被放行

                        let cur_struct_ptr = &mut ips_struct[cur_index];
                        let cur_sent_port = cur_struct_ptr.cur_sent_port;

                        cur_struct_ptr.receive(res.is_not_marked(cur_ip.2, cur_sent_port), graph, states_map);
                    }
                    break 'cur_iter
                }
            }

            // 重置当前迭代器中的 引导迭代器
            pmap_iter.reset_guide_iter();
        }
    }

    pub fn recommend_scan_output_train(g_ptr:&mut PmapGraph, pmap_iter_queue:Vec<PmapIterV6>, out_mod:&mut Box<dyn OutputMethod>, blocker:&BlackWhiteListV6) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let mut guide_iter = pmap_iter.ipv6_guide_iter;
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

                                    let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), port_str];
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

                                    let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), port_str];
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


    pub fn recommend_scan_output(pmap_iter_queue:Vec<PmapIterV6>, out_mod:&mut Box<dyn OutputMethod>, blocker:&BlackWhiteListV6) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let mut guide_iter = pmap_iter.ipv6_guide_iter;
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

                                    let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), port_str];
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

                                    let out_line = vec![Ipv6Addr::from(cur_ip.2).to_string(), port_str];
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