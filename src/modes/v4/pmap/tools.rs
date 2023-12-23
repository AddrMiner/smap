use std::net::Ipv4Addr;
use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
use crate::core::conf::tools::args_parse::target_iterator::TarIterBaseConf;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::{CycleIpv4, Ipv4Iter, PmapGraph, PmapIterV4, PmapState};
use crate::SYS;
use crate::tools::blocker::ipv4_blocker::BlackWhiteListV4;
use crate::tools::check_duplicates::bit_map_v4::BitMapV4;
use crate::tools::check_duplicates::bit_map_v4_port::BitMapV4Port;


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

pub fn full_scan_output_v4<T: Ipv4Iter + Clone>(mut iter:T, res:&BitMapV4Port, sorted_tar_ports:&Vec<u16>, blocker:&BlackWhiteListV4,
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

                let (ports, ports_len) = res.get_active_ports_string(cur_ip.2, &sorted_tar_ports);
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

                let (ports, ports_len) = res.get_active_ports_string(cur_ip.2, &sorted_tar_ports);
                if ports_len != 0 {

                    ip_count += 1;
                    pair_count += ports_len;

                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(),  ports];
                    out_mod.writer_line(&out_line);
                }
            }
            return (ip_count, pair_count)
        }
    }
}


pub fn full_scan_output_and_train_v4<T: Ipv4Iter + Clone>(mut iter:T, res:&BitMapV4Port, sorted_tar_ports:&Vec<u16>, blocker:&BlackWhiteListV4,
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

                let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip.2, &sorted_tar_ports);

                if ports.len() != 0 {
                    ip_count += 1;
                    pair_count += ports.len();

                    graph.update_from_ip(ports);
                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), ports_str];
                    out_mod.writer_line(&out_line);
                }
            }

            cur_ip = iter.get_next_ip();
        } else {
            // 如果是最终值

            if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                // 最终值有效  且  当前 ip 被放行

                let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip.2, &sorted_tar_ports);

                if ports.len() != 0 {
                    ip_count += 1;
                    pair_count += ports.len();

                    graph.update_from_ip(ports);
                    let out_line = vec![Ipv4Addr::from(cur_ip.2).to_string(), ports_str];
                    out_mod.writer_line(&out_line);
                }
            }
            return (ip_count, pair_count)
        }
    }
}


pub fn create_pmap4_iter_queue(pre_last: u64, end_index: u64, thread_num: u64, guide_iter:&CycleIpv4) -> Vec<PmapIterV4> {

    // 创建 pmap_v4 迭代器队列
    let mut pmap_iter_queue = Vec::new();

    // 获取 完全扫描的多线程任务分配列表
    let recommend_scan_tar_ranges = TarIterBaseConf::cycle_group_assign_targets_u64_part(pre_last, end_index, thread_num);

    for target_range in recommend_scan_tar_ranges {

        // 初始化 局部引导迭代器
        let local_guide_iter = guide_iter.init(target_range.0, target_range.1);
        pmap_iter_queue.push(PmapIterV4::new(target_range.2 as usize, local_guide_iter));
    }
    pmap_iter_queue
}


pub fn pmap_receive(res:BitMapV4, graph:&PmapGraph, states_map:&mut AHashMap<String, Arc<PmapState>>,
                    pmap_iter_queue:&mut Vec<PmapIterV4>, blocker:&BlackWhiteListV4){

    for pmap_iter in pmap_iter_queue.iter_mut() {

        let guide_iter = &mut pmap_iter.ipv4_guide_iter;
        let ip_map = &mut pmap_iter.ip_map;

        let cur_start_ip = guide_iter.start_ip;

        let mut cur_ip = guide_iter.get_first_ip();
        'cur_iter:loop {
            if cur_ip.0 {
                // 如果不是最终值
                if blocker.ip_is_avail(cur_ip.2) {
                    // 如果没被黑名单阻止

                    // 根据 在位图中是否被标记, 对状态库进行更新
                    let cur_ip_index = (cur_ip.2 - cur_start_ip) as usize;
                    ip_map[cur_ip_index].receive(res.is_not_marked(cur_ip.2), graph, states_map);
                }

                cur_ip = guide_iter.get_next_ip();
            } else {
                // 如果是最终值

                if cur_ip.1 && blocker.ip_is_avail(cur_ip.2) {
                    // 最终值有效  且  当前 ip 被放行

                    // 根据 在位图中是否被标记, 对状态库进行更新
                    let cur_ip_index = (cur_ip.2 - cur_start_ip) as usize;
                    ip_map[cur_ip_index].receive(res.is_not_marked(cur_ip.2), graph, states_map);
                    
                }
                break 'cur_iter
            }
        }

        // 重置当前迭代器中的 引导迭代器
        pmap_iter.reset_guide_iter();
    }
}
