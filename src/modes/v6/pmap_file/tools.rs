use std::net::Ipv6Addr;
use std::process::exit;
use std::sync::Arc;
use ahash::AHashMap;
use log::error;
use crate::modes::v6::pmap_file::PmapFileV6;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::{PmapFileIterV6, PmapGraph, PmapState};
use crate::{init_var, SYS};
use crate::tools::check_duplicates::{ExtractActPortsV6, NotMarkedV6Port};
use crate::tools::others::split::split_chains;

impl PmapFileV6 {


    /// 根据 预扫描抽样比例 和 最小抽样数量 计算 预扫描需要扫描的目标地址数量
    pub(crate) fn get_sample_num(tar_ip_num:usize, sampling_pro:f64, min_sample_num:usize) -> usize {

        // 采样比例 小于等于 0  或  大于 1 均为非法
        if sampling_pro <= 0.0 ||  1.0 < sampling_pro {
            error!("{}", SYS.get_info("err", "sampling_pro_invalid"));
            exit(1)
        }

        if sampling_pro > 0.99 {
            // 当 采样比例 大于 0.99 时, 直接 取消端口推荐, 对 所有端口对 进行探测
            tar_ip_num
        } else {

            if tar_ip_num <= min_sample_num {
                // 如果 总目标数量  小于等于 最小采样数量
                // 对 所有端口对 进行探测
                tar_ip_num
            } else {

                // 计算   最小采样数量 在 探测目标总量 中的 相对比例, 作为最小采样比例
                // 相对比例 =  最小采样数量 / 探测目标总量
                let min_pro = (min_sample_num as f64) / (tar_ip_num as f64);

                // 取 设定的抽样比例 和 最小采样比例 中的最大值, 作为 最终采样比例
                let final_pro = if min_pro > sampling_pro { min_pro } else { sampling_pro };

                // 预扫描抽样数量:   对[最终采样比例 * 目标地址数量]进行向下取整
                let sampling_num = (final_pro * (tar_ip_num as f64)).floor() as usize;

                if sampling_num < 1 { 1 } else { sampling_num }
            }
        }

    }


    pub fn full_scan_output<B:ExtractActPortsV6>(pre_scan_ips:Vec<u128>, res:B,
                                                 out_mod:&mut Box<dyn OutputMethod>) 
        -> (usize, usize) {

        // 存在活跃端口的ip计数
        let mut ip_count:usize = 0;
        // 活跃端口对计数
        let mut pair_count = 0;

        for cur_ip in pre_scan_ips.into_iter() {
            let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip);

            if ports.len() != 0 {
                
                ip_count += 1;
                pair_count += ports.len();
                
                let out_line = vec![Ipv6Addr::from(cur_ip).to_string(), ports_str];
                out_mod.writer_line(&out_line);
            }
        }

        // 关闭输出
        out_mod.close_output();

        (ip_count, pair_count)
    }


    pub fn full_scan_output_and_train<B:ExtractActPortsV6>(pre_scan_ips:Vec<u128>, res:B,
                                                           out_mod:&mut Box<dyn OutputMethod>, 
                                                           graph:&mut PmapGraph)
        -> (usize, usize) {

        // 存在活跃端口的ip计数
        let mut ip_count:usize = 0;
        // 活跃端口对计数
        let mut pair_count = 0;
        
        for cur_ip in pre_scan_ips.into_iter() {
            let (ports, ports_str) = res.get_active_ports_u16_string(cur_ip);

            if ports.len() != 0 {
                ip_count += 1;
                pair_count += ports.len();

                graph.update_from_ip(&ports);
                let out_line = vec![Ipv6Addr::from(cur_ip).to_string(), ports_str];
                out_mod.writer_line(&out_line);
            }
        }

        // 关闭输出
        out_mod.close_output();

        // 生成 绝对概率表
        graph.update_end();

        (ip_count, pair_count)
    }

    pub fn create_pmap6_iter_queue(targets: Vec<u128>, thread_num: usize) -> Vec<PmapFileIterV6> {

        // 创建 pmap_v6 迭代器队列
        let mut pmap_iter_queue = Vec::new();

        // 获取 多线程任务分配列表
        let recommend_scan_tar_ranges = split_chains(targets, thread_num);

        for cur_ips in recommend_scan_tar_ranges {
            if !cur_ips.is_empty() {
                pmap_iter_queue.push(PmapFileIterV6::new(cur_ips));
            }
        }
        pmap_iter_queue
    }


    pub fn pmap_receive<B:NotMarkedV6Port>(res:B, graph:&PmapGraph, states_map:&mut AHashMap<Vec<u16>, Arc<PmapState>>,
                                       pmap_iter_queue:&mut Vec<PmapFileIterV6>){

        for pmap_iter in pmap_iter_queue.iter_mut() {

            let ips_iter = pmap_iter.tar_ips.iter();
            let ip_structs_iter = pmap_iter.ips_struct.iter_mut();

            for (cur_ip, cur_ip_struct) in ips_iter.zip(ip_structs_iter) {
                let cur_sent_port = cur_ip_struct.cur_sent_port;
                cur_ip_struct.receive(res.is_not_marked(*cur_ip, cur_sent_port), graph, states_map);
            }
        }
    }


    pub fn recommend_scan_output_train(g_ptr:&mut PmapGraph, pmap_iter_queue:Vec<PmapFileIterV6>, out_mod:&mut Box<dyn OutputMethod>) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let ips_iter = pmap_iter.tar_ips.into_iter();
            let ip_structs_iter = pmap_iter.ips_struct.into_iter();

            for (cur_ip, ip_struct) in ips_iter.zip(ip_structs_iter){
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

                    let out_line = vec![Ipv6Addr::from(cur_ip).to_string(), port_str];
                    out_mod.writer_line(&out_line);
                }
            }
        }

        // 关闭输出
        out_mod.close_output();
        // 生成 绝对概率表
        g_ptr.update_end();

        (ip_count, pair_count)
    }


    pub fn recommend_scan_output(pmap_iter_queue:Vec<PmapFileIterV6>, out_mod:&mut Box<dyn OutputMethod>) -> (usize, usize){

        init_var!(usize; 0; ip_count, pair_count);
        for pmap_iter in pmap_iter_queue.into_iter() {

            let ips_iter = pmap_iter.tar_ips.into_iter();
            let ip_structs_iter = pmap_iter.ips_struct.into_iter();

            for (cur_ip, ip_struct) in ips_iter.zip(ip_structs_iter){
                if ip_struct.open_ports.len() != 0 {
                    // 只有开放端口数量不为0的才有输出, 才参与概率相关图训练

                    ip_count += 1;
                    pair_count += ip_struct.open_ports.len();

                    // 生成 端口字符串
                    let mut port_str = String::new();
                    for port in ip_struct.open_ports.into_iter() { port_str.push_str(&format!("{}|", port)); }
                    port_str.pop();

                    let out_line = vec![Ipv6Addr::from(cur_ip).to_string(), port_str];
                    out_mod.writer_line(&out_line);
                }
            }
        }

        // 关闭输出
        out_mod.close_output();

        (ip_count, pair_count)
    }

}