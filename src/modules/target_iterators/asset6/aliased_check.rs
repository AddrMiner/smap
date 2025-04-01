use std::net::Ipv6Addr;
use ahash::{AHashMap, AHashSet};
use rand::{rng, Rng};
use rand::rngs::ThreadRng;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::IPv6PortSpaceTree;

impl IPv6PortSpaceTree {


    /// 由 端口探测结果 生成 别名解析的探测目标
    pub fn gen_aliased_check_targets(&self, cur_records:&Vec<(u128, u16, u32)>) -> (Vec<u64>, Vec<(Vec<u8>, u16, u128)>) {
        // 注意: records 本身是无序的
        
        // 该计数用于别名解析阶段的数据包编码
        let mut aliased_check_count:u32 = 0;
        
        // 生成前缀的列表，用来将探测结果进行还原
        let mut prefixes_vec:Vec<u64> = Vec::new();
        // 生成前缀集合, 用来判断是否存在对应目标
        let mut prefixes_set:AHashSet<u64> = AHashSet::new();
        
        // 当前别名检测标志字段
        let aliased_flag = self.aliased_scan_flag;
        
        let mut targets = Vec::with_capacity(cur_records.len()); 
        let rng = &mut rng();
        for (addr, port, _) in cur_records {
            
            let cur_prefix_val = addr >> 64;
            let cur_prefix_u64 = cur_prefix_val as u64;
            
            if !prefixes_set.contains(&cur_prefix_u64) {
                // 当前前缀没有被包含在已知前缀中
                
                // 生成对应编码
                let mut code = aliased_check_count.to_be_bytes();
                // 将 大端编码的第一个字节附加标志
                code[0] = aliased_flag;
                
                Self::gen_targets(cur_prefix_val << 64, *port, code.into(), rng, &mut targets);
               
                prefixes_vec.push(cur_prefix_u64);
                prefixes_set.insert(cur_prefix_u64);
                aliased_check_count += 1;
            }
        }

        (prefixes_vec, targets)
    }
    
    
    /// 过滤, 将记录输出到文件, 传递区域编码记录信息 
    pub fn clear_and_print_records(aliased_prefixes:&AHashSet<u64>, open_addrs_ports:&mut AHashMap<u128, u16>, max_port_num:u16, records:Vec<(u128, u16, u32)>, output:&mut Box<dyn OutputMethod>, region_len:usize) -> (Vec<u64>, u64) {
        // 生成 区域编码记录器
        let mut region_recorder:Vec<u64> = vec![0u64; region_len];
        region_recorder.shrink_to_fit();
        
        let mut act_count = 0;
        for (cur_addr, cur_port, cur_code) in records {
            // 当前地址对应的/64前缀
            let cur_prefix_64 = (cur_addr >> 64) as u64;
            if !aliased_prefixes.contains(&cur_prefix_64) {
                // 如果 没有被别名前缀包含, 才能被算为正常目标

                if let Some(ports_num) = open_addrs_ports.get_mut(&cur_addr) {
                    // 如果之前已经统计过该地址， 并知道其 开放端口数量

                    if *ports_num >= max_port_num {
                        // 如果 已知开放端口的数量 大于等于 最大开放端口数量
                        continue
                    } else { 
                        *ports_num += 1;
                    }
                } else { 
                    open_addrs_ports.insert(cur_addr, 1);
                }

                output.writer_line(&vec![Ipv6Addr::from(cur_addr).to_string(), cur_port.to_string()]);
                region_recorder[cur_code as usize] += 1;
                
                act_count += 1;
            }
        }
        output.close_output();
        (region_recorder, act_count)
    }

    pub fn print_records(records:Vec<(u128, u16, u32)>, open_addrs_ports:&mut AHashMap<u128, u16>, max_port_num:u16, output:&mut Box<dyn OutputMethod>, region_len:usize) -> (Vec<u64>, u64) {
        // 生成 区域编码记录器
        let mut region_recorder:Vec<u64> = vec![0u64; region_len];
        region_recorder.shrink_to_fit();

        let mut act_count = 0;
        for (cur_addr, cur_port, cur_code) in records {

            if let Some(ports_num) = open_addrs_ports.get_mut(&cur_addr) {
                // 如果之前已经统计过该地址， 并知道其 开放端口数量

                if *ports_num >= max_port_num {
                    // 如果 已知开放端口的数量 大于等于 最大开放端口数量
                    continue
                } else {
                    *ports_num += 1;
                }
            } else {
                open_addrs_ports.insert(cur_addr, 1);
            }
            
            output.writer_line(&vec![Ipv6Addr::from(cur_addr).to_string(), cur_port.to_string()]);
            region_recorder[cur_code as usize] += 1;

            act_count += 1;
        }
        
        output.close_output();
        (region_recorder, act_count)
    }
    
    
    /// 解析探测结果, 输入为 编码计数, 返回 别名前缀集合
    pub fn parse_aliased_result(&self, last_stat:Vec<u64>, prefixes:Vec<u64>) -> AHashSet<u64> {
        let mut aliased_prefixes = AHashSet::<u64>::new();
        
        // 取出别名阈限
        // 如果一个前缀下的随机目标大于等于该阈限, 将被判断为别名前缀
        let aliased_threshold = self.aliased_threshold;
        for (cur_prefix, cur_prefix_active) in prefixes.into_iter().zip(last_stat.into_iter()) {
            
            if cur_prefix_active >= aliased_threshold {
                // 当前前缀下的活跃数量  >= 阈限
                aliased_prefixes.insert(cur_prefix);
            }
        }
        
        aliased_prefixes
    }
    
    
    
    
    
    /// 在 已知/64前缀, 前缀对应编码, 对应端口 下生成随机目标
    fn gen_targets(prefix_64:u128, port:u16, code:Vec<u8>, rng:&mut ThreadRng, targets:&mut Vec<(Vec<u8>, u16, u128)>){
        let rand_max = u128::MAX >> 64;

        for _ in 0..16 {
            let rand_num:u128 = rng.random_range(0..=rand_max);
            let tar_ip = prefix_64 | rand_num;
            
            targets.push((code.clone(), port, tar_ip));
        }
    }



    

}