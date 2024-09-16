use ahash::AHashMap;
use rand::prelude::SliceRandom;
use crate::modules::output_modules::OutputMethod;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoMethodV6;
use crate::modules::target_iterators::Ipv6VecDoubleTree;


impl Ipv6VecDoubleTree {
    
    /// 第一次生成地址
    pub fn first_get_targets(&self) -> Vec<(u128, u8, u8)> {

        let mut targets:Vec<(u128, u8, u8)> = Vec::with_capacity(self.addrs.len());

        // 取出常量
        let initial_ttl = self.initial_ttl;
        
        // code = [ 阶段编码(6比特, 0-63) | 标识编码(2比特, 0-3) ]
        let code = (self.phase << 2) | 3;

        for &addr in &self.addrs {
            targets.push((addr, initial_ttl, code));
        }

        // 随机化目标队列
        {
            let mut rng = rand::thread_rng();
            targets.shuffle(&mut rng);
        }
        
        targets
    }


    /// 生成 下一轮次的探测目标 并 打印当前轮次中的沉默目标
    pub fn gen_scan_targets_and_print_silent(&mut self, probe:&Box<dyn TopoMethodV6>, output:&mut Box<dyn OutputMethod>) -> Vec<(u128, u8, u8)> {
        
        // 上一阶段停止, 开始下一个阶段
        self.phase += 1;
        // code = [ 阶段编码(6比特, 0-63) | 标识编码(2比特, 0-3) ]
        let left_code = self.phase << 2;
        
        
        // 统计使用计数
        let mut index_gen_count = AHashMap::new();
        // 新生成的目标
        let mut targets:Vec<(u128, u8, u8)> = Vec::with_capacity(self.addrs.len());

        let gap_limit = self.gap_limit;
        for (index, ((back_ttl, forward_ttl), (back_silent, forward_silent)))
                                                        in self.states.iter_mut().zip(self.cur_no_recv.iter_mut()).enumerate() {

            if *back_ttl != 0 {
                // 如果该地址的后向探测未停止
                if *back_silent {
                    // 如果 当前轮次 未收到响应

                    // 输出 当前沉默目标
                    output.writer_line(&probe.print_silent_record(self.addrs[index], *back_ttl));

                    // 当前ttl-1
                    *back_ttl -= 1;

                    if *back_ttl != 0 {
                        // 对于未结束的后向探测, 生成下一次探测的目标
                        targets.push((self.addrs[index], *back_ttl, left_code | 2));
                        // self.reward_used[index].1 += 1;
                        if let Some(i) = index_gen_count.get_mut(&index){
                            *i += 1;
                        } else { 
                            index_gen_count.insert(index, 1);
                        }
                    }
                } else {
                    // 对于 已经响应的目标, 要重置设置, 用于下一次探测
                    *back_silent = true;
                    // 对于未结束的后向探测, 生成下一次探测的目标
                    targets.push((self.addrs[index], *back_ttl, left_code | 2));
                    // self.reward_used[index].1 += 1;
                    if let Some(i) = index_gen_count.get_mut(&index){
                        *i += 1;
                    } else {
                        index_gen_count.insert(index, 1);
                    }
                }
            }

            if *forward_ttl != 0 {
                // 如果该地址的前向探测未停止
                if *forward_silent {
                    // 如果 当前轮次 未收到响应

                    // 输出 当前沉默目标
                    output.writer_line(&probe.print_silent_record(self.addrs[index], *forward_ttl));

                    // 增加 沉默计数
                    self.silent_count[index] += 1;
                    if self.silent_count[index] >= gap_limit {
                        // 如果沉默次数过多
                        // 需要终止前向探测
                        *forward_ttl = 0;
                    } else {
                        // 继续向前探测
                        *forward_ttl += 1;

                        if *forward_ttl > self.max_ttl {
                            // 如果下一个目标ttl超过最大ttl, 终止该目标的探测
                            *forward_ttl = 0;
                        } else {
                            // 对于未结束的前向探测, 生成下一次探测的目标
                            targets.push((self.addrs[index], *forward_ttl, left_code | 1));
                            // self.reward_used[index].1 += 1;
                            if let Some(i) = index_gen_count.get_mut(&index){
                                *i += 1;
                            } else {
                                index_gen_count.insert(index, 1);
                            }
                        }
                    }
                } else {
                    // 重置沉默计数
                    self.silent_count[index] = 0;
                    // 对于 已经响应的目标, 要重置设置, 用于下一次探测
                    *forward_silent = true;
                    // 对于未结束的后向探测, 生成下一次探测的目标
                    targets.push((self.addrs[index], *forward_ttl, left_code | 1));
                    // self.reward_used[index].1 += 1;
                    if let Some(i) = index_gen_count.get_mut(&index){
                        *i += 1;
                    } else {
                        index_gen_count.insert(index, 1);
                    }
                }
            }
        }
        
        if targets.len() < self.min_target_num {
            return Vec::new()
        }
        
        // 加入使用计数
        for (index, count) in index_gen_count.into_iter() {
            self.reward_used[index].1 += count;
        }

        // 随机化目标队列
        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);
        
        targets
    }
    
}