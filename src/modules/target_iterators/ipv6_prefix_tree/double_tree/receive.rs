use ahash::AHashSet;
use crate::modules::probe_modules::topology_probe::topo_mod_v6::TopoResultV6;
use crate::modules::target_iterators::Ipv6VecDoubleTree;


impl Ipv6VecDoubleTree {
    pub fn receive(&mut self, res:&TopoResultV6, all_nodes:&mut AHashSet<u128>) -> bool {
        
        let code = res.code;
        
        // 当前阶段
        let cur_phase = code >> 2;

        // 如果不是当前阶段的响应(如上一个阶段的响应, 网络延迟过高引起)
        if cur_phase != self.phase { return false }
        
        // 当前标识
        let cur_sign = code & 0b11;
        match cur_sign {
            // 如果 该数据包为 前向探测 的数据包
            1 => {
                // 取得 目标地址 的索引
                let tar_index = match self.addr_to_seq.get(&res.dest_ip) {
                    Some(s) => *s,
                    None => return false
                };
                if self.cur_no_recv[tar_index].1 {
                    // 如果 当前未接收 (用于查重)
                    
                    let have_exist = all_nodes.contains(&res.responder);
                    if !have_exist {
                        // 如果 当前目标不存在
                        // 记录当前响应者
                        all_nodes.insert(res.responder);
                        // 响应计数加一
                        self.reward_used[tar_index].0 += 1;
                    }
                    
                    if res.from_destination || have_exist {
                        // 如果 前向探测 探测到目标 (端口不可达, 主机不可达), 前向探测应终止
                        // 或
                        // 如果 当前响应目标是否已经存在, 前向探测应终止
                        self.states[tar_index].1 = 0;
                    } else {
                        // 如果 前向探测 收到响应, 且 未到达目标
                        
                        // 将 前向状态 设定为 下一个ttl(当前ttl+1)
                        self.states[tar_index].1 += 1;
                        if self.states[tar_index].1 > self.max_ttl {
                            // 如果下一个目标ttl超过最大ttl, 终止该目标的探测
                            self.states[tar_index].1 = 0;
                        }
                    }

                    // 设置 状态 为 已收到响应
                    self.cur_no_recv[tar_index].1 = false;
                    
                    // 允许输出
                    return true
                }
            }
            // 如果 该数据包为 后向探测 的数据包
            2 => {
                // 取得 目标地址 的索引
                let tar_index = match self.addr_to_seq.get(&res.dest_ip) {
                    Some(s) => *s,
                    None => return false
                };
                if self.cur_no_recv[tar_index].0 {
                    // 如果 当前未接收 (用于查重)
                    
                    // 判断当前响应目标是否已经存在
                    if all_nodes.contains(&res.responder) {
                        // 如果已经存在, 该目标地址的后向探测应该停止
                        self.states[tar_index].0 = 0;
                    } else { 
                        // 如果后向探测到的是从未探测过的地址
                        // 继续向后进行探测
                        self.states[tar_index].0 -= 1;
                        // 记录当前响应者
                        all_nodes.insert(res.responder);
                        // 响应计数加一
                        self.reward_used[tar_index].0 += 1;
                    }
                    
                    // 设置 状态 为 已收到响应
                    self.cur_no_recv[tar_index].0 = false;
                    
                    // 允许输出
                    return true
                }
            }
            // 如果 该数据包为 该地址首次探测的数据包
            3 => {
                // 取得 目标地址 的索引
                let tar_index = match self.addr_to_seq.get(&res.dest_ip) {
                    Some(s) => *s,
                    None => return false
                };
                
                if self.cur_no_recv[tar_index].0 && self.cur_no_recv[tar_index].1 {
                    // 注意: 所有目标的初始化状态都为true
                    
                    // 一接收响应, 立即设为已接收状态
                    self.cur_no_recv[tar_index] = (false, false);

                    // 判断当前响应目标是否已经存在
                    if all_nodes.contains(&res.responder) {
                        // 如果已经存在, 说明该目标应在前后两个方向上停止
                        self.states[tar_index] = (0, 0);
                        // 没有价值的目标
                        return false
                    } else { 
                        // 如果该节点以前并未被发现

                        // 记录当前响应者
                        all_nodes.insert(res.responder);
                        // 响应计数加一
                        self.reward_used[tar_index].0 += 1;
                        
                        if res.from_destination {
                            // 如果 前向探测 探测到目标 (端口不可达, 主机不可达), 前向探测应终止
                            self.states[tar_index].1 = 0;
                            // 如果 第一次收到来自目标的响应
                            // 后向探测应设为 距离-1
                            self.states[tar_index].0 = res.distance - 1;
                        } else { 
                            // 继续进行前向探测
                            // 将 前向状态 设定为 下一个ttl(当前ttl+1)
                            self.states[tar_index].1 += 1;
                            if self.states[tar_index].1 > self.max_ttl {
                                // 如果下一个目标ttl超过最大ttl, 终止该目标的探测
                                self.states[tar_index].1 = 0;
                            }
                            // 如果不是来自目标的响应, 在原来基础上减去1
                            self.states[tar_index].0 -= 1;
                        }
                    }
                    return true
                }
                self.cur_no_recv[tar_index] = (false, false);
            }
            _ => {}
        }
        false
    }
}
