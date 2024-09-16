use std::cell::RefCell;
use std::cmp::min;
use std::rc::Rc;
use ahash::AHashMap;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::node::IPv6PrefixNode;

impl IPv6PrefixTree {
    
    pub fn gen_targets(&mut self) -> (Vec<u128>, AHashMap<u128, usize>) {
        // 计算当前应该分裂的节点个数
        let extra_node_num = min(self.extra_node_num, self.node_queue.len());
        // 从 node_queue 的头部切割出 指定数量的节点队列
        let nodes_to_be_split: Vec<Rc<RefCell<IPv6PrefixNode>>> = self.node_queue.drain(..extra_node_num).collect();

        // 生成的本轮次的探测目标
        let mut generated_targets = Vec::with_capacity(extra_node_num);
        // 分裂出的新节点
        let mut cur_tar_nodes = Vec::with_capacity(extra_node_num);
        // 记录  地址 -> 节点编号 的映射
        let mut addr_to_code:AHashMap<u128, usize> = AHashMap::with_capacity(extra_node_num);

        let default_dim_size = self.default_dim_size;
        let child_max_size = self.child_max_size;
        let max_len_sub_dim = self.max_prefix_len - self.default_dim;
        let allow_leaf_expand = self.allow_leaf_expand;
        let default_dim = self.default_dim;
        let max_prefix_len = self.max_prefix_len;
        let mut rng = rand::thread_rng();
        
        let mut count = 0usize;
        for node in nodes_to_be_split.into_iter() {
            let mut cur_node = node.borrow_mut();

            if cur_node.children.is_empty() {
                // 如果是叶子节点
                if allow_leaf_expand {
                    if cur_node.prefix_len <= max_len_sub_dim {
                        cur_tar_nodes.extend(
                          self.expand_leaf(&cur_node, default_dim_size, default_dim,
                                           &mut count, &mut addr_to_code, &mut generated_targets)  
                        );
                    } else if cur_node.prefix_len < max_prefix_len {
                        let cur_dim = max_prefix_len - cur_node.prefix_len;
                        let cur_dim_size = 1 << cur_dim;
                        cur_tar_nodes.extend(
                            self.expand_leaf(&cur_node, cur_dim_size, cur_dim, 
                                             &mut count, &mut addr_to_code, &mut generated_targets)
                        );
                    }
                }
                continue
            }
            
            // 获得当前轮次的 子节点, 用以生成目标
            let cur_children = if cur_node.incomplete {
                // 如果 该节点 是 之前未完成的节点
                cur_node.get_targets(child_max_size)
            } else { 
                // 进行广度优先遍历, 获得 孩子节点队列(实质)
                let parent_branches = cur_node.branches.clone();
                cur_node.get_children(parent_branches, child_max_size, &mut rng)
            };
            
            for cur_child in cur_children.into_iter() {
                let cur_child_node = cur_child.borrow();
                
                if cur_child_node.zero {
                    // 如果为 零节点, 本轮次不作为探测目标

                    // 直接将分裂得到的节点移动到总节点队列
                    self.node_queue.push(cur_child.clone());

                    // 记录 父节点 -> 子零节点 的映射
                    self.cur_parent_id_to_zero_child_id.insert(cur_node.id, cur_child_node.id);
                    
                } else { 
                    // 非零节点
                    
                    // 加入探测队列  当前前缀 | 1
                    let cur_tar_addr = cur_child_node.mode | 1;

                    // 加入目标地址队列
                    generated_targets.push(cur_tar_addr);
                    // 记录  地址 -> 节点编号 映射关系
                    addr_to_code.insert(cur_tar_addr, count);
                    count += 1;

                    // 将 分裂出的新节点加入 当前探测列表
                    cur_tar_nodes.push(cur_child.clone());
                }
            }

            // 如果 当前节点为 未完成节点, 需要被加入 总队列, 等待下次分裂
            if cur_node.incomplete { self.node_queue.push(node.clone()) }
        }

        // 记录 当前目标节点队列
        self.cur_tar_node_queue = cur_tar_nodes;
        // 警告: 生成地址的队列 应与 节点队列保持一致
        (generated_targets, addr_to_code)
    }
    
    
    
    
    
    
    
}