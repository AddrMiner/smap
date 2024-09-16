use std::cell::RefCell;
use std::cmp::min;
use std::rc::Rc;
use ahash::AHashMap;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::IPv6FixedPrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::node::IPv6FixedPrefixNode;

impl IPv6FixedPrefixTree {

    /// 生成探测目标
    pub fn gen_targets(&mut self) -> (Vec<u128>, AHashMap<u128, usize>) {

        // 计算当前应该分裂的节点个数
        let extra_node_num = min(self.extra_node_num, self.node_queue.len());
        // 从 node_queue 的头部切割出 指定数量的节点队列
        let nodes_to_be_split: Vec<Rc<RefCell<IPv6FixedPrefixNode>>> = self.node_queue.drain(..extra_node_num).collect();

        // 生成的本轮次的探测目标
        let mut generated_targets = Vec::with_capacity(extra_node_num);
        // 分裂出的新节点
        let mut cur_tar_nodes = Vec::with_capacity(extra_node_num);
        // 记录  地址 -> 节点编号 的映射
        let mut addr_to_code:AHashMap<u128, usize> = AHashMap::with_capacity(extra_node_num);
        
        // 取出常量
        let allow_leaf_expand = self.allow_leaf_expand;
        let allow_layer_expand = self.allow_layer_expand;
        let layer_expand_threshold = self.layer_expand_count;
        let dim_size = self.dim_size;

        let mut count = 0usize;
        for node in nodes_to_be_split.into_iter() {
            let cur_node = node.borrow();

            if cur_node.children.is_empty() {
                // 如果当前节点为叶子节点, 说明无可分裂
                
                if allow_leaf_expand {
                    // 注意: 未达到指定前缀的节点探索性分裂
                    let child_nodes = self.expand_leaf(
                        &cur_node, &mut count, &mut addr_to_code, &mut generated_targets);
                    // 将 扩展出的节点 加入当前 节点列表
                    cur_tar_nodes.extend(child_nodes);
                }
                continue
            }
            
            // 在孩子节点中是否存在 子零节点
            let mut zero_child_no_exist = true;

            // 将 该节点 分裂为 它的孩子节点
            for new_node in &cur_node.children {
                let mut cur_new_node = new_node.borrow_mut();

                // 将 父节点的分支列表 和 本节点的id 加入 本节点的分支列表
                let cur_new_node_id = cur_new_node.id;
                cur_new_node.branches.extend(&cur_node.branches);
                cur_new_node.branches.push(cur_new_node_id);
                
                if cur_new_node.zero {
                    // 如果为 零节点, 本轮次不作为探测目标
                    // 注意: 零节点直接被用于生成探测目标时需为(最大前缀的)叶子节点
                    zero_child_no_exist = false;
                    
                    // 直接将分裂得到的节点移动到总节点队列
                    self.node_queue.push(new_node.clone());
                    // 记录 父节点 -> 子零节点 的映射
                    self.cur_parent_id_to_zero_child_id.insert(cur_node.id, cur_new_node_id);
                } else {
                    // 非零节点
                    
                    // 加入探测队列   当前前缀 | 1
                    let cur_tar_addr = cur_new_node.mode | 1;
                    // 加入目标地址队列
                    generated_targets.push(cur_tar_addr);
                    // 记录  地址 -> 节点编号 映射关系
                    addr_to_code.insert(cur_tar_addr, count);
                    count += 1;

                    // 将 分裂出的新节点加入 当前探测列表
                    cur_tar_nodes.push(new_node.clone());
                }
            }
            
            // 如果允许对空间树的同级节点进行扩展
            if allow_layer_expand {
                // 当 当前分裂节点孩子数量 > 层级分裂限制 并且 < 孩子节点允许存在的最大数量(非完全节点)
                if cur_node.children.len() > layer_expand_threshold && cur_node.children.len() < dim_size {
                    // 扩展父节点孩子层级
                    self.expand_layer(&cur_node, &mut count, &mut addr_to_code, &mut generated_targets, &mut cur_tar_nodes, zero_child_no_exist);
                }
            }
        }

        // 记录 当前目标节点队列
        self.cur_tar_node_queue = cur_tar_nodes;
        
        // 警告: 生成地址的队列 应与 节点队列保持一致
        (generated_targets, addr_to_code)
    }
}