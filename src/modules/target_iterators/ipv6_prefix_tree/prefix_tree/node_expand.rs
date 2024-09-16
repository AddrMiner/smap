use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashMap;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::node::IPv6PrefixNode;

impl IPv6PrefixTree {

    pub fn expand_leaf(&mut self, parent:&IPv6PrefixNode, dim_size:usize, expand_dim:u8,
                       count:&mut usize, addr_to_seq:&mut AHashMap<u128,usize>,
                       generated_targets:&mut Vec<u128>)
                       -> Vec<Rc<RefCell<IPv6PrefixNode>>> {

        // 取出常量
        let parent_mode = parent.mode;
        let parent_id = parent.id;

        // 父节点id 对应的q_value(*1) 设为 父节点对应的q_value
        {
            // 计算   父节点当前的q_value
            let parent_q_value = parent.get_q_value(&self.id_q_value);
            // 将计算得到的 q_value 直接赋给 id 的q_value
            match self.id_q_value.get_mut(&parent_id) {
                Some(q) => *q = parent_q_value,
                None => {
                    self.id_q_value.insert(parent_id, parent_q_value);
                }
            }
        }

        // 当前节点前缀长度
        let cur_prefix_len = parent.prefix_len + expand_dim;
        // 计算左移距离
        let left_move_len = 128 - cur_prefix_len;

        let mut child_nodes = Vec::with_capacity(dim_size);

        // 计算扩展维度时所用的 左移距离
        let dim_size = dim_size as u128;
        for i in 1..dim_size {
            let expand_mode = (i << left_move_len) | parent_mode;

            // 生成新节点
            // 警告: 扩展节点不应该分享路径上的q_value, 否则可能会大幅度拉低效果
            let cur_id = self.id_num;
            let mut child_node = IPv6PrefixNode::new(cur_id, expand_mode, cur_prefix_len, false, true);
            // 注意: 分裂产生的节点只会对 父节点 和 本身 造成影响, 并且只受 父节点 和 本身 的影响
            child_node.branches = vec![parent_id, cur_id];
            self.id_num += 1;

            child_nodes.push(Rc::new(RefCell::new(child_node)));

            // 加入探测队列   当前前缀 | 1
            let cur_tar_addr = expand_mode | 1;
            // 加入目标地址队列
            generated_targets.push(cur_tar_addr);
            // 记录  地址 -> 节点编号 映射关系
            addr_to_seq.insert(cur_tar_addr, *count);

            *count += 1;
        }

        // 创建 子零节点
        let cur_id = self.id_num;
        let mut zero_child = IPv6PrefixNode::new(cur_id, parent_mode, cur_prefix_len, true, true);
        zero_child.branches = vec![parent_id, cur_id];
        self.id_num += 1;

        // 建立 父节点id -> 子零节点 的映射关系
        self.cur_parent_id_to_zero_child_id.insert(parent_id, zero_child.id);
        // 将 子零节点 加入总列表
        self.node_queue.push(Rc::new(RefCell::new(zero_child)));

        child_nodes
    }
    
    
}