use std::cell::RefCell;
use std::rc::Rc;
use ahash::AHashMap;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::IPv6FixedPrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::node::IPv6FixedPrefixNode;

impl IPv6FixedPrefixTree {
    
    /// 扩展当前节点下的孩子节点
    /// 注意: 层级扩展 产生 虚拟节点
    pub fn expand_layer(&mut self, parent:&IPv6FixedPrefixNode, count:&mut usize, addr_to_seq:&mut AHashMap<u128,usize>,
                        generated_targets:&mut Vec<u128>, cur_tar_nodes:&mut Vec<Rc<RefCell<IPv6FixedPrefixNode>>>, zero_child_no_exist:bool) {

        // 取出常量
        let dim_size = self.dim_size as u128;
        
        // 创建与父节点同级的虚拟父节点
        let virtual_node_id = self.id_num;
        {
            // 计算   父节点当前的q_value
            let parent_q_value = parent.get_q_value(&self.id_q_value);
            // 将 父节点当前的q_value 赋值给 虚拟节点
            self.id_q_value.insert(virtual_node_id, parent_q_value);
            
            self.id_num += 1;
        }

        // 取出父节点第一个孩子的 模式, 前缀长度
        let first_child = parent.children[0].borrow();
        // 注意: 扩展节点的前缀长度 应与 原本的孩子的前缀长度 保持一致
        let cur_prefix_len = first_child.prefix_len;
        // 计算左移距离
        let left_move_len = 128 - cur_prefix_len;

        let parent_mode = first_child.mode & (!(self.split_mask_u128 << left_move_len));
        
        for i in 1..dim_size {

            // 生成 扩展模式 和 探测目标
            let expand_mode = (i << left_move_len) | parent_mode;
            let cur_tar_addr = expand_mode | 1;

            // 如果生成的目标已经存在, 说明存在该节点
            if addr_to_seq.contains_key(&cur_tar_addr) { continue }

            // 生成新节点
            let cur_id = self.id_num;
            let mut new_child_node = IPv6FixedPrefixNode::new(cur_id, expand_mode, cur_prefix_len, false);
            // 警告: 层级扩展的节点只对 与父节点同级的虚拟节点 和 自身造成影响
            new_child_node.branches = vec![virtual_node_id, cur_id];
            self.id_num += 1;

            // 加入目标地址队列
            generated_targets.push(cur_tar_addr);
            // 记录  地址 -> 节点编号 映射关系
            addr_to_seq.insert(cur_tar_addr, *count);
            *count += 1;

            // 将 分裂出的新节点加入 当前探测列表
            cur_tar_nodes.push(Rc::new(RefCell::new(new_child_node)));
        }
        
        if zero_child_no_exist {
            // 如果 该父节点不存在零孩子节点

            // 创建 子零节点
            let cur_id = self.id_num;
            let mut zero_child = IPv6FixedPrefixNode::new(cur_id, parent_mode, cur_prefix_len, true);
            // 警告: 层级扩展的节点只对 与父节点同级的虚拟节点 和 自身造成影响
            zero_child.branches = vec![virtual_node_id, cur_id];
            self.id_num += 1;

            if parent.children.len() == (self.dim_size - 1) {
                // 如果 父节点的孩子数量正好等于 全数量-1 并且 不存在零孩子节点
                // 说明 该父节点只扩展出了 零孩子节点
                
                // 建立 父节点id -> 子零节点 的映射关系
                self.cur_parent_id_to_zero_child_id.insert(parent.id, zero_child.id);
            } else {
                // 建立 虚拟父节点id -> 子零节点 的映射关系
                self.cur_parent_id_to_zero_child_id.insert(virtual_node_id, zero_child.id);
            }
            
            // 将生成的零孩子节点加入总节点队列
            self.node_queue.push(Rc::new(RefCell::new(zero_child)));
        } 
    }
    
    


    /// 扩展当前叶子节点, 生成 当前节点的子节点
    /// 警告: 扩展的节点包括 添加了长度和分支id的父节点 和 其它探测节点, 添加了长度的父节点不应产生探测目标, 且应被加入 非当前探测队列中
    pub fn expand_leaf(&mut self, parent:&IPv6FixedPrefixNode, count:&mut usize, addr_to_seq:&mut AHashMap<u128,usize>,
                      generated_targets:&mut Vec<u128>) 
        -> Vec<Rc<RefCell<IPv6FixedPrefixNode>>> {

        // 取出常量
        let dim_size = self.dim_size;
        let parent_mode = parent.mode;
        let parent_id = parent.id;

        // 父节点id 对应的q_value(*1) 设为 父节点对应的q_value
        {
            // 计算   父节点当前的q_value
            let parent_q_value = parent.get_q_value(&self.id_q_value);
            // 将计算得到的 q_value 直接赋给 id 的q_value
            *self.id_q_value.get_mut(&parent_id).unwrap() = parent_q_value;
        }

        // 当前节点前缀长度
        let cur_prefix_len = parent.prefix_len + self.dim;
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
            let mut child_node = IPv6FixedPrefixNode::new(cur_id, expand_mode, cur_prefix_len, false);
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
        let mut zero_child = IPv6FixedPrefixNode::new(cur_id, parent_mode, cur_prefix_len, true);
        zero_child.branches = vec![parent_id, cur_id];
        self.id_num += 1;
        
        // 建立 父节点id -> 子零节点 的映射关系
        self.cur_parent_id_to_zero_child_id.insert(parent_id, zero_child.id);
        // 将 子零节点 加入总列表
        self.node_queue.push(Rc::new(RefCell::new(zero_child)));

        child_nodes
    }
}