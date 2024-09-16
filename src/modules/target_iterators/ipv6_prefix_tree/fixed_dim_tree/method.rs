use std::cell::RefCell;
use std::process::exit;
use std::rc::Rc;
use ahash::AHashMap;
use log::{error, info};
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::IPv6FixedPrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::node::IPv6FixedPrefixNode;
use crate::SYS;

impl IPv6FixedPrefixTree {
    
    /// 使用 广度优先遍历 获得起始队列
    /// 返回值: 起始前缀 | 1 生成的地址
    pub fn init_queue(&mut self) -> (Vec<u128>, AHashMap<u128, usize>) {

        // 获取根节点
        let root = match self.root.as_ref() {
            None => {
                error!("{}", SYS.get_info("err", "root_not_found"));
                exit(1)
            }
            Some(r) => r.clone()
        };

        // 将根节点置为 空
        // 目的是将 无效节点 从内存中清除出去
        self.root = None;

        // 记录 起始前缀 对应的探测地址
        let mut generated_targets = Vec::new();

        // 存储广度优先遍历的节点队列
        let mut q: Vec<Rc<RefCell<IPv6FixedPrefixNode>>> = Vec::new();
        
        // 在节点队列中加入 根节点
        q.push(root);

        // 取出 常用值
        let start_prefix_len = self.start_prefix_len;

        // 记录  地址 -> 节点编号 的映射
        let mut addr_to_code:AHashMap<u128, usize> = AHashMap::new();
        // 计数值, 与节点队列保持一致
        let mut count = 0usize;

        while let Some(node) = q.pop() {
            let mut cur_node = node.borrow_mut();

            if cur_node.children.is_empty() || cur_node.prefix_len >= start_prefix_len {
                // 如果是 叶子节点 或 大于等于最小前缀大小

                // 加入探测队列   当前前缀 | 1
                let cur_tar_addr = cur_node.mode | 1;
                // 加入目标地址队列
                generated_targets.push(cur_tar_addr);
                // 记录  地址 -> 节点编号 映射关系
                addr_to_code.insert(cur_tar_addr, count);
                
                count += 1;

                // 将 当前节点id 插入 分支列表
                let cur_node_id = cur_node.id;
                cur_node.branches.push(cur_node_id);

                // 加入 当前节点队列
                self.cur_tar_node_queue.push(node.clone());
            } else {

                // 如果是 非叶子节点 且 前缀长度小于最小前缀长度
                // 将 当前节点 的全部子节点加入队列
                for child in &cur_node.children {
                    q.push(child.clone())
                }
            }
        }

        // 警告: 生成地址的队列 应与 节点队列保持一致
        (generated_targets, addr_to_code)
    }
    
    pub fn get_layer_expand_count(&mut self){
        
        // 如果 不允许层级扩展, 直接清理内存后返回
        if !self.allow_layer_expand {
            self.layer_expand_count = self.dim_size;
            self.split_count.clear();
            self.split_count.shrink_to_fit();
            return
        }
        
        if self.layer_expand_ratio < f64::EPSILON {
            // 如果 层级扩展比例 小于等于0, 意味着 所有节点都不应该进行 层级扩展
            self.allow_layer_expand = false;
            self.layer_expand_count = self.dim_size;
        } else if self.layer_expand_ratio >= (1.0 - f64::EPSILON) {
            // 如果 层级扩展比例 大于等于1, 意味着 所有节点都应该进行 层级扩展
            self.layer_expand_count = 0;
        } else {
            // 规定 层级扩展比例
            self.split_count.sort();
            let layer_expand_index = ((1.0 - self.layer_expand_ratio) * (self.split_count.len() as f64)) as usize;
            if layer_expand_index >= self.split_count.len() {
                // 等同于不允许分裂
                self.allow_layer_expand = false;
                self.layer_expand_count = self.dim_size;
            } else {
                // 将指定比例位置上的分裂数量 设为 层级分裂依据
                self.layer_expand_count = self.split_count[layer_expand_index] as usize;
            }
        }
        
        info!("{} {}", SYS.get_info("info", "hier_extension_ind"), self.layer_expand_count);
        
        // 清理内存
        self.split_count.clear();
        self.split_count.shrink_to_fit();
    }
    
    
}