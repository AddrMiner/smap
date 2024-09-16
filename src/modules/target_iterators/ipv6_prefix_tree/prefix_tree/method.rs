use std::cell::RefCell;
use std::process::exit;
use std::rc::Rc;
use ahash::AHashMap;
use log::error;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::node::IPv6PrefixNode;
use crate::SYS;

impl IPv6PrefixTree {

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
        let mut q: Vec<Rc<RefCell<IPv6PrefixNode>>> = Vec::new();

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

            if cur_node.children.is_empty() || (cur_node.real && (cur_node.prefix_len >= start_prefix_len)) {
                // 如果是 叶子节点 或 大于等于最小前缀大小(必须为实节点)

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


    /// 以 一个目标地址为单位, 对 该地址对应节点在树中的所有相关位的信息进行更新(分支节点)
    #[inline]
    pub fn update_id_reward(id_reward_used:&mut AHashMap<u64, (u64, u64)>, branches:&Vec<u64>, cur_reward_used:(u64,u64)){

        for branch in branches {

            if let Some((reward, used)) = id_reward_used.get_mut(branch) {
                // 如果 存在目标id

                // 将 当前节点的信息 添加到所有分支节点
                *reward += cur_reward_used.0;
                *used += cur_reward_used.1;
            } else {
                // 如果 不存在 目标id
                id_reward_used.insert(*branch, cur_reward_used);
            }
        }
    }
    
    
}