use std::cell::RefCell;
use std::process::exit;
use std::rc::Rc;
use log::error;
use crate::modules::target_iterators::ipv6_space_tree::IPv6SpaceTreeNode;
use crate::modules::target_iterators::ipv6_space_tree::space_tree::IPv6SpaceTree;
use crate::SYS;
use crate::tools::others::sort::quick_sort_from_big_to_small;

impl IPv6SpaceTree {

    pub fn init_queue(&mut self){

        // 初始化 叶子节点队列 和 叶子节点队列对应的奖励队列
        self.init_node_queue(self.no_allow_gen_seeds);

        // 将 奖励队列 和 叶子节点队列 按照 奖励队列 从大到小 排序
        let node_queue_len =  self.all_reward.len();
        quick_sort_from_big_to_small(&mut self.all_reward, &mut self.region_queue, 0, node_queue_len-1);
    }

    pub fn init_node_queue(&mut self, no_allow_gen_seed:bool){

        // 存储广度优先遍历的节点队列
        let mut q:Vec<Rc<RefCell<IPv6SpaceTreeNode>>> = Vec::new();

        // 加入 根节点
        match self.root.as_ref() {
            None => {
                error!("{}", SYS.get_info("err", "root_not_found"));
                exit(1)
            },
            Some(r) => q.push(r.clone())
        };

        while let Some(node) = q.pop(){

            let mut cur_node = node.borrow_mut();

            if cur_node.childs.is_empty() {
                // 如果是叶子节点

                if no_allow_gen_seed {
                    // 如果不允许 生成种子地址, 将叶子节点的 种子地址 直接复制给已使用地址
                    cur_node.used_addrs = cur_node.seed_addrs_list.iter().cloned().collect();
                }
                
                // 注意: 只有叶子节点才初始化 q_value
                cur_node.q_value = (cur_node.seed_addrs_list.len() as f64) / (cur_node.split_stack.len() as f64);

                // 直接加入待探测队列
                self.region_queue.push(node.clone());
                // 记录 叶子节点 的奖励值
                self.all_reward.push(cur_node.q_value);
            } else {

                // 如果是非叶子节点
                // 将 当前节点 的全部子节点加入队列
                for child in &cur_node.childs {
                    q.push(child.clone())
                }
            }
        }
    }


    /// 获取地址结构段统计分布信息
    #[inline]
    pub fn get_stat(addrs:&Vec<u128>, move_len:&Vec<u8>, dim_size:usize, split_mask:usize) -> Vec<Vec<u64>>{
        // 定义 分布统计信息
        // 注意: 分布统计信息向量中的下标 与 move_len向量中的下标 一致
        let mut stat= vec![vec![0u64;dim_size]; move_len.len()];
        for addr in addrs.iter() {
            // 对于 整个地址聚类块 中的 每个地址

            // index表示在地址结构中的位置, 如 0 表示地址结构中的第一个分段
            // move_len表示获取分段值时的右移距离
            for (index, move_len) in move_len.iter().enumerate() {

                // 计算地址分割片段
                let split_addr_val = ((addr >> move_len) as usize) & split_mask;
                stat[index][split_addr_val] += 1;
            }
        }
        stat
    }
}