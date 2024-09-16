use ahash::AHashMap;
use num_traits::FromPrimitive;
use rand::prelude::SliceRandom;
use rust_decimal::Decimal;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::tools::others::sort::quick_sort_from_big_to_small;

impl IPv6PrefixTree {


    pub fn update_tree(&mut self, feedback_info:&Vec<(u64, u64)>) -> bool {

        // 根据该轮次的反馈信息, 更新id对应的q_value
        let id_q_value = &mut self.id_q_value;
        {
            // id -> (总的新发现链路数量, 总的消耗的探测负载数量)
            let mut id_reward_used: AHashMap<u64, (u64, u64)> = AHashMap::with_capacity(feedback_info.len());

            // 遍历 反馈信息, 获得当前轮次下 各个id下的 (总的新发现链路数量, 总的消耗的探测负载数量)
            for (reward_budget, node) in feedback_info.iter().zip(self.cur_tar_node_queue.iter()) {

                // 取出 当前反馈信息 对应的 节点
                let cur_node = node.borrow();

                // 记录 各个id 下的  (总的新发现链路数量, 总的消耗的探测负载数量)
                IPv6PrefixTree::update_id_reward(&mut id_reward_used, &cur_node.branches, *reward_budget);
            }

            // 取出常量
            let learning_rate = self.learning_rate;
            let one_sub_learning_rate = Decimal::from(1) - learning_rate;

            // 根据 总记录 对 各个id下的 q_value进行更新
            for (id, (total_reward, total_used)) in id_reward_used.into_iter() {

                // 节点优势水平    ln(total_reward + 1) / ln(total_used + 1)   =  log_{total_used + 1}(total_reward + 1)
                let node_level = ((total_reward + 1) as f64).log((total_used + 1) as f64);
                let node_level = Decimal::from_f64(node_level).unwrap();

                if let Some(zero_child_id) = self.cur_parent_id_to_zero_child_id.get(&id) {
                    // 如果存在 该父节点对应的 子零节点, 就将该父节点id对应的节点优势水平赋给 子零节点id
                    id_q_value.insert(*zero_child_id, node_level);
                }

                // 更新 id 的 q_value
                if let Some(q) = id_q_value.get_mut(&id) {
                    *q = *q * one_sub_learning_rate + learning_rate * node_level;
                } else {
                    id_q_value.insert(id, node_level);
                }
            }
        }

        {   // 将本轮次探测的节点列表加入总探测列表
            self.node_queue.extend(self.cur_tar_node_queue.iter().cloned());
            // 清空本轮次探测列表
            self.cur_tar_node_queue.clear();
            self.cur_tar_node_queue.shrink_to_fit();
            // 清除 子零节点映射关系
            self.cur_parent_id_to_zero_child_id.clear();
            self.cur_parent_id_to_zero_child_id.shrink_to_fit();
        }

        // 取出常量
        let max_prefix_len = self.max_prefix_len;
        let allow_leaf_expand = self.allow_leaf_expand;

        // 根据 id的q_value 更新 当前节点队列中的奖励值大小
        let node_queue_len = self.node_queue.len();
        let mut new_node_queue = Vec::with_capacity(node_queue_len);
        let mut all_reward = Vec::with_capacity(node_queue_len);

        if let Some(t) = self.threshold {
            for node in self.node_queue.iter() {

                // 取出当前节点
                let cur_node = node.borrow();
                let cur_q_value = cur_node.get_q_value(id_q_value);

                // 只有大于阀限的节点才被接受
                if cur_q_value <= t { 
                    id_q_value.remove(&cur_node.id);
                    continue 
                }

                // 如果非叶子节点
                if !cur_node.children.is_empty() {
                    new_node_queue.push(node.clone());
                    // 向奖励值队列中 添加 当前节点的奖励值
                    all_reward.push(cur_q_value);
                } else if allow_leaf_expand && cur_node.prefix_len < max_prefix_len {
                    new_node_queue.push(node.clone());
                    // 向奖励值队列中 添加 当前节点的奖励值
                    all_reward.push(cur_q_value);
                }
            }
            id_q_value.shrink_to_fit();
        } else {
            for node in self.node_queue.iter() {

                // 取出当前节点
                let cur_node = node.borrow();

                // 如果非叶子节点
                if !cur_node.children.is_empty() {
                    new_node_queue.push(node.clone());
                    // 向奖励值队列中 添加 当前节点的奖励值
                    all_reward.push(cur_node.get_q_value(id_q_value));
                } else if allow_leaf_expand && cur_node.prefix_len < max_prefix_len {
                    new_node_queue.push(node.clone());
                    // 向奖励值队列中 添加 当前节点的奖励值
                    all_reward.push(cur_node.get_q_value(id_q_value));
                }
            }
        }

        // 清理原先的节点队列
        self.node_queue.clear();
        self.node_queue.shrink_to_fit();

        // 根据 奖励值队列 对 节点队列进行排序
        let node_queue_len = new_node_queue.len();
        if node_queue_len == 0 { return true }

        if self.rand_ord {
            // 随机化排序, 用于测试
            let mut rng = rand::thread_rng();
            new_node_queue.shuffle(&mut rng);
        } else {
            quick_sort_from_big_to_small(&mut all_reward, &mut new_node_queue, 0, node_queue_len - 1);
        }

        self.node_queue = new_node_queue;
        false
    }
}