use std::cell::RefCell;
use std::cmp::min;
use std::rc::Rc;
use ahash::AHashSet;
use rand::seq::SliceRandom;
use crate::modules::target_iterators::ipv6_space_tree::IPv6SpaceTreeNode;
use crate::modules::target_iterators::ipv6_space_tree::space_tree::IPv6SpaceTree;
use crate::tools::others::sort::quick_sort_from_big_to_small;

impl IPv6SpaceTree {
    
    pub fn gen_addrs(&mut self, cur_budget:u64) -> Vec<(u16, u128)> {
        let node_queue_len =  self.all_reward.len();
        // 区域抽取数量 和 叶子节点数量 中的最小值
        let cur_extra_region_num = min(self.region_extraction_num as usize, node_queue_len);
        self.cur_extra_region_num = cur_extra_region_num;

        // 目标队列
        let mut targets:Vec<(u16, u128)> = Vec::with_capacity(cur_budget as usize);

        // 计算 前max_node_num个 奖励的总和
        let sum_reward:f64 = self.all_reward.iter().take(cur_extra_region_num).sum();
        for i in 0..cur_extra_region_num {

            let mut node = (&self.region_queue[i]).borrow_mut();

            // 获得生成的 地址集合
            let cur_ips_set:AHashSet<u128>;
            {
                // 计算当前节点的预算值
                let region_budget = ((self.all_reward[i] / sum_reward) * (cur_budget as f64)) as usize;

                // 在当前节点生成 目标地址集合
                let region_gen_addrs = node.gen_addrs(region_budget, &self);

                // 当前目标集合 = 生成的目标集合 - 已使用的总集合
                cur_ips_set = region_gen_addrs.difference(&self.used_addrs).cloned().collect();
            }
            
            // 注意: cur_extra_region_num 不能超过 u16::MAX

            // 将 (区域编码, 本区域地址) 写入目标队列
            for &ip in &cur_ips_set {
                targets.push((i as u16, ip));
            }

            // 向 已使用的地址 集合中添加 当前集合
            self.used_addrs.extend(cur_ips_set);
        }

        // 随机化目标队列
        {
            let mut rng = rand::thread_rng();
            targets.shuffle(&mut rng);
        }

        targets
    }

    pub fn update_tree(&mut self, last_act:Vec<u64>){

        // 区域抽取数量
        let tar_region_num = self.cur_extra_region_num;

        // 取出常用变量
        let learning_rate = self.learning_rate;
        let one_sub_learning_rate = 1.0 - self.learning_rate;

        for i in 0..tar_region_num {

            // 该区域在上次探测中活跃的数量
            let new_act_num = last_act[i];

            // 当前节点
            let mut cur_node = self.region_queue[i].borrow_mut();

            // 更新 q值       q = (1-a) * q + a * [ 上次扫描活跃数量 / 当前搜索维度 ]
            cur_node.q_value = one_sub_learning_rate * cur_node.q_value + learning_rate * ( (new_act_num as f64) / (cur_node.searched_dim as f64));
            self.all_reward[i] = cur_node.q_value;

            if cur_node.no_used_generated_address.is_empty() && cur_node.split_stack.is_empty() {
                // 如果 该节点的  未使用地址 和 待分裂维度 都为 空
                // 该节点将被裁撤

                let parent = cur_node.parent.clone().unwrap();
                let mut parent_node = parent.borrow_mut();

                {// 将 该节点持有的信息转交父节点
                    // 将 子节点 的 已探测地址 合并进 父节点
                    parent_node.used_addrs.extend(&cur_node.used_addrs);

                    // 将 子节点奖励值 合并进 父节点
                    parent_node.q_value += cur_node.q_value * (cur_node.searched_dim as f64) / (parent_node.searched_dim as f64);

                    {// 将 子节点中存在 而 父节点中不存在的模式 插入父节点的模式
                        let mut new_modes: Vec<u128> = Vec::new();
                        for &mode in &cur_node.modes {
                            if !parent_node.modes.contains(&mode) {
                                new_modes.push(mode);
                            }
                        }
                        parent_node.modes.extend(new_modes);
                    }

                    // 如果父节点的地址生成元为空
                    if parent_node.gen_move_len.is_empty() {
                        parent_node.gen_move_len = cur_node.gen_move_len.clone();
                    }
                }

                {   // 从空间树中删除该叶子节点
                    let cur_node_id = cur_node.id;
                    drop(cur_node);
                    parent_node.childs.retain(|x|{
                       x.borrow().id != cur_node_id
                    });

                    // 判断 父节点是否存在其它孩子
                    // 如果它没有其他孩子了, 说明已经是叶子节点, 将被加入队列
                    if parent_node.childs.is_empty() {
                        parent_node.space_size = self.dim_size.pow(parent_node.searched_dim as u32) * parent_node.modes.len();
                        self.region_queue.push(parent.clone());
                        self.all_reward.push(parent_node.q_value);
                    }
                }
            }
        }

        {// 删除 已被用完的叶子区域
            let high_regions: Vec<Rc<RefCell<IPv6SpaceTreeNode>>> = self.region_queue.drain(..tar_region_num).collect();
            let high_rewards: Vec<f64> = self.all_reward.drain(..tar_region_num).collect();

            let mut new_high_regions = Vec::with_capacity(tar_region_num);
            let mut new_high_rewards = Vec::with_capacity(tar_region_num);

            for (index, region) in high_regions.into_iter().enumerate() {
                let node = region.borrow();

                if !node.no_used_generated_address.is_empty() || !node.split_stack.is_empty() {
                    new_high_regions.push(region.clone());
                    new_high_rewards.push(high_rewards[index]);
                }
            }
            drop(high_rewards);

            self.region_queue.extend(new_high_regions);
            self.all_reward.extend(new_high_rewards);
        }

        // 将 奖励队列 和 叶子节点队列 按照 奖励队列 从大到小 排序
        let node_queue_len =  self.all_reward.len();
        quick_sort_from_big_to_small(&mut self.all_reward, &mut self.region_queue, 0, node_queue_len-1);
    }

   

}