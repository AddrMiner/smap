use std::process::exit;
use ahash::AHashSet;
use log::error;
use rand::prelude::IteratorRandom;
use crate::modules::target_iterators::ipv6_space_tree::IPv6SpaceTreeNode;
use crate::modules::target_iterators::IPv6SpaceTree;
use crate::SYS;

impl IPv6SpaceTreeNode {

    /// 当一个节点确定要分裂时, 获取子区域的维度, 并从父区域删除这些维度
    /// 注意: 仅供密度空间树使用
    pub fn get_child_move_len_density(&mut self) -> Vec<u8> {

        let mut child_move_len:Vec<u8> = Vec::new();

        let mut index = usize::MAX;
        for (i, &move_len) in self.split_stack.iter().enumerate() {
            if move_len == self.split_move_len {
                index = i;
                break
            }
        }

        if index == usize::MAX {
            error!("{}", SYS.get_info("err","get_child_move_len_err"));exit(1)
        }

        // 孩子分割点
        child_move_len.extend_from_slice(&self.split_stack[index + 1 ..]);

        // 父节点的 起始搜索维度
        self.searched_dim = child_move_len.len() as u8;

        // 分割后的父节点分割点
        self.split_stack = self.split_stack[..=index].to_owned();

        child_move_len.sort();
        child_move_len
    }

    /// 在指定的[分割维度]上进行[扩展]
    /// 注意: expand_mask = ! (split_mask << expand_move_len)
    /// 如: 需要在  ...1111_0000_1111 进行扩展(0000为扩展位), expand_mask =  !(split_mask(1111) << 4)
    fn expand_dim(&mut self, expand_mask:u128) {

        // 如果 模式串 为空, 将该区域的种子地址写入
        // 注意: 这种情况只可能在 该区域首次进行维度扩展时出现
        if self.modes.is_empty() {
            self.modes = self.seed_addrs_list.clone();
        }

        // 更新 已搜索维度数量
        self.searched_dim += 1;

        // 将所有 模式串 的 扩展维度, 置为 0, 并删除相同元素
        let modes_set:AHashSet<u128> = self.modes.iter()
            .map(|&mode| mode & expand_mask)
            .collect();

        // 将 模式集合 转换成列表并赋值给 节点模式
        self.modes = modes_set.into_iter().collect();
    }

    /// 使用全部模式生成对应的所有地址
    /// 注意: 请仔细检查逻辑是否错误
    #[allow(unused_assignments)]
    fn gen_addrs_by_all_modes(&self, dim_size:u128) -> AHashSet<u128> {
        // 生成的全部地址
        let mut generated_addrs = AHashSet::with_capacity(self.space_size);

        // 复制 地址生成元
        let gen_move_len:Vec<u8> = self.gen_move_len.clone();

        // 复制 modes
        generated_addrs = self.modes.iter().map(|&x| x).collect();

        for left_move_len in gen_move_len {

            let mut cur_addrs = AHashSet::new();
            for mode in generated_addrs.iter() {

                for dim_size in 1..dim_size {
                    let tar_addr = mode | (dim_size << left_move_len);
                    cur_addrs.insert(tar_addr);
                }
            }
            generated_addrs.extend(cur_addrs);
        }
        generated_addrs
    }

    /// 根据 本区域的指定预算, 生成 目标地址
    #[allow(unused_assignments)]
    pub fn gen_addrs(&mut self, region_budget:usize, tree:&IPv6SpaceTree) -> AHashSet<u128> {

        // 根据 [预算 和 已使用地址数量]  判断 是否需要进行 维度扩展
        // 如果 需要进行维度扩展, 持续进行维度扩展, 直到 [预算 + 已使用地址数量 <= 空间大小] 或者 整个空间探索完毕
        // 区域空间扩展标识
        let mut expanded = false;
        {
            let space_needed = region_budget + self.used_addrs.len();
            while space_needed > self.space_size {
                // 弹出 当前需要进行扩展的维度, 如果为空则直接跳出循环
                let cur_split = match self.split_stack.pop() {
                    None => break,
                    Some(c) => c
                };

                // 使用当前维度 扩充 地址生成元
                self.gen_move_len.push(cur_split);

                // 计算 扩展掩码
                let expand_mask = !(tree.split_mask_u128 << cur_split);

                // 扩展 指定维度
                self.expand_dim(expand_mask);

                // 更新 区域搜索空间大小
                self.space_size = tree.dim_size.pow(self.searched_dim as u32) * self.modes.len();

                // 标识 在本轮次区域空间已经被扩展
                expanded = true;
            }
        }

        if expanded {
            // 如果 区域空间 被扩展

            // 重新 生成整个空间的 生成地址
            let all_generated_address = self.gen_addrs_by_all_modes(tree.dim_size as u128);

            // 未使用过的地址   整个空间的生成地址 - 使用过的地址
            let no_used_addrs = all_generated_address.difference(&self.used_addrs).cloned().collect();

            self.no_used_generated_address = no_used_addrs;
        }

        // 从 区域的未使用地址集合 抽取 指定预算的地址
        let mut selected_ips:AHashSet<u128> = AHashSet::with_capacity(region_budget);
        {
            // 生成随机种子
            let mut rng = rand::thread_rng();

            // 随机选择 目标地址, 并生成 目标地址列表
            selected_ips = self.no_used_generated_address
                // 从 未使用地址 中随机选择 指定数量的地址(引用)
                .iter().choose_multiple(&mut rng, region_budget)
                // 将 选择的地址 组成 列表
                .into_iter().cloned().collect();

            // 从 未使用的地址 中删除 当次选择的地址
            self.no_used_generated_address = self.no_used_generated_address.difference(&selected_ips).cloned().collect();
            // 向 已使用的地址 中插入 当次使用地址
            self.used_addrs.extend(&selected_ips);
        }

        selected_ips
    }
}