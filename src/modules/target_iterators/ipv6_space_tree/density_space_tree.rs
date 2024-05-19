use std::cell::{RefCell, RefMut};
use std::process::exit;
use std::rc::Rc;
use log::error;
use rand::seq::IteratorRandom;
use crate::modules::target_iterators::ipv6_space_tree::IPv6SpaceTreeNode;
use crate::modules::target_iterators::ipv6_space_tree::space_tree::IPv6SpaceTree;
use crate::SYS;

impl IPv6SpaceTree {

    /// 初始化 密度地址空间树
    pub fn init_density_tree(&mut self){

        let mut seeds:Vec<u128>;
        {
            // 从 文件 中读取种子地址
            let all_seeds = self.get_seeds();

            // 凡是输入文件中的地址都不允许生成
            if self.no_allow_gen_seeds_from_file {
                self.used_addrs = all_seeds.iter().cloned().collect();
            }

            let mut rng = rand::thread_rng();
            // 随机选择 目标地址, 并生成 目标地址列表
            seeds = all_seeds.into_iter().choose_multiple(&mut rng, self.seeds_num).into_iter().collect();
            seeds.shrink_to_fit();

            // 可以生成种子文件中的地址 且 不允许生成种子地址
            if (!self.no_allow_gen_seeds_from_file) && self.no_allow_gen_seeds {
                self.used_addrs = seeds.iter().cloned().collect();
            }
        }
        
        self.seeds_num = seeds.len();

        // 创建根节点
        let (split_move_len, act_val_num, stack) = self.get_split_stack_density(&seeds, &self.initial_split_move_len);
        let root = IPv6SpaceTreeNode::new(self.id_num, seeds, stack, split_move_len, act_val_num, None, 0);
        self.id_num += 1;
        let root = Rc::new(RefCell::new(root));

        // 裂解 种子地址集群, 生成 聚类区域队列
        self.density_split_tree(root.clone());
        self.root = Some(root);
        
        // 初始化  区域队列 和 对应的奖励队列
        self.init_queue();
    }


    /// 递归分割形成密度空间树
    pub fn density_split_tree(&mut self, node:Rc<RefCell<IPv6SpaceTreeNode>>){
        
        let mut cur_node: RefMut<IPv6SpaceTreeNode> = node.borrow_mut();

        // 当前 地址聚类块地址数量 <= 聚类块地址数量上限
        // 该 节点 不需要继续分裂, 直接返回
        if cur_node.seed_addrs_list.len() <= self.max_leaf_size {
            return
        }

        // 该节点需要进行分裂
        let mut key_ips:Vec<Vec<u128>>;
        {
            // 取出该节点 分裂点
            let split_move_len = cur_node.split_move_len;
            if split_move_len == u8::MAX {
                // 地址数量达到分裂要求, 但是不存在非零熵值位, 说明出现错误
                error!("{}", SYS.get_info("err", "ipv6_space_tree_no_entropy_err"));
                exit(1)
            }

            // 取出 该节点分裂点上的统计信息
            let act_val_num = cur_node.act_val_num.clone();

            // 值类型(下标) -> 对应索引
            let mut index_list = vec![0usize; self.dim_size];
            key_ips = Vec::with_capacity(act_val_num.len());
            for (index, (val, num)) in act_val_num.into_iter().enumerate() {
                index_list[val] = index;
                key_ips.push(Vec::with_capacity(num as usize));
            }

            let split_mask = self.split_mask_usize;
            for addr in cur_node.seed_addrs_list.iter() {
                // 对于 整个地址聚类块 中的 每个地址

                // 计算当前地址在 分割点 上的值
                let val = ((addr >> split_move_len) as usize) & split_mask;
                key_ips[index_list[val]].push(*addr);
            }
            
            // 删除 父节点中的地址
            cur_node.seed_addrs_list.clear();
            cur_node.seed_addrs_list.shrink_to_fit();
        }
        
        // 删除该节点中的 零熵值维度 和 分裂维度, 得到 子节点所需分割点维度
        let child_move_len = cur_node.get_child_move_len_density();
        
        // 生成子节点
        for ips in key_ips {
            
            let (split_move_len, act_val_num, stack) = self.get_split_stack_density(&ips, &child_move_len);
            let child = Rc::new(RefCell::new(IPv6SpaceTreeNode::new(self.id_num, ips, stack, split_move_len, act_val_num, Some(node.clone()), cur_node.level + 1)));
            self.id_num += 1;
            
            cur_node.childs.push(child);
        }
        
        // 裂解子空间区域
        for child in &cur_node.childs {
            self.density_split_tree(child.clone());
        }
    }



    /// 根据当前节点的 种子地址, 生成该节点对应的维度栈
    /// 警告: move_len 必须 从小到大 排序
    fn get_split_stack_density(&self, addrs:&Vec<u128>, move_len:&Vec<u8>) -> (u8, Vec<(usize, u64)>, Vec<u8>) {

        // 注意: 该栈的顺序为  低熵 -> 高熵
        // 注意: 当熵值相等时为    地址结构较左 ->  地址结构较右

        // 获取 地址结构段 的统计信息
        let stat = Self::get_stat(addrs, move_len, self.dim_size, self.split_mask_usize);

        // 取出常量
        let addrs_len = addrs.len() as f64; let dim_f64 = self.dim as f64;

        // 统计 熵值信息
        // 注意: move_len 与 熵值列表 一一对应
        let mut index_entropy = Vec::with_capacity(move_len.len());

        // 对每个地址结构段进行熵值计算
        for (index, local_stat) in stat.iter().enumerate() {
            // 对于每个地址结构段(注意: 从右向左)

            // 计算各类型对应的概率值
            let pro_list = Self::get_pro_list_no_zero(addrs_len, local_stat);
            // 使用 概率值向量 计算 熵值
            let cur_entropy = Self::get_entropy(pro_list, dim_f64);

            index_entropy.push((index, cur_entropy));
        }

        // 先按照熵值 从小到大排序, 如果熵值相等, 按 右移距离 从大到小排序(按地址结构 从左向右)
        index_entropy.sort_by(|a, b| {
            a.1.partial_cmp(&b.1).unwrap().then(b.0.cmp(&a.0))
        });

        let (split_move_len, act_val_num) = if let Some((split_index, _)) = index_entropy.iter().find(|(_, second)| *second > f64::EPSILON) {
            // 找到 第一个非零熵值
            (move_len[*split_index], Self::get_act_val_num(&stat[*split_index]))
        } else {
            (u8::MAX, vec![])    // u8::MAX为无效值, 表示不存在非零分裂点
        };

        (split_move_len, act_val_num, index_entropy.into_iter().map(
            |x| move_len[x.0]
        ).collect())
    }

}


