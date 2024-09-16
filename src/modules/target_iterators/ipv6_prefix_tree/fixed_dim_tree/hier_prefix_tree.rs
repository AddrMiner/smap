use std::cell::{RefCell, RefMut};
use std::process::exit;
use std::rc::Rc;
use log::error;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::IPv6FixedPrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::node::IPv6FixedPrefixNode;
use crate::modules::target_iterators::IPv6SpaceTree;
use crate::SYS;


impl IPv6FixedPrefixTree {
    
    /// 由 种子地址 构建 层次空间树
    pub fn init_hier_tree(&mut self){

        // 从 hit_list 和 前缀列表 中得到种子地址
        let seeds = Self::get_seeds(self.max_prefix_len, &self.seeds_path, &self.prefix_path);

        // 创建根节点
        let root = Rc::new(RefCell::new(IPv6FixedPrefixNode::new(self.id_num,0, 0, false)));
        self.id_num += 1;

        // 裂解 种子地址集群, 生成 空间树
        self.hier_split_tree(root.clone(), &self.initial_split_move_len.clone(), seeds);
        
        // 根节点赋值
        self.root = Some(root);
        
        // 获取 层级分裂判断依据
        self.get_layer_expand_count();
    }

    /// 递归分割生成 层次空间树
    pub fn hier_split_tree(&mut self, node:Rc<RefCell<IPv6FixedPrefixNode>>, move_len:&Vec<u8>, seed_addrs_list:Vec<u128>) {

        // 当前节点 种子地址数量 小于等于 1
        // 该 节点 不需要继续分裂, 直接返回
        if seed_addrs_list.len() <= 1 { return }

        // 获得 当前节点的可变引用
        let mut cur_node: RefMut<IPv6FixedPrefixNode> = node.borrow_mut();

        // 获得分裂点, 分裂点处的统计信息, 孩子节点的分割点
        let (split_move_len, act_val_num, child_move_len, child_mode) =
            self.get_split_hier(&seed_addrs_list, move_len.clone(), cur_node.mode);

        let mut key_ips:Vec<Vec<u128>>;
        {
            // 取出该节点 分裂点
            if split_move_len == u8::MAX {
                // 地址数量达到分裂要求, 但是不存在非零熵值位, 说明出现错误
                error!("{}", SYS.get_info("err", "ipv6_space_tree_no_entropy_err"));
                exit(1)
            }

            // 值类型(下标) -> 对应索引
            let mut index_list = vec![0usize; self.dim_size];
            key_ips = Vec::with_capacity(act_val_num.len());
            for (index, (val, num)) in act_val_num.into_iter().enumerate() {
                index_list[val] = index;
                key_ips.push(Vec::with_capacity(num as usize));
            }

            let split_mask = self.split_mask_usize;
            for addr in seed_addrs_list.into_iter() {
                // 对于 整个地址聚类块 中的 每个地址

                // 计算当前地址在 分割点 上的值
                let val = ((addr >> split_move_len) as usize) & split_mask;
                key_ips[index_list[val]].push(addr);
            }
        }

        // 子节点的 前缀长度 = 最大前缀长度 - 分割维度大小 * 待分割维度数量
        let prefix_len = self.max_prefix_len - self.dim * (child_move_len.len() as u8);
        
        // 记录分裂数量  用于 同层级扩展的依据
        self.split_count.push(key_ips.len() as u8);

        // 生成子节点
        for ips in key_ips.into_iter() {

            // 计算当前地址在 分割点 上的值
            let val = ((ips[0] >> split_move_len) & self.split_mask_u128) << split_move_len;
            let child = Rc::new(RefCell::new(IPv6FixedPrefixNode::new(self.id_num, child_mode | val, prefix_len, val == 0)));
            self.id_num += 1;

            cur_node.children.push(child.clone());
            self.hier_split_tree(child, &child_move_len, ips);
        }
    }
    
    /// 根据当前节点的 种子地址, 按子网层级进行分裂
    /// 警告: move_len 必须 从小到大 排序
    /// 返回值: (当前结构段的位置(如果为u8::MAX则为无法找到分裂点), 统计信息, 剩余的分裂点(不包含当前分裂点), mode)
    pub fn get_split_hier(&self, addrs:&Vec<u128>, mut move_len:Vec<u8>, mut mode:u128) -> (u8, Vec<(usize, u64)>, Vec<u8>, u128){

        // 注意: 地址分割维度需从小到大排序, 也即 地址结构从右向左

        // 获取 地址结构段 的统计信息
        let mut stat = IPv6SpaceTree::get_stat(addrs, &move_len, self.dim_size, self.split_mask_usize);

        // 取出第一个地址 以 提取零熵值位的值
        let addr = addrs[0];

        // 取出常量
        let addrs_len = addrs.len() as f64; let dim_f64 = self.dim as f64;

        // 对每个地址结构段进行熵值计算
        while let Some((split_move_len, local_stat)) = move_len.pop().zip(stat.pop()) {
            // 对于每个地址结构段(注意: 从右向左)

            // 计算各类型对应的概率值
            let pro_list = IPv6SpaceTree::get_pro_list_no_zero(addrs_len, &local_stat);
            // 使用 概率值向量 计算 熵值
            let cur_entropy = IPv6SpaceTree::get_entropy(pro_list, dim_f64);

            // 找到第一个 熵值大于0 的结构段
            if cur_entropy > f64::EPSILON {

                // 返回当前结构段的位置, 统计信息, 剩余的分裂点(不包含当前分裂点), 附加零熵值位的mode
                return (split_move_len, IPv6SpaceTree::get_act_val_num(&local_stat), move_len, mode);
            } else {

                // 将 当前地址结构段(零熵值) 的值添加到 mode
                mode |= ((addr >> split_move_len) & self.split_mask_u128) << split_move_len;
            }
        }
        
        (u8::MAX, vec![], vec![], mode)
    }
}