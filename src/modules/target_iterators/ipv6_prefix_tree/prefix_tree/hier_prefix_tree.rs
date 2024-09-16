use std::cell::{RefCell, RefMut};
use std::cmp::min;
use std::mem::take;
use std::rc::Rc;
use ahash::{AHashMap, AHashSet};
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::node::IPv6PrefixNode;

impl IPv6PrefixTree {

    pub fn init_hier_tree(&mut self){

        // 获取初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(self.max_prefix_len);
        // 获取前缀列表
        let (prefixes, start_prefix_len) = Self::get_prefixes(&self.prefix_path, init_mask, self.max_prefix_len);
        // 获取种子地址列表
        let addrs = Self::get_seeds_from_hit_list(&self.seeds_path, init_mask);
        
        // 创建根节点
        let root = Rc::new(RefCell::new(
           IPv6PrefixNode::new(self.id_num, 0, 0, false, false) 
        ));
        self.id_num += 1;

        // 裂解前缀, 种子地址集群, 生成 可变维度空间树
        self.hier_split_tree(root.clone(), prefixes, addrs, start_prefix_len);
        
        // 根节点赋值
        self.root = Some(root);
    }
    
    
    pub fn hier_split_tree(&mut self, node:Rc<RefCell<IPv6PrefixNode>>, 
                           prefixes:Vec<(u128, u8)>, addrs:Vec<u128>, split_prefix_len:u8) {
        
        if prefixes.is_empty() && addrs.len() <= 1 { return }

        // 计算右移距离, 掩码, 分割位值和其对应的数量
        let (split_move_len, prefix_val_num, addr_val_num, longer_prefix_set) =
            self.get_split_hier(&prefixes, &addrs, split_prefix_len);

        // 记录 不同前缀值 对应的 最小前缀长度
        let mut val_min_len: AHashMap<u128, u8> = AHashMap::new();
        // 记录 不同区域的前缀列表(按照分裂点的前缀值进行分类)
        let mut key_prefixes: Vec<Vec<(u128, u8)>>;
        // 记录 不同区域的种子地址列表
        let mut key_addrs: Vec<Vec<u128>>;

        // 值类型(下标) -> 对应索引
        let mut prefix_index = AHashMap::new();
        let mut addr_index = AHashMap::new();
        {
            key_prefixes = Vec::with_capacity(prefix_val_num.len());
            for (index, (val, num)) in prefix_val_num.into_iter().enumerate() {
                prefix_index.insert(val, index);
                key_prefixes.push(Vec::with_capacity(num as usize));
            }

            key_addrs = Vec::with_capacity(addr_val_num.len());
            for (index, (val, num)) in addr_val_num.into_iter().enumerate() {
                addr_index.insert(val, index);
                key_addrs.push(Vec::with_capacity(num as usize));
            }

            // 遍历该区域所有前缀
            for prefix in prefixes.into_iter() {
                if prefix.1 > split_prefix_len {
                    // 只有大于 当前分裂点前缀长度 的前缀才被保留

                    // 计算当前前缀在分裂点上的 前缀值
                    let prefix_val = prefix.0 >> split_move_len;

                    // 按照 前缀值 将前缀加入对应分类
                    key_prefixes[*prefix_index.get(&prefix_val).unwrap()].push(prefix);

                    // 记录在该分类上的 最小前缀长度
                    if let Some(l) = val_min_len.get_mut(&prefix_val) {
                        *l = min(*l, prefix.1);
                    } else {
                        val_min_len.insert(prefix_val, prefix.1);
                    }
                }
            }

            // 遍历该区域所有种子地址
            for addr in addrs.into_iter() {
                let prefix_val = addr >> split_move_len;
                // 按照 前缀值 将地址加入对应分类
                key_addrs[*addr_index.get(&prefix_val).unwrap()].push(addr);
            }
        }

        // 获得 当前节点的可变引用
        let mut cur_node: RefMut<IPv6PrefixNode> = node.borrow_mut();
        // 计算相对于上一次分裂多出来的二进制位
        let zero_mask = 1u128 << (split_prefix_len - cur_node.prefix_len) - 1;
        let parent_real = cur_node.real;
        let parent_zero = cur_node.zero;
        // 计算默认的下一个分裂点(没有最短前缀长度)
        let next_split_prefix_len = split_prefix_len + self.default_dim;
        let max_prefix_len = self.max_prefix_len;
        let next_split_prefix_len = if next_split_prefix_len > max_prefix_len { max_prefix_len } else { next_split_prefix_len };

        for (prefix_val, index) in prefix_index.iter() {
            // 判断当前节点是否为 零节点
            let zero = Self::is_zero(*prefix_val, zero_mask, parent_real, parent_zero);

            let child = Rc::new(RefCell::new(
               IPv6PrefixNode::new(self.id_num, prefix_val << split_move_len, split_prefix_len, zero, 
                                   !longer_prefix_set.contains(&prefix_val))
            ));
            self.id_num += 1;

            cur_node.children.push(child.clone());
            if split_prefix_len < max_prefix_len {
                // 只有在 当前分裂点的前缀长度 小于 最大前缀长度 时才继续向下分裂
                self.hier_split_tree(
                    child,
                    take(&mut key_prefixes[*index]),
                    match addr_index.get(&prefix_val) {
                        None => Vec::new(),
                        Some(addr_i) => take(&mut key_addrs[*addr_i])
                    },
                    {
                        // 获取该区域的最小前缀长度
                        match val_min_len.get(&prefix_val) {
                            None => next_split_prefix_len,
                            Some(cur_min_len) => if *cur_min_len > max_prefix_len { max_prefix_len } else { *cur_min_len }
                        }
                    }
                )
            }
        }

        // 清理 更长前缀集合
        drop(longer_prefix_set);

        for (prefix_val, index) in addr_index {

            // 如果该前缀值在 前缀遍历时出现过, 就直接停止该轮
            // 如果未在前缀列表中出现, 说明为未知子网
            // 未知子网按 最短前缀 进行分裂
            if prefix_index.contains_key(&prefix_val) { continue }

            let zero = Self::is_zero(prefix_val, zero_mask, parent_real, parent_zero);

            let child = Rc::new(RefCell::new(
                IPv6PrefixNode::new(self.id_num, prefix_val << split_move_len, split_prefix_len, zero, true)));
            self.id_num += 1;

            cur_node.children.push(child.clone());
            if split_prefix_len < max_prefix_len {
                self.hier_split_tree(
                    child,
                    Vec::new(),
                    take(&mut key_addrs[index]),
                    next_split_prefix_len
                )
            }
        }
    }


    /// 判断当前节点是否为零节点
    #[inline]
    pub fn is_zero(prefix_val:u128, zero_mask:u128, parent_real:bool, parent_zero:bool) -> bool {
        // 判断是否为零节点
        let mut zero = (prefix_val & zero_mask) == 0;
        if !parent_real {
            // 如果 父节点为 非实质节点
            // 只要路线中有一个节点为 非零节点, 该节点为非零节点
            // 全为 零节点 时，才为零节点
            zero = parent_zero & zero;
        }
        zero
    }
    

    /// 获取分裂点信息
    /// 输入: 区域前缀列表, 区域种子地址列表, 区域最小前缀长度
    /// 输出: 分裂点右移距离, 前缀信息, 种子地址信息, 更长前缀的前缀值集合
    pub fn get_split_hier(&self, prefixes:&Vec<(u128, u8)>, addrs:&Vec<u128>, split_prefix_len:u8)
        -> (u8, AHashMap<u128, u64>, AHashMap<u128, u64>, AHashSet<u128>) {

        // 计算 右移距离
        let split_move_len = 128 - split_prefix_len;

        // 值 -> 数量大小
        let mut prefix_val_num = AHashMap::new();
        let mut addr_val_num = AHashMap::new();

        // 记录比当前分裂点前缀长度更长的 前缀值
        let mut longer_prefix_set = AHashSet::new();
        let mut cur_len_prefix_set = AHashSet::new();
        
        for (prefix, prefix_len) in prefixes {
            
            // 计算 前缀值
            let prefix_val = prefix >> split_move_len;
            
            if *prefix_len > split_prefix_len {
                // 实际前缀长度 大于 当前分裂点的前缀长度

                // 将 更长前缀的前缀值 进行记录
                longer_prefix_set.insert(prefix_val);

                // 统计数量
                if let Some(t) = prefix_val_num.get_mut(&prefix_val) {
                    *t += 1;
                } else {
                    prefix_val_num.insert(prefix_val, 1);
                }
            } else {
                // 实际前缀长度 小于等于 当前分裂点的前缀长度
                cur_len_prefix_set.insert(prefix_val);
                if !prefix_val_num.contains_key(&prefix_val) {
                    // 如果不存在, 数量设为0
                    prefix_val_num.insert(prefix_val, 0);
                }
            }
        }

        // 计算 差集
        let longer_prefix_set = longer_prefix_set.difference(&cur_len_prefix_set).copied().collect();
        drop(cur_len_prefix_set);

        for addr in addrs {
            // 计算 前缀值
            let prefix_val = addr >> split_move_len;

            // 统计数量
            if let Some(t) = addr_val_num.get_mut(&prefix_val) {
                *t += 1;
            } else {
                addr_val_num.insert(prefix_val, 1);
            }
        }

        (split_move_len, prefix_val_num, addr_val_num, longer_prefix_set)
    }
}
