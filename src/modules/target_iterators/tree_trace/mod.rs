use std::cmp::min;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::str::FromStr;
use ahash::AHashSet;
use log::{error, info, warn};
use rand::{rng, Rng};
use rand::seq::SliceRandom;
use crate::SYS;

mod node;
mod pcs_table;

pub use node::HuffNode;
pub use pcs_table::PCStable;

pub struct TreeTraceIter {

    // 前缀信息结构表, 每个元素表示一个前缀, 其中是它的具体信息
    pub pcs_list:Vec<PCStable>,

    // 哈夫曼树
    pub huffman_tree:HuffNode,
}



impl TreeTraceIter {

    /// 输入前缀列表, 生成前缀信息表
    pub fn new(path:&String, gen_topo_tar:bool) -> Self {

        // 初始状态下的 pcs列表
        let initial_pcs_list = Self::init_pcs_list(path);
        // 由 初始pcs列表 创建的 哈夫曼树
        let initial_huffman = HuffNode::new(&initial_pcs_list, gen_topo_tar);

        Self {
            pcs_list: initial_pcs_list,
            huffman_tree: initial_huffman.unwrap(),
        }
    }

    /// 在一个轮次的探测完成以后, 更新所有前缀的 reward
    pub fn update_rewards(&mut self, info:Vec<u64>){
        for (cur_pcs, reward_plus) in self.pcs_list.iter_mut().zip(info){
            cur_pcs.reward += reward_plus;
        }
    }

    /// 在每个轮次之间重新生成哈夫曼树
    /// 返回是否已经结束
    pub fn recreate_huffman(&mut self, gen_topo_tar:bool) -> bool {
        // 先清空哈夫曼树
        self.huffman_tree = HuffNode {
            zero: None,
            one: None,
            weight: Default::default(),
            index: 0,
        };
        
        if let Some(root) = HuffNode::new(&self.pcs_list, gen_topo_tar) {
            self.huffman_tree = root;
            false
        } else { 
            true   
        }
    }

    pub fn print_offset_count(&self, top_count:usize, gen_topo_tar:bool) {
        let mut total_count = 0;
        let mut offset_count = Vec::with_capacity(self.pcs_list.len());

        for (index, cur_pcs) in self.pcs_list.iter().enumerate() {
            let cur_offset = cur_pcs.offset;

            offset_count.push((index, cur_offset));
            total_count += cur_offset;
        }

        // 按 offset 值从大到小排序
        offset_count.sort_by(|a, b| b.1.cmp(&a.1));

        info!("total_count: {}", total_count);

        let top_count = min(top_count, offset_count.len());
        for i in 0..top_count {
            
            let cur_index = offset_count[i].0;
            let cur_offset = offset_count[i].1;
            
            let prefix = Ipv6Addr::from((self.pcs_list[cur_index].stub as u128) << 64);
            let prefix_len = self.pcs_list[cur_index].mask.leading_zeros();
            let cur_reward = self.pcs_list[cur_index].reward;
            
            info!("{}:  {:?}/{}  gen:{}    {}%  reward:{}    {}%", i+1, prefix, prefix_len, cur_offset, (cur_offset as f64) / (total_count as f64) * 100.0, cur_reward, 
                if gen_topo_tar {
                    (cur_reward as f64) / ((cur_offset as f64) * 32.0) * 100.0
                } else {
                    (cur_reward as f64) / (cur_offset as f64) * 100.0
                }
            )
        }
        
    }

    /// 生成指定数量的具体目标
    pub fn gen_target(&mut self, budget:u64) -> Vec<(u64, u8, Vec<u8>)>{
        let mut rng = rng();

        let mut targets = Vec::with_capacity(budget as usize);
        for _ in 0..budget {

            // 生成随机数
            let rand_u64:u64 = rng.random();
            // 使用随机数遍历二叉树
            let tar_prefix_index = HuffNode::search_tree(&self.huffman_tree, rand_u64);

            // 由索引找到对应 pcs块
            let tpcs = &mut self.pcs_list[tar_prefix_index as usize];

            // 将生成的目标加入队列
            // (目标前缀, hop_limit), 包含区域编码信息的自定义编码
            targets.push(tpcs.gen_target(tar_prefix_index));
        }

        // 对所有目标打乱顺序
        targets.shuffle(&mut rng);

        targets
    }
    
    pub fn gen_topo_target(&mut self, budget:u64) -> Vec<(u64, u8, Vec<u8>)> {
        let mut rng = rng();
        let mut targets = Vec::with_capacity(budget as usize);
        
        // 计算每轮次生成的 目标地址数量
        // 警告: budget应足够大
        let tar_addrs_len = budget / 32;
        for _ in 0..tar_addrs_len {

            // 生成随机数
            let rand_u64:u64 = rng.random();
            // 使用随机数遍历二叉树
            let tar_prefix_index = HuffNode::search_tree(&self.huffman_tree, rand_u64);
            // 由索引找到对应 pcs块
            let tpcs = &mut self.pcs_list[tar_prefix_index as usize];
            
            // 生成 该前缀下随机地址的所有ttl
            targets.extend(tpcs.gen_topo_target(tar_prefix_index));
        }

        // 对所有目标打乱顺序
        targets.shuffle(&mut rng);

        targets
    }

    /// 读取文件中的前缀信息，并生成初始状态下的 pcs列表
    pub fn init_pcs_list(path:&String) -> Vec<PCStable> {
        let prefixes = Self::get_prefixes_from_file(path);

        // 根据前缀信息生成初始 pcs列表
        let mut pcs_list = Vec::with_capacity(prefixes.len());
        for (cur_prefix, cur_prefix_len) in prefixes.into_iter() {

            pcs_list.push(PCStable {
                // 前64位前缀
                stub: cur_prefix,
                // 地址生成掩码
                mask: u64::MAX >> cur_prefix_len,
                reward: 0,
                offset: 0,
            });
        }

        pcs_list
    }


    pub fn get_prefixes_from_file(path:&String) -> AHashSet<(u64, u8)> {
        // 从文件中获取前缀信息
        let mut prefixes = AHashSet::new();
        match OpenOptions::new().read(true).write(false).open(path) {
            Ok(file) => {
                // 生成读取缓冲区
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(prefix) => {

                            let mut p = prefix.split("/");
                            match Ipv6Addr::from_str(p.next().unwrap().trim()) {
                                Ok(ipv6) => {
                                    match u8::from_str(p.next().unwrap().trim()) {
                                        Ok(prefix_len) => {

                                            // 取前64位
                                            let cur_prefix = (u128::from(ipv6) >> 64) as u64;
                                            let cur_prefix_len = if prefix_len > 64 { 64 } else { prefix_len };

                                            prefixes.insert((cur_prefix, cur_prefix_len));
                                        }
                                        Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), prefix.trim())
                                    }
                                }
                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), prefix.trim())
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), path)
        }
        prefixes
    }
}