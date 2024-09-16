use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashMap;
use log::{error, info, warn};
use rust_decimal::Decimal;
use crate::modules::target_iterators::ipv6_prefix_tree::fixed_dim_tree::IPv6FixedPrefixTree;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::SYS;
use crate::tools::others::parse::parse_str;

impl IPv6FixedPrefixTree {

    pub fn new(divide_dim:u32, max_prefix_len:u32, learning_rate:Decimal, seeds_path:String, 
               prefix_path:String, start_prefix_len:u8, threshold:String, extra_node_num:usize,
               allow_leaf_expand:bool, allow_layer_expand:bool, layer_expand_ratio:f64, rand_ord:bool) -> Self {

        // 划分维度必须 在[1, 32]范围内
        if divide_dim < 1 || 32 < divide_dim {
            error!("{} {}", SYS.get_info("err", "ipv6_space_tree_divide_dim_err"), "[1, 32]");
            exit(1)
        }

        // 最大前缀长度必须 大于1, 小于或等于128, 且 能被划分维度整除
        if max_prefix_len <= 1 || 128 < max_prefix_len || (max_prefix_len % divide_dim != 0) {
            error!("{}", SYS.get_info("err", "ipv6_tree_max_prefix_len_err"));
            exit(1)
        }

        let move_len_cap = max_prefix_len / divide_dim;
        let mut split_move_len:Vec<u8> = Vec::with_capacity(move_len_cap as usize);

        for i in 1..=move_len_cap {
            let cur_move_len = (128 - (divide_dim * i)) as u8;
            split_move_len.push(cur_move_len);
        }

        // 注意: 从小到大排序，对于地址结构来说，这意味着从右向左
        split_move_len.sort();

        // 计算划分维度对应的单位空间大小
        let dim_size = 1usize << divide_dim;

        let threshold:Option<Decimal> = match threshold.as_str() {
            "0" | "0.0" => Some(Decimal::ZERO),
            "none" => None,
            other => {
                let t = parse_str(other);
                Some(t)
            }
        };
        
        Self {
            id_num: 0,
            
            dim: divide_dim as u8,
            dim_size,
            split_mask_u128: (dim_size - 1) as u128,
            split_mask_usize: dim_size - 1,
            max_prefix_len: max_prefix_len as u8,
            
            root: None,
            initial_split_move_len: split_move_len,
            
            cur_tar_node_queue: Vec::new(),
            node_queue: Vec::new(),
            
            learning_rate,
            start_prefix_len,
            
            seeds_path,
            prefix_path,
            
            id_q_value: AHashMap::new(),
            
            threshold,
            
            extra_node_num,
            allow_leaf_expand,

            allow_layer_expand,
            layer_expand_ratio,
            // 默认不进行层级扩展
            layer_expand_count: dim_size,

            split_count: Vec::new(),
            cur_parent_id_to_zero_child_id: AHashMap::new(),

            rand_ord,
        }
    }
    
    /// 从 hit_list 中读取种子地址, 有效前缀位保留, 后续拼接 ::1
    /// 从 前缀离线数据库 中读取前缀, 所有前缀拼接 ::1 后作为种子地址
    /// 将所有种子地址 从小到大排序, 并删除重复地址
    pub fn get_seeds(max_prefix_len:u8, seeds_path:&String, prefix_path:&String) -> Vec<u128> {
        // 获取初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(max_prefix_len);

        // 从 种子地址文件 中 获取全部的 种子地址
        let mut seeds = IPv6PrefixTree::get_seeds_from_hit_list(seeds_path,init_mask);
        // 将 前缀 拼接 ::1 后加入 种子地址列表
        seeds.extend(IPv6FixedPrefixTree::get_addrs_from_prefixes(prefix_path, init_mask));

        // 从小到大排序
        seeds.sort();
        // 删除重复地址
        seeds.dedup();
        
        info!("{} {}", SYS.get_info("info", "seeds_num"), seeds.len());
        
        seeds
    }
    
    fn get_addrs_from_prefixes(prefix_path:&String, init_mask:u128) -> Vec<u128> {
        // 所有 前缀生成的地址
        let mut prefix_addrs:Vec<u128> = Vec::with_capacity(262_144);
        
        match OpenOptions::new().read(true).write(false).open(prefix_path) {
            Ok(file) => {
                let mut last_val:u128 = 0;

                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(prefix) => {
                            match Ipv6Addr::from_str(prefix.split("/").next().unwrap().trim()) {
                                Ok(ipv6) => {
                                    let cur_val = u128::from(ipv6) & init_mask;

                                    if cur_val != last_val {
                                        prefix_addrs.push(cur_val | 1);
                                        last_val = cur_val;
                                    }
                                }
                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), prefix.trim())
                            }
                        }
                        Err(_) => {}
                    }
                }

            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), prefix_path)
        }
        prefix_addrs
    }
}