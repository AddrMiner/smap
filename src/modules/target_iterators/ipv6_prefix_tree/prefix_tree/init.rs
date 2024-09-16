use std::cmp::min;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashMap;
use log::{error, warn};
use rust_decimal::Decimal;
use crate::modules::target_iterators::ipv6_prefix_tree::prefix_tree::IPv6PrefixTree;
use crate::SYS;
use crate::tools::others::parse::parse_str;

impl IPv6PrefixTree {


    pub fn new(default_divide_dim:u32,threshold:String, seeds_path:String, prefix_path:String,
               start_prefix_len:u8, max_prefix_len:u8, learning_rate:Decimal, extra_node_num:usize,
               allow_leaf_expand:bool, rand_ord:bool, child_max_size:usize) -> Self {

        // 划分维度必须 在[1, 32]范围内
        if default_divide_dim < 1 || 32 < default_divide_dim {
            error!("{} {}", SYS.get_info("err", "ipv6_space_tree_divide_dim_err"), "[1, 32]");
            exit(1)
        }

        // 计算划分维度对应的单位空间大小
        let default_dim_size = 1usize << default_divide_dim;

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

            default_dim: default_divide_dim as u8,
            default_dim_size,

            start_prefix_len,
            max_prefix_len,

            root: None,

            cur_tar_node_queue: Vec::new(),
            node_queue: Vec::new(),

            learning_rate,
            seeds_path,
            prefix_path,

            id_q_value: AHashMap::new(),

            threshold,
            extra_node_num,
            
            allow_leaf_expand,
            
            cur_parent_id_to_zero_child_id: AHashMap::new(),

            child_max_size,
            rand_ord,
        }
    }

    /// 获取初始化掩码， 用于遮蔽有效范围之外的部分
    pub fn get_init_mask(max_prefix_len:u8) -> u128 {
        let after = if max_prefix_len == 128 { 0 } else { u128::MAX >> max_prefix_len };
        !after
    }


    pub fn get_seeds_from_hit_list(seeds_path:&String, init_mask:u128) -> Vec<u128> {
        // 所有种子地址(有效前缀位后置为 ::1)
        let mut seeds:Vec<u128> = Vec::with_capacity(1_048_576);

        match OpenOptions::new().read(true).write(false).open(seeds_path) {
            Ok(file) => {
                let mut last_val:u128 = 0;

                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(addr) => {
                            match Ipv6Addr::from_str(addr.trim()) {
                                Ok(ipv6) => {
                                    let cur_val = u128::from(ipv6) & init_mask;

                                    if cur_val != last_val {
                                        seeds.push(cur_val | 1);
                                        last_val = cur_val;
                                    }
                                }
                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr.trim())
                            }
                        }
                        Err(_) => {}
                    }
                }

            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &seeds_path)
        }
        seeds
    }

    pub fn get_prefixes(prefix_path:&String, init_mask:u128, max_prefix_len:u8) -> (Vec<(u128, u8)>, u8) {
        // 所有 前缀
        let mut prefixs:Vec<(u128, u8)> = Vec::with_capacity(262_144);
        // 所有前缀中, 最短的前缀长度
        let mut start_prefix_len = u8::MAX;

        match OpenOptions::new().read(true).write(false).open(&prefix_path) {
            Ok(file) => {
                let mut last_val:u128 = 0;
                let mut last_len:u8 = 0;

                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(prefix) => {
                            match prefix.split("	").next() {
                                None => {}
                                Some(prefix) => {
                                    let mut p = prefix.split("/");
                                    
                                    match Ipv6Addr::from_str(p.next().unwrap().trim()) {
                                        Ok(ipv6) => {
                                            match u8::from_str(p.next().unwrap().trim()) {
                                                Ok(mut prefix_len) => {
                                                    let cur_val;
                                                    if prefix_len > max_prefix_len {
                                                        // 当 当前前缀长度 大于 最大前缀长度 时
                                                        cur_val = u128::from(ipv6) & init_mask;
                                                        prefix_len = max_prefix_len;
                                                    } else {
                                                        cur_val = u128::from(ipv6);
                                                    }

                                                    if (last_val != cur_val) || (last_len != prefix_len) {
                                                        // 加入前缀集
                                                        prefixs.push((cur_val, prefix_len));
                                                        // 计算 最短前缀长度
                                                        start_prefix_len = min(start_prefix_len, prefix_len);

                                                        last_val = cur_val;
                                                        last_len = prefix_len;
                                                    }
                                                }
                                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), prefix.trim())
                                            }
                                        }
                                        Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), prefix.trim())
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }

            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &prefix_path)
        }
        (prefixs, start_prefix_len)
    }

}