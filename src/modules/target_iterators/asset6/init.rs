use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::{AHashMap, AHashSet};
use log::{error, warn};
use crate::modules::target_iterators::asset6::{IPv6PortSpaceTree, U144};
use crate::SYS;
use crate::tools::file::get_path::get_current_path;

impl IPv6PortSpaceTree {


    pub fn new(divide_dim:u32, max_leaf_size:usize, mut no_allow_gen_seeds:bool, port_entropy_mul:f64, aliased_threshold:f64,
               learning_rate:f64, region_extraction_num:u32, seeds_path:String, seeds_num:usize, no_allow_gen_seeds_from_file:bool, aliased_prefixes_path:String) -> Self {

        // 划分维度必须 在[1, 32]范围内
        if divide_dim < 1 || 32 < divide_dim {
            error!("{} {}", SYS.get_info("err", "ipv6_space_tree_divide_dim_err"), "[1, 32]");
            exit(1)
        }

        // 聚类区域最小上限数量 为 2
        if max_leaf_size < 2 {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_max_leaf_size_err"));
            exit(1)
        }

        if region_extraction_num >= (u32::MAX >> 8)  {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_region_extraction_num_err"));
            exit(1)
        }
        
        if 144 % divide_dim != 0 {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_range_err"));
            exit(1)
        }

        let move_len_cap = 144 / divide_dim;
        let mut split_move_len:Vec<u8> = Vec::with_capacity(move_len_cap as usize);

        for i in 1..=move_len_cap {
            let cur_move_len = (144 - (divide_dim * i)) as u8;
            split_move_len.push(cur_move_len);
        }

        // 注意: 从小到大排序，对于地址结构来说，这意味着从右向左
        split_move_len.sort();

        // 计算划分维度对应的单位空间大小
        let dim_size = 1usize << divide_dim;

        if no_allow_gen_seeds_from_file {
            no_allow_gen_seeds = true;
        }
        
        // 调整范围在 [1, 16]
        let mut aliased_threshold = (aliased_threshold * 16.0) as u64;
        if aliased_threshold > 16 { aliased_threshold = 16; }
        if aliased_threshold < 1 { aliased_threshold = 1; }

        let aliased_prefixes_path = aliased_prefixes_path.trim();
        let aliased_prefixes_path = if aliased_prefixes_path == "" { None }
        else { Some(aliased_prefixes_path.to_string()) };
        
        Self {
            id_num: 0,
            dim: divide_dim,
            dim_size,
            
            split_mask_u144: U144::from(dim_size - 1),
            
            max_leaf_size,
            initial_split_move_len: split_move_len,
            
            region_queue: Vec::new(),
            all_reward: Vec::new(),
            
            region_extraction_num,
            learning_rate,
            seeds_path,
            
            no_allow_gen_seeds,
            no_allow_gen_seeds_from_file,
            used_addrs: AHashSet::new(),

            root: None,
            cur_extra_region_num: 0,
            seeds_num,
            id2port: AHashMap::new(),
            port_entropy_mul,
            
            aliased_threshold,
            
            port_scan_flag: 0b0000_0001,
            aliased_scan_flag: 0b0001_0000,
            
            aliased_prefixes_path,
        }
    }


    pub fn get_mapping(path:&str) -> AHashMap<u16, u16> {
        let mut mapping = AHashMap::with_capacity(65540);
        match OpenOptions::new().read(true).write(false).open(path) {
            Ok(file) => {
                // 生成读取缓冲区
                let lines = BufReader::with_capacity(65540*2, file).lines();

                for line in lines {
                    match line {
                        Ok(map) => {

                            let mut p = map.split(",");

                            let m1:u16 = p.next().unwrap().parse::<u16>().unwrap();
                            let m2:u16 = p.next().unwrap().parse::<u16>().unwrap();

                            mapping.insert(m1, m2);
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
        mapping.shrink_to_fit();
        mapping
    }
    
    
    pub fn get_seeds(&self) -> Vec<U144> {
        // 端口 -> 用于聚类的信息
        // 在聚类前使用
        let port2id =  Self::get_mapping(&get_current_path(&SYS.get_info("conf", "asset6_port2id")));
        
        // 所有种子目标
        let mut seeds:AHashSet<U144> = AHashSet::with_capacity(self.seeds_num);

        match OpenOptions::new().read(true).write(false).open(&self.seeds_path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();
                
                // 如果范围为整个ipv6地址空间范围
                for line in lines {
                    match line {
                        Ok(addr_port_str) => {
                            
                            let mut addr_port = addr_port_str.split(|c| c == '|' || c == ',');
                            
                            match addr_port.next() {
                                None => {}
                                Some(ipv6_str) => {
                                    match Ipv6Addr::from_str(ipv6_str.trim()) {
                                        Ok(ipv6) => {
                                            
                                            match addr_port.next() {
                                                None => {}
                                                Some(port_str) => {
                                                    match u16::from_str(port_str.trim()) {
                                                        Ok(port) => {
                                                            let ipv6_u144 = U144::from(u128::from(ipv6));
                                                            
                                                            // 注意是映射后的port
                                                            let mapped_port = *port2id.get(&port).unwrap();
                                                            let port_u144 = U144::from(mapped_port);
                                                            
                                                            let tar = (ipv6_u144 << 16) | port_u144;
                                                            seeds.insert(tar);
                                                        }
                                                        Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_str),
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_str),
                                    }
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &self.seeds_path)
        }

        // 所有种子目标
        let seeds:Vec<U144> = seeds.into_iter().collect();

        seeds
    }
    
    
    
    
    
}