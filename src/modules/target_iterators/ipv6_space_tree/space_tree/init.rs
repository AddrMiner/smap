use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashSet;
use log::{error, warn};
use crate::core::conf::tools::args_parse::port::parse_range;
use crate::modules::target_iterators::ipv6_space_tree::space_tree::IPv6SpaceTree;
use crate::SYS;


/// ipv6空间树 初始化方法
impl IPv6SpaceTree {

    /// 定义ipv6空间树
    /// 输入 空间树划分维度, 划分范围
    /// 注意: 划分范围为 (开始位置, 结束位置), 位置有效范围[1, 128], 开始位置必须小于或等于结束位置且能被划分维度整除
    pub fn new(divide_dim:u32, divide_range:String, max_leaf_size:usize, mut no_allow_gen_seeds:bool,
               learning_rate:f64, region_extraction_num:u32, seeds_path:String, seeds_num:usize, no_allow_gen_seeds_from_file:bool) -> Self {

        // 划分维度必须 在[1, 32]范围内
        if divide_dim < 1 || 32 < divide_dim {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_divide_dim_err"));
            exit(1)
        }
        
        // 聚类区域最小上限数量 为 2
        if max_leaf_size < 2 {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_max_leaf_size_err"));
            exit(1)
        }

        if region_extraction_num > (u16::MAX as u32)  {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_region_extraction_num_err"));
            exit(1)
        }

        // 计算右移距离向量
        let range = parse_range(&divide_range, "ipv6_space_tree_range_err");
        // 保证 开始位置必须小于或等于结束位置, 范围大小必须能被划分维度整除
        let range_size = range.1 - range.0 + 1;
        if range.0 < 1 || 128 < range.0 || range.1 < 1 || 128 < range.1 || (range_size % divide_dim != 0) {
            error!("{}", SYS.get_info("err", "ipv6_space_tree_range_err"));
            exit(1)
        }

        let move_len_cap = range_size / divide_dim;
        let mut split_move_len:Vec<u8> = Vec::with_capacity(move_len_cap as usize);

        for i in 1..=move_len_cap {
            let cur_move_len = (128 - (divide_dim * i + range.0 - 1)) as u8;
            split_move_len.push(cur_move_len);
        }

        // 注意: 从小到大排序，对于地址结构来说，这意味着从右向左
        split_move_len.sort();

        // 计算划分维度对应的单位空间大小
        let dim_size = 1usize << divide_dim;
        
        if no_allow_gen_seeds_from_file {
            no_allow_gen_seeds = true;
        }

        Self {
            id_num: 0,
            dim: divide_dim,
            dim_size,
            range,
            split_mask_usize: dim_size - 1,
            split_mask_u128: (dim_size - 1) as u128,
            
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
        }
    }


    /// 获取初始化掩码， 用于遮蔽有效范围之外的部分
    pub fn get_init_mask(&self) -> u128 {
        let before = if self.range.0 == 1 { 0 } else {  u128::MAX << (129 - self.range.0) };
        let after = if self.range.1 == 128 { 0 } else { u128::MAX >> self.range.1 };

        ! (before | after)
    }

    /// 获取种子地址
    /// 警告: 输入的种子地址必须是排好序且无重复的
    pub fn get_seeds(&self) -> Vec<u128> {
        // 所有种子地址
        let mut seeds:Vec<u128> = Vec::with_capacity(self.seeds_num);

        match OpenOptions::new().read(true).write(false).open(&self.seeds_path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf","max_read_buf_bytes"), file).lines();

                if self.range == (1, 128) {
                    // 如果范围为整个ipv6地址空间范围
                    for line in lines {
                        match line {
                            Ok(addr) => {
                                match Ipv6Addr::from_str(addr.trim()) {
                                    Ok(ipv6) => {
                                        seeds.push(u128::from(ipv6));
                                    }
                                    Err(_) => {
                                        warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr.trim());
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                } else {
                    // 如果指定了初始化范围
                    let init_mask = self.get_init_mask();
                    let mut last_val:u128 = 0;
                    for line in lines {
                        match line {
                            Ok(addr) => {
                                match Ipv6Addr::from_str(addr.trim()) {
                                    Ok(ipv6) => {
                                        let cur_val = u128::from(ipv6) & init_mask;

                                        if cur_val != last_val {
                                            seeds.push(cur_val);
                                            last_val = cur_val;
                                        }
                                    }
                                    Err(_) => {
                                        warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr.trim());
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            Err(_) => {
                error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &self.seeds_path);
            }
        }
        seeds
    }
    
    
}