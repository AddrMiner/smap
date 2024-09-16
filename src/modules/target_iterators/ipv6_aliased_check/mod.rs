mod method;

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashSet;
use log::{error, warn};
use rand::prelude::SliceRandom;
use crate::modules::target_iterators::IPv6PrefixTree;
use crate::SYS;


#[derive(Clone)]
pub struct IPv6AliaChecker {
    pub path:String,

    // 前缀长度
    pub prefix_len:u8,
    // 每个前缀生成随机地址的数量
    pub rand_count:usize,
    // 前缀总量
    pub prefix_count:usize,
    
    // 别名阀限, 任何前缀不同相应地址数量超过该阀限将被视为别名
    pub alia_threshold:u8,
    
    // 前缀列表(保存所有未检测前缀)
    pub prefixes:Vec<u128>,
    // 每批次探测的前缀数量
    pub prefixes_len_per_batch:usize,
    
    // 当前轮次探测的前缀列表
    pub cur_prefixes:Vec<u128>,
}


impl IPv6AliaChecker {


    pub fn new(path:String, prefix_len:u8, prefix_count:usize, rand_count:usize, 
               alia_ratio:f64, prefixes_len_per_batch:usize) -> Self {

        if prefix_len >= 128 {
            // 前缀长度不能大于等于128
            error!("{}", SYS.get_info("err", "ipv6_alia_prefix_len_err"));
            exit(1)
        }
        
        if rand_count > (u8::MAX as usize) {
            // 如果 每个前缀生成随机地址的数量 超过一个字节能表示的值
            error!("{}", SYS.get_info("err", "ipv6_alia_rand_count_err"));
            exit(1)
        }

        if prefixes_len_per_batch >= (u32::MAX as usize) {
            // 如果前缀总量超过表示范围
            error!("{}", SYS.get_info("err", "prefixes_len_per_batch_over"));
            exit(1)
        }
        
        let alia_threshold = ((rand_count as f64) * alia_ratio) as u8;
        if alia_threshold < 1 || (alia_threshold as usize) > rand_count {
            // 别名阀限必须大于等于1, 且不能大于 每前缀随机地址数量
            error!("{}", SYS.get_info("err", "alia_threshold_err"));
            exit(1)
        }

        Self {
            prefix_len,
            rand_count,

            prefix_count,
            alia_threshold,
            prefixes: Vec::new(),
            
            path,
            prefixes_len_per_batch,
            cur_prefixes: Vec::new(),
        }
    }

    
    pub fn init(&mut self) {
        self.prefixes = Self::get_prefixes(&self.path, self.prefix_len, self.prefix_count);
    }

    pub fn get_prefixes(path:&String, prefix_len:u8, prefix_count:usize) -> Vec<u128> {
        // 所有不重复的前缀
        let mut prefixes:AHashSet<u128> = AHashSet::with_capacity(prefix_count);

        // 获取前缀初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(prefix_len);

        match OpenOptions::new().read(true).write(false).open(path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf", "max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(addr) => {
                            match Ipv6Addr::from_str(addr.trim()) {
                                Ok(ipv6) => {
                                    prefixes.insert(u128::from(ipv6) & init_mask);
                                }
                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr.trim())
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), path)
        }

        let mut prefixes_vec:Vec<u128>= prefixes.into_iter().collect();

        let mut rng = rand::thread_rng();
        prefixes_vec.shuffle(&mut rng);
        
        prefixes_vec
    }
}