mod method;

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::process::exit;
use std::str::FromStr;
use ahash::AHashMap;
use log::{error, warn};
use rand::prelude::SliceRandom;
use rand::rng;
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
    pub aliased_threshold:u8,
    
    // 前缀列表(保存所有未检测前缀, 及其对应端口)
    pub prefixes:Vec<(u128, u16)>,
    // 每批次探测的前缀数量
    pub prefixes_len_per_batch:usize,
    
    // 当前轮次探测的前缀列表
    pub cur_prefixes_port:Vec<(u128, u16)>,
    
    // 扫描标志, 用来区分不同轮次的探测
    pub scan_flag:u8,
    
    pub not_aliased_records_path:Option<String>,
    
}


impl IPv6AliaChecker {


    pub fn new(path:String, prefix_len:u8, prefix_count:usize, rand_count:usize,
               aliased_threshold:f64, prefixes_len_per_batch:usize, not_aliased_records_path:String) -> Self {

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

        if prefixes_len_per_batch >= ((u32::MAX >> 8) as usize) {
            // 如果前缀总量超过表示范围
            error!("{}", SYS.get_info("err", "prefixes_len_per_batch_over"));
            exit(1)
        }
        
        let aliased_threshold = ((rand_count as f64) * aliased_threshold) as u8;
        if aliased_threshold < 1 || (aliased_threshold as usize) > rand_count {
            // 别名阀限必须大于等于1, 且不能大于 每前缀随机地址数量
            error!("{}", SYS.get_info("err", "alia_threshold_err"));
            exit(1)
        }

        let not_aliased_records_path = not_aliased_records_path.trim();
        let not_aliased_records_path = if not_aliased_records_path == "" { None }
        else { Some(not_aliased_records_path.to_string()) };

        Self {
            prefix_len,
            rand_count,

            prefix_count,
            aliased_threshold,
            prefixes: Vec::new(),
            
            path,
            prefixes_len_per_batch,
            cur_prefixes_port: Vec::new(),
            
            scan_flag: 1,
            not_aliased_records_path,
        }
    }
    
    pub fn change_scan_flag(&mut self){
        let next_scan_flag = ((self.scan_flag as u16) + 1) % 254;

        if next_scan_flag == 0 {
            self.scan_flag = 1;
        } else {
            self.scan_flag = next_scan_flag as u8;
        }
    }

    
    pub fn init(&mut self) {
        self.prefixes = Self::get_prefixes(&self.path, self.prefix_len, self.prefix_count);
    }

    pub fn get_prefixes(path:&String, prefix_len:u8, prefix_count:usize) -> Vec<(u128, u16)> {
        // 所有不重复的 <前缀, 端口>, 前缀唯一
        let mut prefixes_port:AHashMap<u128, u16> = AHashMap::with_capacity(prefix_count);

        // 获取前缀初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(prefix_len);

        match OpenOptions::new().read(true).write(false).open(path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf", "max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(addr_port_) => {
                            let addr_port: Vec<&str> = addr_port_.split(|c| c == '|' || c == ',').collect();
                            
                            let cut_prefix = match Ipv6Addr::from_str(addr_port[0].trim()) {
                                Ok(ipv6) => {
                                    u128::from(ipv6) & init_mask
                                }
                                Err(_) => { warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_.trim()); continue }
                            };
                            
                            let cur_port = if addr_port.len() == 1 { 0 } 
                            else { 
                                match u16::from_str(addr_port[1].trim()) {
                                    Ok(p) => p,
                                    Err(_) => { warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_.trim()); continue }
                                }
                            };
                            
                            prefixes_port.insert(cut_prefix, cur_port);
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), path)
        }

        let mut prefixes_vec:Vec<(u128, u16)>= prefixes_port.into_iter().collect();

        let mut rng = rng();
        prefixes_vec.shuffle(&mut rng);
        
        prefixes_vec
    }
}