use std::cmp::min;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::mem::take;
use std::net::Ipv6Addr;
use std::str::FromStr;
use ahash::AHashSet;
use log::{error, info, warn};
use rand::{rng, Rng};
use rand::seq::SliceRandom;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::ipv6_aliased_check::IPv6AliaChecker;
use crate::modules::target_iterators::IPv6PrefixTree;
use crate::SYS;

impl IPv6AliaChecker {

    pub fn gen_targets(&mut self) -> Vec<(Vec<u8>, u16, u128)> {

        // 计算当前轮次需要探测的前缀数量
        let cur_prefixes_len = min(self.prefixes.len(), self.prefixes_len_per_batch);
        if cur_prefixes_len <= 0 { return Vec::with_capacity(0) }

        // 准备常量
        let rand_count = self.rand_count;
        let rand_max = u128::MAX >> self.prefix_len;
        let mut rng = rng();

        // 取出 当前轮次需要进行探测的前缀
        let cur_prefixes_port:Vec<(u128, u16)> = self.prefixes.drain(..cur_prefixes_len).collect();

        // 用以存储 探测目标(code, ip, port)
        let mut targets:Vec<(Vec<u8>, u16, u128)> = Vec::with_capacity(cur_prefixes_len * rand_count);

        
        let scan_flag = self.scan_flag;
        for (index, (prefix, port)) in cur_prefixes_port.iter().enumerate() {
            let cur_index = index as u32;
            let mut cur_code = cur_index.to_be_bytes();
            cur_code[0] = scan_flag;
            let cur_code:Vec<u8> = cur_code.to_vec();
            
            for _ in 0..rand_count {
                let rand_num:u128 = rng.random_range(0..=rand_max);
                let tar_ip = prefix | rand_num;

                targets.push((cur_code.clone(), *port, tar_ip));
            }
        }

        // 将所有探测目标进行随机化
        targets.shuffle(&mut rng);

        // 记录 当前前缀列表
        self.cur_prefixes_port = cur_prefixes_port;

        targets
    }


    pub fn get_alia_prefixes(&mut self, res:Vec<u8>, aliased_prefixes:&mut Vec<u128>, output:&mut Box<dyn OutputMethod>) {
        // 注意: res表示探测结果, 下标表示编码, 值表示编码对应的响应数量
        let cur_prefixes_port = take(&mut self.cur_prefixes_port);
        self.cur_prefixes_port.clear();

        // 取出常量
        let aliased_threshold = self.aliased_threshold;

        for ((prefix, _), act_addrs_len) in cur_prefixes_port.into_iter().zip(res.into_iter()) {
            if act_addrs_len >= aliased_threshold {
                // 如果 活跃地址数量超过 别名阈限

                // 该前缀为别名前缀
                aliased_prefixes.push(prefix);
                output.writer_line(&vec![Ipv6Addr::from(prefix).to_string()]);
            }
        }
    }
    

    pub fn get_alia_addrs(&self, alia_prefixes:&AHashSet<u128>, output:&mut Box<dyn OutputMethod>) -> u64 {
        // 打印别名地址标识
        output.writer_line(&vec![String::from("ipv6_aliased_addrs")]);

        // 获取前缀初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(self.prefix_len);

        let mut aliased_addrs_count = 0u64;
        match OpenOptions::new().read(true).write(false).open(&self.path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf", "max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(addr_port_) => {

                            let addr_port: Vec<&str> = addr_port_.split(|c| c == '|' || c == ',').collect();

                            let cur_prefix = match Ipv6Addr::from_str(addr_port[0].trim()) {
                                Ok(ipv6) => {
                                    u128::from(ipv6) & init_mask
                                }
                                Err(_) => { warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_.trim()); continue }
                            };

                            if alia_prefixes.contains(&cur_prefix) {
                                // 如果当前地址的前缀是 别名前缀
                                
                                if addr_port.len() == 1 {
                                    output.writer_line(&vec![Ipv6Addr::from(cur_prefix).to_string()]);
                                } else {
                                    output.writer_line(&vec![Ipv6Addr::from(cur_prefix).to_string(), addr_port[1].to_string()]);
                                }
                                aliased_addrs_count += 1;
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &self.path)
        }
        aliased_addrs_count
    }
    
    
    pub fn save_not_aliased_records(&self, save_path:&str, alia_prefixes:&AHashSet<u128>){

        let file = OpenOptions::new()
            .create(true)     // 如果文件不存在则创建
            .write(true)      // 使用写入模式(会覆盖已有内容)
            .truncate(true)   // 打开文件时清空已有内容
            .open(save_path)
            .unwrap();
        // 添加缓冲写入器
        let mut writer = BufWriter::with_capacity(1024 * 1024 * 256, file);


        // 获取前缀初始化掩码
        let init_mask = IPv6PrefixTree::get_init_mask(self.prefix_len);

        let mut not_aliased_records_count = 0u64;
        match OpenOptions::new().read(true).write(false).open(&self.path) {
            Ok(file) => {
                // 生成读取缓冲区   注意后续调整缓冲区大小
                let lines = BufReader::with_capacity(SYS.get_conf("conf", "max_read_buf_bytes"), file).lines();

                for line in lines {
                    match line {
                        Ok(addr_port_) => {

                            let addr_port: Vec<&str> = addr_port_.split(|c| c == '|' || c == ',').collect();

                            let cur_prefix = match Ipv6Addr::from_str(addr_port[0].trim()) {
                                Ok(ipv6) => {
                                    u128::from(ipv6) & init_mask
                                }
                                Err(_) => { warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr_port_.trim()); continue }
                            };

                            if !alia_prefixes.contains(&cur_prefix) {
                                // 如果当前地址的前缀 不是 别名前缀

                                writeln!(writer, "{}", addr_port_).unwrap();
                                not_aliased_records_count += 1;
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), &self.path)
        }

        // 确保所有数据都被写入磁盘
        writer.flush().unwrap();
        
        info!("{} {}", SYS.get_info("info", "not_alia_records_count"), not_aliased_records_count);
    }

    pub fn save_aliased_prefixes_64_records(save_path:&str, alia_prefixes:AHashSet<u64>){
        info!("{} {}", SYS.get_info("info", "aliased_prefixes_count"), alia_prefixes.len());

        let file = OpenOptions::new()
            .create(true)     // 如果文件不存在则创建
            .write(true)      // 使用写入模式(会覆盖已有内容)
            .truncate(true)   // 打开文件时清空已有内容
            .open(save_path)
            .unwrap();
        // 添加缓冲写入器
        let mut writer = BufWriter::with_capacity(1024 * 1024 * 32, file);

        for cur_prefix in alia_prefixes.into_iter() {
            let cur_prefix_u128 = (cur_prefix as u128) << 64;
            writeln!(writer, "{}/64", Ipv6Addr::from(cur_prefix_u128)).unwrap();
        }

        // 确保所有数据都被写入磁盘
        writer.flush().unwrap();
    }
}