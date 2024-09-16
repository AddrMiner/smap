use std::cmp::min;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::mem::take;
use std::net::Ipv6Addr;
use std::str::FromStr;
use ahash::AHashSet;
use log::{error, warn};
use rand::Rng;
use rand::seq::SliceRandom;
use crate::modules::output_modules::OutputMethod;
use crate::modules::target_iterators::ipv6_aliased_check::IPv6AliaChecker;
use crate::modules::target_iterators::IPv6PrefixTree;
use crate::SYS;

impl IPv6AliaChecker {

    pub fn gen_targets(&mut self) -> Vec<(u32, u128)> {

        // 计算当前轮次需要探测的前缀数量
        let cur_prefixes_len = min(self.prefixes.len(), self.prefixes_len_per_batch);
        if cur_prefixes_len <= 0 { return Vec::with_capacity(0) }

        // 准备常量
        let rand_count = self.rand_count;
        let rand_max = u128::MAX >> self.prefix_len;
        let mut rng = rand::thread_rng();

        // 取出 当前轮次需要进行探测的前缀
        let cur_prefixes:Vec<u128> = self.prefixes.drain(..cur_prefixes_len).collect();

        // 用以存储 探测目标(code, ip)
        let mut tar_ips:Vec<(u32, u128)> = Vec::with_capacity(cur_prefixes_len * rand_count);

        for (index, prefix) in cur_prefixes.iter().enumerate() {
            let cur_index = index as u32;
            for _ in 0..rand_count {
                let rand_num:u128 = rng.gen_range(0..=rand_max);
                let tar_ip = prefix | rand_num;

                tar_ips.push((cur_index, tar_ip));
            }
        }

        // 将所有探测目标进行随机化
        tar_ips.shuffle(&mut rng);

        // 记录 当前前缀列表
        self.cur_prefixes = cur_prefixes;

        tar_ips
    }


    pub fn get_alia_prefixes(&mut self, res:Vec<u8>, alia_prefixes:&mut Vec<u128>, output:&mut Box<dyn OutputMethod>) {
        // 注意: res表示探测结果, 下标表示编码, 值表示编码对应的响应数量
        let cur_prefixes = take(&mut self.cur_prefixes);
        self.cur_prefixes.clear();

        // 取出常量
        let alia_threshold = self.alia_threshold;

        for (prefix, act_addrs_len) in cur_prefixes.into_iter().zip(res.into_iter()) {
            if act_addrs_len >= alia_threshold {
                // 如果 活跃地址数量超过 别名阈限

                // 该前缀为别名前缀
                alia_prefixes.push(prefix);
                output.writer_line(&vec![Ipv6Addr::from(prefix).to_string()]);
            }
        }
    }
    

    pub fn get_alia_addrs(&self, alia_prefixes:AHashSet<u128>, output:&mut Box<dyn OutputMethod>) -> u64 {

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
                        Ok(addr) => {
                            match Ipv6Addr::from_str(addr.trim()) {
                                Ok(ipv6) => {
                                    let addr = u128::from(ipv6);
                                    let prefix = addr & init_mask;

                                    if alia_prefixes.contains(&prefix) {
                                        // 如果当前地址的前缀是 别名前缀
                                        output.writer_line(&vec![Ipv6Addr::from(addr).to_string()]);
                                        aliased_addrs_count += 1;
                                    }
                                }
                                Err(_) => warn!("{} {}", SYS.get_info("warn","file_line_invalid"), addr.trim())
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
    


}