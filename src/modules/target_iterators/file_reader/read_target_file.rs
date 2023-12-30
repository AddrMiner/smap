use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek};
use std::process::exit;
use log::error;
use regex::Regex;
use crate::SYS;
use crate::tools::file::parse_context::count_file_lines;

pub struct TargetFileReader {
    pub fallback_bytes:u64,
    pub max_read_buf_bytes:u64,
    pub path:String,
    pub tar_num:Option<u64>,
}

impl TargetFileReader {

    pub fn new(path:&String) -> Self {

        Self {
            fallback_bytes: SYS.get_conf("conf", "fallback_bytes"),
            max_read_buf_bytes: SYS.get_conf("conf","max_read_buf_bytes"),
            path: path.to_string(),
            tar_num: None
        }
    }

    /// 获取真正的起始索引
    pub fn get_start(&self, start_index:u64, end_index:u64) -> (bool, u64){

        // 获取补全首行
        let first_line = self.get_full_first_line(start_index);

        match OpenOptions::new().read(true).write(false).open(&self.path) {

            Ok(mut file) => {

                // 将文件指针指向 开始索引 的位置
                file.seek(std::io::SeekFrom::Start(start_index)).map_err(
                    |_| {
                        error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), start_index, self.path);
                        exit(1)
                    }
                ).unwrap();

                // 创建缓冲区读取器
                let mut reader = BufReader::new(file);
                let mut buffer= String::new();

                // 读取 原生(非补全)的 首行
                let offset = reader.read_line(&mut buffer).map_err(
                    |_| {
                        error!("{} {}", SYS.get_info("err", "read_target_line_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();

                if buffer.trim() == first_line {
                    // 如果 补全的首行 和 非补全的首行一致

                    //       [ 1, 2, 3...  ]
                    // start [ 1, 2, 3...  ]

                    (true, start_index)
                } else {
                    // 如果 补全的首行 和 非补全的首行 不一致

                    //       [ 1, 2, 3...  ]
                    //       [ 1, start, 3...  ] new_start

                    let new_start_index = start_index + (offset as u64);
                    return if new_start_index > end_index {

                        // 新的开始索引 已经到下一个线程的区域
                        (false, 0)
                    } else {
                        (true, new_start_index)
                    }
                }
            }

            Err(_) => {
                error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                exit(1)
            }
        }

    }


    fn get_full_first_line(&self, start_index:u64) -> String {

        // 获取回退索引
        let mut fallback_index = if start_index >= self.fallback_bytes {
            // 如果 start_index - fallback_bytes 得到的索引值 大于等于 0
            start_index - self.fallback_bytes
        } else {
            // 如果目标索引 小于 0, 直接设为 0
            0
        };

        match OpenOptions::new().read(true).write(false).open(&self.path) {
            Ok(mut file) => {

                // 将文件指针指向 开始索引之前 fallback_index 字节的位置
                file.seek(std::io::SeekFrom::Start(fallback_index)).map_err(
                    |_| {
                        error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), start_index, self.path);
                        exit(1)
                    }
                ).unwrap();

                // 创建缓冲区读取器
                let mut reader = BufReader::new(file);
                let mut buffer= String::new();

                // 按行读取
                loop {
                    let bytes = reader.read_line(&mut buffer).map_err(
                        |_| {
                            error!("{} {}", SYS.get_info("err", "read_target_line_failed"), self.path);
                            exit(1)
                        }
                    ).unwrap();
                    fallback_index += bytes as u64;

                    if bytes == 0 {
                        // 已经到文件末尾
                        // 在到达 开始索引之前就到了文件末尾, 意味着发生错误
                        error!("{} {}", SYS.get_info("err", "target_file_index_invalid"), self.path);
                        exit(1)
                    }

                    if fallback_index > start_index {
                        // 已经读取过 索引为 start_index 的字节
                        return buffer.trim().to_string()
                    }
                    buffer.clear();
                }
            }
            Err(_) => {
                error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                exit(1)
            }
        }
    }



    /// 0: 起始字节索引, 1:最后字节索引, 2:局部目标数量(字节数 or 目标数量)
    /// 注意: 索引左右均为闭区间
    pub fn assign(&self, thread_num:u64) -> Vec<(u64, u64, u64)> {

        let mut assign_vec;

        let f = File::open(&self.path).map_err(
            |_| {
                error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                exit(1)
            }
        ).unwrap();

        if let Some(tar_num) = self.tar_num {
            // 如果存在 有效目标数量, 按照 有效目标数量进行分割

            assign_vec = vec![];

            let mut buffer = String::new();
            // 注意: 这里可能需要仔细检查
            let mut reader = BufReader::with_capacity(self.max_read_buf_bytes as usize, f);

            let assigned_num = Self::assign_by_num(tar_num, thread_num);

            let mut pre_last_add_one:u64 = 0;
            for cur_num in assigned_num.into_iter() {

                // 计算 一个范围内的字节数
                let mut cur_bytes_num = 0;
                for _ in 0..cur_num {
                    let bytes_read = reader.read_line(&mut buffer).unwrap();
                    if bytes_read == 0 {
                        break;
                    }
                    buffer.clear();

                    cur_bytes_num += bytes_read as u64;
                }

                // 一个范围的最后字节索引
                let cur_last = pre_last_add_one + cur_bytes_num - 1;

                if pre_last_add_one > cur_last {
                    // 如果范围的 起始字节索引 大于 最后字节索引
                    error!("{}", SYS.get_info("err", "assign_by_num_failed"));
                    exit(1)
                }

                assign_vec.push((pre_last_add_one, cur_last, cur_num));
                pre_last_add_one += cur_bytes_num;
            }

        } else {
            // 如果不存在有效目标数量, 使用 字节大小进行分割

            // 获取文件元数据
            let metadata = f.metadata().map_err(
                |_| {
                    error!("{} {}", SYS.get_info("err", "get_target_file_info_failed"), self.path);
                    exit(1)
                }
            ).unwrap();

            assign_vec = Self::assign_by_bytes(metadata.len(), thread_num);

        }
        assign_vec
    }


    fn assign_by_num(total_num:u64, thread_num:u64) -> Vec<u64> {
        let mut targets_ranges = vec![];

        let base_num = total_num / thread_num;
        let mut remain_num = total_num % thread_num;

        for _ in 0..thread_num {

            let tar_num;
            if remain_num > 0 {
                tar_num = base_num + 1;
                remain_num -= 1;
            } else {
                tar_num = base_num;
            }

            if tar_num < 1 {
                return targets_ranges
            }
            targets_ranges.push(tar_num);
        }
        targets_ranges
    }

    fn assign_by_bytes(total_bytes:u64, thread_num:u64) -> Vec<(u64, u64, u64)> {

        let mut assign_vec = vec![];

        let base_size = total_bytes / thread_num;
        let mut left_size = total_bytes % thread_num;

        let mut pre_last_add_one: u64 = 0;
        for _ in 0..thread_num {
            let last_byte;
            if left_size > 0 {
                last_byte = pre_last_add_one + base_size;
                assign_vec.push((pre_last_add_one, last_byte, base_size + 1));
                left_size -= 1;
            } else {
                last_byte = pre_last_add_one + base_size - 1;
                assign_vec.push((pre_last_add_one, last_byte, base_size));
            }

            pre_last_add_one = last_byte + 1;
        }

        assign_vec
    }


    /// 从 ipv4目标文件名 中提取附加信息
    /// 0: 目标数量  1: 范围是否有效 2: 最小ip 3: 最大ip
    pub fn parse_file_info_v4(&mut self) -> (Option<u64>, bool, u32, u32) {

        // 提取目标数量
        let tar_num;
        {
            let num_regex = Regex::new(r"_num(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(num_match) = num_regex.captures(&self.path) {
                let num = num_match[1].parse::<u64>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                tar_num = Some(num);
            } else {
                // 如果未匹配到 总数量字段
                if cfg!(target_os = "windows") {
                    // 如果当前系统为 windows
                    tar_num = None;
                } else {
                    tar_num = count_file_lines(&self.path);
                }
            }
        }

        self.tar_num = tar_num;

        // 提取 最小 和 最大 地址, 用于优化 拦截器 和 其它可能利用该信息的模块
        // 注意: 这里的所有提示信息均被视为 严格有效, 将尽可能地缩小范围
        // 注意: 这里的提示信息不对实际探测的地址产生约束作用, 但会根据提示信息优化 拦截器的约束条件 和 其它模块
        let min_ip;
        let max_ip;
        let mut min_ip_flag = false;
        let mut max_ip_flag = false;
        {

            let min_regex = Regex::new(r"_min(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(min_match) = min_regex.captures(&self.path) {
                let min = min_match[1].parse::<u32>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                min_ip = min;
                min_ip_flag = true;
            } else {
                min_ip = 0;
            }


            let max_regex = Regex::new(r"_max(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(max_match) = max_regex.captures(&self.path) {
                let max = max_match[1].parse::<u32>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                max_ip = max;
                max_ip_flag = true;
            } else {
                max_ip = 0;
            }
        }

        if min_ip_flag && max_ip_flag {
            // 只有 最小ip 和 最大ip 都存在时, 范围才有效
            (tar_num, true, min_ip, max_ip)
        } else {
            (tar_num, false, min_ip, max_ip)
        }

    }



    /// 从 ipv6目标文件名 中提取附加信息
    /// 0: 目标数量  1: 范围是否有效 2: 最小ip 3: 最大ip
    pub fn parse_file_info_v6(&mut self) -> (Option<u64>, bool, u128, u128) {

        // 提取目标数量
        let tar_num;
        {
            let num_regex = Regex::new(r"_num(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(num_match) = num_regex.captures(&self.path) {
                let num = num_match[1].parse::<u64>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                tar_num = Some(num);
            } else {

                // 如果未匹配到 总数量字段
                if cfg!(target_os = "windows") {
                    // 如果当前系统为 windows
                    tar_num = None;
                } else {
                    tar_num = count_file_lines(&self.path);
                }
            }
        }

        self.tar_num = tar_num;

        // 提取 最小 和 最大 地址, 用于优化 拦截器 和 其它可能利用该信息的模块
        // 注意: 这里的所有提示信息均被视为 严格有效, 将尽可能地缩小范围
        // 注意: 这里的提示信息不对实际探测的地址产生约束作用, 但会根据提示信息优化 拦截器的约束条件 和 其它模块
        let min_ip;
        let max_ip;
        let mut min_ip_flag = false;
        let mut max_ip_flag = false;
        {

            let min_regex = Regex::new(r"_min(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(min_match) = min_regex.captures(&self.path) {
                let min = min_match[1].parse::<u128>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                min_ip = min;
                min_ip_flag = true;
            } else {
                min_ip = 0;
            }


            let max_regex = Regex::new(r"_max(\d+)_").map_err(
                |_|{
                    error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                    exit(1)
                }
            ).unwrap();
            if let Some(max_match) = max_regex.captures(&self.path) {
                let max = max_match[1].parse::<u128>().map_err(
                    |_|{
                        error!("{} {}", SYS.get_info("err", "parse_targets_file_name_failed"), self.path);
                        exit(1)
                    }
                ).unwrap();
                max_ip = max;
                max_ip_flag = true;
            } else {
                max_ip = 0;
            }
        }

        if min_ip_flag && max_ip_flag {
            // 只有 最小ip 和 最大ip 都存在时, 范围才有效
            (tar_num, true, min_ip, max_ip)
        } else {
            (tar_num, false, min_ip, max_ip)
        }

    }


}




