use std::cmp::min;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek};
use std::net::{Ipv6Addr};
use std::str::FromStr;
use std::process::exit;
use log::{error, warn};
use crate::modules::target_iterators::file_reader::read_target_file::TargetFileReader;
use crate::SYS;

pub struct Ipv6FileReader {

    pub current_index:u64,
    pub end_index:u64,
    pub reader:BufReader<File>,

    // 目标端口是否从文件读取
    pub tar_port_from_file:bool,

    // 当目标端口为 0 时, 该项无效, 将从文件读取
    pub tar_port:u16,
}

impl Ipv6FileReader {


    /// 0: 是否为最终值  1:当前值是否有效   2:ip   3:端口
    pub fn get_next_ip_port_v6(&mut self) -> (bool, bool, u128, u16) {

        let mut current_line = String::new();
        let bytes = self.reader.read_line(&mut current_line).map_err(
            |_|{
                error!("{}", SYS.get_info("err", "read_cur_target_failed"));
                exit(1)
            }
        ).unwrap();
        if bytes == 0 {
            // 到文件末尾, 说明是最后一个, 而且是无效值
            return (false, false, 0, 0)
        }

        // 解析目标地址, 端口
        let ip_port = self.get_ip_port(current_line);

        // 更新字节索引
        self.current_index += bytes as u64;
        if self.current_index > self.end_index {

            // 如果索引超出范围, 说明是最后一个
            if ip_port.0 {
                // 如果 ip port 有效
                (false, true, ip_port.1, ip_port.2)
            } else {
                // 如果ip port无效
                (false, false, 0, 0)
            }
        }else {
            // 如果索引没有超出范围, 说明不是最后一个
            if ip_port.0 {
                // 如果 ip port 有效
                (true, true, ip_port.1, ip_port.2)
            } else {
                // 如果ip port无效
                (true, false, 0, 0)
            }
        }
    }



    fn get_ip_port(&self, line:String) -> (bool, u128, u16) {

        let s:Vec<&str> = line.split('|').collect();

        if self.tar_port_from_file {
            // 从文件中获取目标端口
            if s.len() == 2 {
                match Ipv6Addr::from_str(s[0].trim()) {
                    Ok(ipv6) => {
                        match u16::from_str(s[1].trim()) {
                            Ok(port) => {
                                // 如果 ip 和 port 转换成功
                                return (true, u128::from(ipv6), port)
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
            } else if s.len() == 1 {
                // 如果是单个ip
                match Ipv6Addr::from_str(s[0].trim()) {
                    Ok(ipv6) => {
                        return (true, u128::from(ipv6), 0)
                    }
                    Err(_) => {}
                }
            }
        } else {
            // 指定端口
            match Ipv6Addr::from_str(s[0].trim()) {
                Ok(ipv6) => {
                    return (true, u128::from(ipv6), self.tar_port)
                }
                Err(_) => {}
            }
        }

        warn!("{} {}", SYS.get_info("warn","file_line_invalid"), line.trim());
        (false, 0, 0)
    }


}


impl TargetFileReader {

    pub fn get_ipv6_file_reader(&self, assigned_targets:&(u64,u64,u64), cur_tar_port:u16) -> Option<Ipv6FileReader> {

        if let Some(_) = self.tar_num {
            // 存在目标数量, 按照目标数量进行分配

            match OpenOptions::new().read(true).write(false).open(&self.path) {
                Ok(mut file) => {

                    // 将文件指针指向 开始索引(局部) 的位置
                    file.seek(std::io::SeekFrom::Start(assigned_targets.0)).map_err(
                        |_| {
                            error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), assigned_targets.0, self.path);
                            exit(1)
                        }
                    ).unwrap();

                    return Some(
                        Ipv6FileReader {
                            current_index: assigned_targets.0,
                            end_index: assigned_targets.1,
                            reader: BufReader::with_capacity(self.max_read_buf_bytes as usize, file),

                            tar_port_from_file: cur_tar_port == 0,
                            tar_port: cur_tar_port,
                        }
                    )
                }
                Err(_) => {
                    error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                    exit(1)
                }
            }

        } else {
            // 不存在目标数量, 按照字节数进行分配

            let (valid, start_index) = self.get_start(assigned_targets.0, assigned_targets.1);

            if valid {
                match OpenOptions::new().read(true).write(false).open(&self.path) {
                    Ok(mut file) => {

                        // 将文件指针指向 开始索引(局部) 的位置
                        file.seek(std::io::SeekFrom::Start(start_index)).map_err(
                            |_| {
                                error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), start_index, self.path);
                                exit(1)
                            }
                        ).unwrap();

                        // 取 设定的最大缓冲区大小(字节数), 当前被分配区域大小(字节) + 回退字节数, 中的 最小值 作为缓冲区大小
                        let buf_capacity = min(self.max_read_buf_bytes,
                                               assigned_targets.2 + self.fallback_bytes) as usize;

                        return Some(
                            Ipv6FileReader {
                                current_index: start_index,
                                end_index: assigned_targets.1,
                                reader: BufReader::with_capacity(buf_capacity, file),

                                tar_port_from_file: cur_tar_port == 0,
                                tar_port: cur_tar_port,
                            }
                        )
                    }
                    Err(_) => {
                        error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                        exit(1)
                    }
                }
            }
            None
        }
    }
}