use std::fs::{File};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr};
use std::str::FromStr;
use std::process::exit;
use log::{error, warn};
use crate::modules::target_iterators::Ipv4IterFP;
use crate::SYS;

pub struct Ipv4FileReader {

    pub current_index:u64,
    pub end_index:u64,
    pub reader:BufReader<File>,

    // 目标端口是否从文件读取
    pub tar_port_from_file:bool,

    // 当目标端口为 0 时, 该项无效, 将从文件读取
    pub tar_port:u16,
}

impl Ipv4FileReader {

    fn get_ip_port(&self, line:String) -> (bool, u32, u16) {

        let s:Vec<&str> = line.split('|').collect();

        if self.tar_port_from_file {
            // 从文件中获取目标端口
            if s.len() == 2 {
                match Ipv4Addr::from_str(s[0].trim()) {
                    Ok(ipv4) => {
                        match u16::from_str(s[1].trim()) {
                            Ok(port) => {
                                // 如果 ip 和 port 转换成功
                                return (true, u32::from(ipv4), port)
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
            } else if s.len() == 1 {
                // 如果是单个ip
                match Ipv4Addr::from_str(s[0].trim()) {
                    Ok(ipv4) => {
                        return (true, u32::from(ipv4), 0)
                    }
                    Err(_) => {}
                }
            }
        } else {
            // 指定端口
            match Ipv4Addr::from_str(s[0].trim()) {
                Ok(ipv6) => {
                    return (true, u32::from(ipv6), self.tar_port)
                }
                Err(_) => {}
            }
        }

        warn!("{} {}", SYS.get_info("warn","file_line_invalid"), line.trim());
        (false, 0, 0)
    }

}

impl Ipv4IterFP for Ipv4FileReader {
    fn get_next_ip_port(&mut self) -> (bool, bool, u32, u16) {
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
        } else {
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
}

