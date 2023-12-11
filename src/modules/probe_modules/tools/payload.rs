use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::exit;
use log::error;
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};
use crate::SYS;
use crate::tools::file::parse_context::parse_line_with_annotation;


pub fn get_payload(payload_args:Option<String>, file_path:String, seed:u64, min_payload_len:usize, max_payload_len:usize) -> Vec<u8> {

    if let Some(args) = payload_args {

        let option_arg:Vec<&str> = args.split(":").collect();

        if option_arg.len() != 2 { error!("{} {}", SYS.get_info("err", "payload_args_invalid"), args); exit(1) }

        match option_arg[0] {

            "file" => {
                let payload = parse_payload_from_file(file_path, option_arg[1], seed);

                // 如果负载长度 合法
                if  min_payload_len <= payload.len() && payload.len() <= max_payload_len { return payload }
            }

            "bytes" => {
                let payload = parse_payload(option_arg[1], seed);

                // 如果负载长度 合法
                if min_payload_len <= payload.len() && payload.len() <= max_payload_len { return payload }
            }

            /*
            //固定在程序中的 载荷模式
            "native" => {
                // 如果 探测参数是特定字符串, 返回对应 载荷

                match option_arg[1] {
                    "template_1" => {
                        let payload = vec![1, 2, 3, 4];

                        // 如果负载长度 合法
                        if payload.len() <= max_payload_len { return payload }
                    }
                    _ => {}
                }
            }*/
            _ => { error!("{} {}", SYS.get_info("err", "payload_args_invalid"), args); exit(1) }
        }
    } else {
        // 如果不存在 探测参数

        // 如果 没有探测参数, 并且 最小负载数量允许为 0, 返回 空负载向量
        if min_payload_len == 0 { return vec![] }
    }

    // 没有符合长度等限制
    error!("{}", SYS.get_info("err", "payload_invalid"));
    exit(1)
}

fn parse_payload(input:&str, seed:u64) -> Vec<u8> {

    let mut payload =  vec![];

    let input = input.trim();
    if input.starts_with('[') && input.ends_with(']') {

        // 随机数生成器
        let mut rng = StdRng::seed_from_u64(seed);

        let input_s = input.trim_matches(|c| c == '[' || c == ']');
        let input_split = input_s.split(',');

        for byte_str in input_split {
            let byte_str = byte_str.trim();

            let tar_byte:u8;
            if byte_str == "*" {
                // 如果载荷数组中存在 * 标记, 对该字节进行随机填充
                tar_byte = rng.gen();
            } else {
                tar_byte = byte_str.parse().map_err(|_|{
                    error!("{} {}", SYS.get_info("err", "payload_byte_parse_failed"), input);
                    exit(1)
                }).unwrap();
            }

            payload.push(tar_byte);
        }
    } else {
        error!("{} {}", SYS.get_info("err", "payload_byte_parse_failed"), input);
        exit(1)
    }
    payload
}


fn parse_payload_from_file(path:String, target:&str, seed:u64) -> Vec<u8> {

    let path = if cfg!(target_os = "windows") {
        path.replace("/", "\\")
    } else {
        path
    };

    let path = path.trim();

    let list_file = File::open(path).map_err(
        |_| {
            error!("{} {}", SYS.get_info("err", "open_payload_file_failed"), path);
            exit(1)
        }
    ).unwrap();

    let lines = BufReader::new(list_file).lines();
    for line in lines {
        match line {
            // 成功获取到该行
            Ok(l) => {

                // 清除注释和无效行
                match parse_line_with_annotation(l) {

                    Some(template) => {
                        let target_bytes:Vec<&str> = template.split(":").collect();

                        if target_bytes.len() == 2 {
                            if target_bytes[0].trim() == target.trim() {
                                return parse_payload(target_bytes[1], seed)
                            }
                        }
                    },
                    None => {}
                }

            }
            Err(_) => {}
        }
    }
    error!("{} {} {}", SYS.get_info("err", "match_payload_failed"), target, path);  exit(1)
}

