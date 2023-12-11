use std::process::Command;
use log::{warn};
use crate::SYS;

/// 解析带有注释的行
pub fn parse_line_with_annotation(line_string: String) -> Option<String> {


    let text_before_annotation = line_string
                                                .split(|c| c == '#' || c == ';').next();

    match text_before_annotation {
        None => None,
        Some(t) => {

            let text = t.trim();
            if text == "" {
                // 删除无效行
                None
            } else {
                Some(text.to_string())
            }
        }
    }


}


pub fn count_file_lines(filename:&String) -> Option<u64> {

    let none_option:Option<u64> = None;

    let output = Command::new("wc")
        .arg("-l")
        .arg(filename)
        .output()
        .map_err(|_|{
            // 获取行数命令调用失败
            warn!("{} {}", SYS.get_info("warn", "wc_l_failed"), filename);
            return none_option
        }).unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // 按 空格分割, 获取前一部分
    let lines = stdout.split(" ").next();

    match lines {
        Some(s) => {

            let tar_num = s.trim().parse::<u64>().map_err(
                |_|{
                    warn!("{} {}", SYS.get_info("warn", "wc_l_failed"), filename);
                    return none_option
                }
            ).unwrap();

            Some(tar_num)
        }
        None => {
            warn!("{} {}", SYS.get_info("warn", "wc_l_failed"), filename);
            none_option
        }
    }
}



