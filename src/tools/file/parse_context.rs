use std::process::Command;
use log::warn;
use crate::SYS;


/// 解析带有注释的行
pub fn parse_line_with_annotation(line_string: String) -> Option<String> {
    let text_before_annotation = line_string.split(|c| c == '#' || c == ';').next();
    match text_before_annotation {
        None => None,
        Some(t) => {
            let text = t.trim();
            if text.is_empty() {
                None
            } else {
                Some(text.to_string())
            }
        }
    }
}

pub fn count_file_lines(filename: &String) -> Option<u64> {
    let output = Command::new("wc")
        .arg("-l")
        .arg(filename)
        .output()
        .ok()?;  // 使用 `ok()?` 处理可能的错误

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout.split_whitespace().next();  // `split_whitespace` 确保无效空格被忽略

    match lines {
        Some(s) => {
            s.trim().parse::<u64>().ok()  // 使用 `ok()` 处理可能的解析错误
        }
        None => {
            warn!("{} {}", SYS.get_info("warn", "wc_l_failed"), filename);
            None
        }
    }
}



