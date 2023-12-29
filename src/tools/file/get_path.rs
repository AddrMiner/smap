

use std::{env, fs};
use std::process::exit;
use log::error;
use crate::SYS;


/// 获取当前二进制文件的存储目录, 并拼接子路径
pub fn get_current_path(child_path:&str) -> String {

    let mut path = match env::current_exe() {
        Ok(p) => p,
        Err(_) => {
            error!("{}", SYS.get_info("err", "get_install_path_failed"));
            exit(1)
        }
    };

    // 删除 二进制文件路径
    path.pop();
    // 删除 上级目录
    path.pop();

    let filepath = if cfg!(target_os = "windows") {
        child_path.replace("/", "\\")
    } else {
        child_path.to_string()
    };

    let path = path.join(filepath);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| {
            error!("{} {:?}", SYS.get_info("err", "create_cur_parent_path_failed"), &path);
            exit(1)
        }).unwrap();
    }

    match path.to_str() {
        None => {
            error!("{}", SYS.get_info("err", "get_tar_path_failed"));
            exit(1)
        }
        Some(p) => { p.to_string() }
    }
}