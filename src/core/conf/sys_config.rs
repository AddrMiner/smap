//! 编译时读取 系统配置信息 以初始化 系统级关键参数 和 提示信息。
//! 在编译前修改对应文件即可实现修改 程序语言, 关键底层配置 等。

use std::process::exit;
use std::str::FromStr;
use configparser::ini::Ini;

pub struct SysConf {
    info:Ini
}


impl SysConf {

    /// 编译时 读取并解析 系统配置文件
    pub fn new() -> SysConf {

        // 这里的路径是从当前 rs 文件开始计算的
        let sys_text = include_str!("../../../sys_conf.ini");

        let sys_text = String::from(sys_text);

        // 区分大小写地解析系统配置文件
        let mut info = Ini::new_cs();
        info.read(sys_text).map_err(
            |_|{
                eprintln!("can not open sys_conf.ini");
                exit(1)
            }).unwrap();


        SysConf{ info }
    }

    /// 获取 系统提示 信息, 如果无法获取到目标值, 就报错
    pub fn get_info(&self, section:&str, key:&str) -> String {

        if let Some(info) = self.info.get(section,key) {
            info
        }else {
            eprintln!("Failed to get system configuration information!\nsection:{}    key:{}", section, key);
            exit(1)
        }

    }

    /// 获取 系统信息, 如果无法获取到目标值, 就返回空
    pub fn get_info_without_panic(&self, section:&str, key:&str) -> Option<String> {
        self.info.get(section,key)
    }


    /// 获取 系统配置 信息
    pub fn get_conf<T : FromStr> (&self, section:&str, key:&str) -> T {

        if let Some(val) = self.info.get(section, key) {

            let res = val.parse::<T>();

            match res {
                Ok(r) => r,
                Err(_) => {
                    eprintln!("Failed to convert system configuration information type!\nsection:{}    key:{}", section, key);
                    exit(1)
                }
            }

        }else {
            eprintln!("Failed to get system configuration information!\nsection:{}    key:{}", section, key);
            exit(1)
        }

    }



}