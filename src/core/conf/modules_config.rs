//! 各个模块的通用配置器

use std::process::exit;
use std::str::FromStr;
use ahash::AHashMap;
use log::error;
use crate::SYS;

#[derive(Clone)]
pub struct ModuleConf{

    conf:AHashMap<String, String>,
}


impl ModuleConf {

    /// 模块参数配置器生成
    #[allow(dead_code)]
    pub fn new(parameter_num:usize) -> ModuleConf {

        ModuleConf {
            conf: AHashMap::with_capacity(parameter_num),
        }

    }

    /// 添加 参数字段 和 值
    #[allow(dead_code)]
    pub fn add_conf(&mut self, parameter:String, val:String){
        self.conf.insert(parameter, val);
    }

    /// 解析自定义参数, 注意: 如果附加参数中包含和传入参数中相同的键, 其值将被替换为附加参数中对应的值
    pub fn new_from_vec_args(args:&Vec<String>, additional_parameters:Vec<String>) -> Self {

        let mut conf:AHashMap<String, String> = AHashMap::with_capacity(args.len());

        for arg in args {

            let para_val:Vec<&str> = arg.split("=").collect();

            if para_val.len() != 2 {
                // 如果 参数 不合法, 即不符合  para=val
                error!("{}", SYS.get_info("err", "mod_arg_invalid"));
                exit(1)
            }

            conf.insert(para_val[0].to_string(), para_val[1].to_string());
        }

        for arg in additional_parameters {

            let para_val:Vec<&str> = arg.split("=").collect();

            if para_val.len() != 2 {
                // 如果 参数 不合法, 即不符合  para=val
                error!("{}", SYS.get_info("err", "mod_arg_invalid"));
                exit(1)
            }

            conf.insert(para_val[0].to_string(), para_val[1].to_string());
        }

        Self { conf }
    }


    /// 解析给定类型的参数
    /// # examples
    /// let c:u32 = conf.get_conf(&String::from("para"));
    #[allow(dead_code)]
    pub fn get_conf<T : FromStr>(&self, parameter:&String) -> T {

        let res_str = match self.conf.get(parameter) {
            None => {
                error!("{} {}", SYS.get_info("err","get_parameter_failed"), parameter);
                exit(1)
            }
            Some(v) => v.to_string()
        };

        let res = res_str.parse::<T>();

        match res {
            Ok(r) => r,
            Err(_) => {
                error!("{} {}", SYS.get_info("err","convert_parameter_failed"), parameter);
                exit(1)
            }
        }

    }

    /// 先尝试从 自定义参数 中查找对应配置, 如果失败会 尝试从 系统配置 查找
    pub fn get_conf_or_from_sys<T : FromStr>(&self, parameter:&String) -> T {

        let res_str = match self.conf.get(parameter) {
            None => {
                match SYS.get_info_without_panic("conf", parameter) {
                    None => {
                        error!("{} {}", SYS.get_info("err","get_parameter_failed"), parameter);
                        exit(1)
                    }
                    Some(v) => v
                }
            }
            Some(v) => v.to_string()
        };

        let res = res_str.parse::<T>();

        match res {
            Ok(r) => r,
            Err(_) => {
                error!("{} {}", SYS.get_info("err","convert_parameter_failed"), parameter);
                exit(1)
            }
        }

    }


    pub fn get_info(&self, parameter:&String) -> Option<String> {

        match self.conf.get(parameter) {
            None => {
                None
            }
            Some(v) => Some(v.to_string())
        }

    }


}
