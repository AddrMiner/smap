use std::process::exit;
use log::error;
use crate::core::conf::modules_config::ModuleConf;
pub use crate::modules::output_modules::csv::Csv;
use crate::SYS;

mod csv;



/// 激活的 输出模块名称
pub const OUTPUT_MODS: [&str; 1] = ["csv"];

impl OutputMod {
    pub fn new(name: &str, _conf:Option<ModuleConf>, output_file:&Option<String>, is_ipv6:bool) -> OutputMod {   // 传递出去一个实现了输出模块方法的 struct

        if !OUTPUT_MODS.contains(&name) {   // 激活检查
            error!("{}", SYS.get_info("err", "output_mod_not_exist"));
            exit(1);
        }

        
        // 警告: 输出模块将截断现有目标文件(定义输出模块时, 目标文件将置空), 一个模式只能使用一个输出模块
        
        match name {        // 各类模块的构造方法

            "csv" => Csv::new(output_file, is_ipv6),


            _ => {
                error!("{}", SYS.get_info("err", "output_mod_not_exist"));
                exit(1)
            }
        }
    }


    pub fn init(o:&OutputMod) -> Box<dyn OutputMethod> {

        let name = o.name;

        match name {        // 各类模块的构造方法

            "csv" => Box::new(Csv::init(o)),


            _ => {
                error!("{}", SYS.get_info("err", "output_mod_not_exist"));
                exit(1)
            }
        }


    }
}

pub trait OutputMethod:Send {     // 运行过程中的回调函数

    // vec<string>格式 行写入
    fn writer_line(&mut self, data:&Vec<String>);


    // 关闭输出
    fn close_output(&mut self);


}




pub struct OutputMod {

    pub name:&'static str,

    pub buffer_capacity:usize,
    pub output_file:Option<String>,
    pub conf:Option<ModuleConf>,
}



