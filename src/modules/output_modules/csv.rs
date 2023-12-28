use std::fs::File;
use std::process::exit;
use csv::{Writer, WriterBuilder};
use log::error;
use crate::modes::Helper;
use crate::modules::output_modules::{OutputMethod, OutputMod};
use crate::SYS;
use crate::tools::file::get_path::get_current_path;
use crate::tools::others::time::get_fmt_time;


pub struct Csv{
    csv_writer:Writer<File>,
}


impl Csv {   // 定义构造方法和初始化方法

    pub fn new(output_file_arg:&Option<String>, is_ipv6:bool) -> OutputMod {         // 输出模块创建， 用于初始化参数配置

        let output_file = match output_file_arg {
            Some(o) => (*o).clone(),
            None => {
                let child_path = if is_ipv6 {
                    get_fmt_time(&SYS.get_info("conf", "output_file_pattern_v6"))
                } else {
                    get_fmt_time(&SYS.get_info("conf", "output_file_pattern_v4"))
                };

                get_current_path(&child_path)
            }
        };



        OutputMod {
            name: "csv",

            buffer_capacity: SYS.get_conf("conf", "default_output_buffer_capacity"),
            output_file: Some(output_file),
            conf:None
        }

    }

    pub fn init(o:&OutputMod) -> impl OutputMethod {

        let output_file = match &o.output_file {
            None => {
                error!("{}", SYS.get_info("err", "output_file_not_found"));
                exit(1)
            }
            Some(output_f) => output_f
        };

        match  WriterBuilder::new()
            .buffer_capacity(o.buffer_capacity)   // 注意，io 缓冲区大小， 以字节为单位  默认 1048576
            .flexible(true)
            .from_path(output_file){
            Ok(csv_writer) => {

                Csv{
                    csv_writer,
                }
            }
            Err(_) => {
                error!("{} {}", SYS.get_info("err", "open_output_file_failed"), output_file);
                exit(1)
            }
        }
    }

}

impl OutputMethod for Csv {      // 运行过程中的 回调函数

    fn writer_line(&mut self, data:&Vec<String>)
    {
        self.csv_writer.write_record(data).map_err(|_|{
            error!("{}", SYS.get_info("err", "output_write_record_failed"));
            exit(1)
        }).unwrap();
    }



    fn close_output(&mut self){
        self.csv_writer.flush().map_err(|_|{
            error!("{}", SYS.get_info("err", "output_flush_failed"));
            exit(1)
        }).unwrap();

    }

}

impl Helper for Csv {

    fn print_help() -> String {
        SYS.get_info("help", "Csv")
    }

}








/*
impl SerializeOutput for Csv {

    fn writer_struct<S: Serialize>(&mut self, data:&S){

        self.csv_writer.serialize(data).map_err(|e|{
            println!("{}",e);
            exit(1);
        }).unwrap();

    }

}
 */
