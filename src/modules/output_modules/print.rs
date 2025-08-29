use crate::modules::output_modules::{OutputMethod, OutputMod};


pub struct Print{}


impl Print {   // 定义构造方法和初始化方法

    pub fn new() -> OutputMod {         // 输出模块创建， 用于初始化参数配置

        OutputMod {
            name: "print",

            buffer_capacity: 0,
            output_file: None,
            conf:None
        }

    }

    pub fn init(_o:&OutputMod) -> impl OutputMethod {
        Print {}
    }

}

impl OutputMethod for Print {      // 运行过程中的 回调函数

    fn writer_line(&mut self, data:&Vec<String>)
    {

        let mut cur_output = String::new();
        for cur_data in data.iter() {
            cur_output.push_str(cur_data);
            cur_output.push(',');
        }

        cur_output.pop();
        println!("{}", cur_output);
    }



    fn close_output(&mut self){}

}