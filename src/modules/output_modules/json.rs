
use crate::modules::output_modules::{OutputMethod, OutputMod};

pub struct Json {
    is_not_first:bool,

    name_vec:Vec<String>,
}

impl Json {


    pub fn new() -> OutputMod {
        OutputMod {
            name: "json",

            buffer_capacity: 0,
            output_file: None,
            conf: None,
        }
    }

    pub fn init(_o:&OutputMod) -> impl OutputMethod {
        Json {
            is_not_first: false,
            name_vec: vec![],
        }
    }


}


impl OutputMethod for Json {
    fn writer_line(&mut self, data: &Vec<String>) {

        if self.is_not_first {
            let mut cur_output = String::from("{");

            for (cur_name, cur_val) in self.name_vec.iter().zip(data.into_iter()) {
                cur_output.push_str(&format!("{}:{},", cur_name, cur_val))
            }

            cur_output.pop();
            cur_output.push_str("}");

            println!("{}", cur_output);
        } else {
            self.name_vec = data.clone();
            self.is_not_first = true;
        }

    }

    fn close_output(&mut self) {}
}