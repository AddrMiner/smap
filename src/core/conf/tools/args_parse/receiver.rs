use crate::core::conf::set_conf::receiver_conf::{ReceiverBaseConf};
use crate::SYS;
impl ReceiverBaseConf {


    pub fn parse_output_mod(output_mod:&Option<String>) -> String {

        if let Some(o) = output_mod {
            o.to_string()
        } else {
            SYS.get_info("conf", "default_output_mod")
        }

    }

}