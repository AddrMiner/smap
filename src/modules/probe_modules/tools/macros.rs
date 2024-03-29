


/// 按照标记,向 output_data 向量中添加对应字段
/// 如果对应标记为真, 添加对应字段
/// 如果对应标记为假, 不添加对应字段
#[macro_export]
macro_rules! push_fields_name {
    ($self:ident; $output_data:ident; $($field:ident),*) => (
        $(
            if $self.fields_flag.$field {
                $output_data.push(String::from(stringify!($field)));
            }
        )*
    )
}



/// 按照标记,向 output_data 向量中添加对应字段的值
/// 如果对应标记为真, 添加对应字段的值
/// 如果对应标记为假, 不添加对应字段的值
#[macro_export]
macro_rules! push_fields_val {
    ($self:ident; $output_data:ident; $(($field:ident, $val:expr)),*) => (
        $(
            if $self.fields_flag.$field {
                $output_data.push($val.to_string());
            }
        )*
    )
}


/// 字段构造
#[macro_export]
macro_rules! create_fields {
    ($fields_conf:ident; $fields:ident; $($field:ident),*) => (
        $(
            if $fields.contains(&stringify!($field).to_string()) {
                $fields_conf.$field = true;
                $fields_conf.len += 1;
            }
        )*
    );
    ($fields_conf:ident; $fields:ident; $final_block:block; $($field:ident),*) => (
        $(
            if $fields.contains(&stringify!($field).to_string()) {
                $fields_conf.$field = true;
                $fields_conf.len += 1;

                $final_block
            }
        )*
    );
}


#[macro_export]
macro_rules! not_use_port_check {
    ($tar_ports:ident) => (
         if $tar_ports.len() != 1 {
            // 如果有 多个端口 或 没有输入端口
            log::error!("{}", crate::SYS.get_info("err", "tar_ports_not_match_net_layer"));
            std::process::exit(1)
        } else {
            if $tar_ports[0] != 0 {
                // 如果输出的目标端口不为0
                log::error!("{}", crate::SYS.get_info("err", "tar_ports_not_match_net_layer"));
                std::process::exit(1)
            }
        }
    );
}

#[macro_export]
macro_rules! parse_custom_args {
    ($p:ident; $(($field:ident, $t:ty, $default:expr, $err_info:expr)),*) => {

        $(let $field:$t;)*

        let custom_conf = $p.conf.clone();
        match custom_conf {
            Some(c) => {
                $(
                    $field = match c.get_info(&String::from(stringify!($field))) {
                        Some(val) => {
                            val.trim().parse().map_err(|_|{
                             log::error!("{}", crate::SYS.get_info("err", $err_info)); std::process::exit(1)
                            }).unwrap()
                        }
                        None => $default
                    };
                )*
            }
            None => { $($field = $default;)* }
        }
    };
}

#[macro_export]
macro_rules! cal_output_len {
    ($output_len:ident, $type:ty, $val:expr; $($field:ident),* ) => (
        let mut $output_len:$type = $val;
        $(
            if $field { $output_len += 1; }
        )*
    )
}
