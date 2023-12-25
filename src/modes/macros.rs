
/// 为 发送线程 或 接收线程 准备数据
/// 例:
/// 模式一:   prepare_data!(self; e, f);  表示 let e = self.e; let f = self.f;
/// 模式二:   prepare_data!(self; clone; a, b);  表示 let a = self.a.clone(); let b = self.b.clone(); 第二个分号前的参数是方法名称
#[macro_export]
macro_rules! prepare_data {
    (;$method:ident;$($field:ident),*) => (
        $(let $field = $field.$method();)*
    );
    ($self:ident; $($field:ident),*) => (
        $(let $field = $self.$field;)*
    );
    ($self:ident; $method:ident; $($field:ident),*) => (
        $(let $field = $self.$field.$method();)*
    )
}


#[macro_export]
macro_rules! creat_channels {
    (
        $( ($sender:ident, $receiver:ident, $t:ty) ),*
    ) => {
        $(
            let ($sender, $receiver): (
                std::sync::mpsc::Sender<$t>,
                std::sync::mpsc::Receiver<$t>
            ) = std::sync::mpsc::channel();
        )*
    }
}


#[macro_export]
macro_rules! ending_the_receiving_thread {
    ($self:ident; $msg_sender:ident) => (
        let end_time = chrono::Utc::now().timestamp() + $self.sender_conf.cool_seconds;
        // 向接收线程发送终止时间失败
        if let Err(_) = $msg_sender.send(end_time){ error!("{}", crate::SYS.get_info("err","send_recv_close_time_failed")); std::process::exit(1) }
    )
}

#[macro_export]
macro_rules! recv_ready {
    ($receiver:ident) => (
        if let Err(_) = $receiver.recv() {
            error!("{}", crate::SYS.get_info("err", "recv_ready_receive_failed"));
            std::process::exit(1)
        }
    )
}

#[macro_export]
macro_rules! init_var {
    ($t:ty; $e:expr; $($field:ident),*) => (
        $(let mut $field:$t = $e;)*
    );
}

#[macro_export]
macro_rules! wait_sender_threads {
    ($sender_threads:ident; $($field:ident),*; $block:block) => (
        for sender_thread in $sender_threads {
            let sender_res = sender_thread.join();

            if let Ok(($($field,)*)) = sender_res  $block
            else { error!("{}", crate::SYS.get_info("err", "send_thread_err")); std::process::exit(1) }
        }
    );
}

#[macro_export]
macro_rules! computing_time {
    ($start_time:ident; $end_time:ident, $running_time:ident) => (
        let $end_time = chrono::Local::now();
        let $running_time = crate::tools::others::time::get_fmt_duration(($end_time - $start_time).num_seconds(), crate::SYS.get_info("print", "running_time_pattern"));
        println!("{} {}", crate::SYS.get_info("print", "show_running_time"), $running_time);
    );
    ($start_time:ident, $end_time:ident; $running_time:ident) => (
        let $running_time = crate::tools::others::time::get_fmt_duration(($end_time - $start_time).num_seconds(), crate::SYS.get_info("print", "running_time_pattern"));
        println!("{} {}", crate::SYS.get_info("print", "show_running_time"), $running_time);
    );
}

#[macro_export]
macro_rules! write_to_summary {

    // 输出结果

    ($self:ident; $mode:expr; $target:expr; [$($field:ident),*; $(($custom_field_str:expr, $custom_field:ident)),*]) => (
        if let Some(summary_path) = &$self.base_conf.summary_file {
            let header = vec![$(stringify!($field),)*  $($custom_field_str,)* ];
            let val = vec![$($field.to_string(),)*  $($custom_field.to_string(),)* ];
            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );

    ($self:ident; $mode:expr; $target:expr; #[$clas:ident; $($field:ident),*; $(($custom_field_str:expr, $custom_field:ident)),*]) => (
        if let Some(summary_path) = &$self.base_conf.summary_file {
            let header = vec![$(stringify!($field),)*  $($custom_field_str,)* ];
            let val = vec![$($clas.$field.to_string(),)*  $($clas.$custom_field.to_string(),)* ];
            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );


    ($self:ident; $mode:expr; $target:expr; [$($field:ident),*; $(($custom_field_str:expr, $custom_field:ident)),*]; #[$clas:ident; $($clas_field:ident),*; $(($clas_custom_field_str:expr, $clas_custom_field:ident)),*]) => (
        if let Some(summary_path) = &$self.base_conf.summary_file {
            let header = vec![$(stringify!($field),)*  $($custom_field_str,)*  $(stringify!($clas_field),)*  $($clas_custom_field_str,)*  ];
            let val = vec![ $($field.to_string(),)*  $($custom_field.to_string(),)*  $($clas.$clas_field.to_string(),)*  $($clas.$clas_custom_field.to_string(),)* ];
            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );


    ($self:ident; $mode:expr; $target:expr; [$($field:ident),*; $(($custom_field_str:expr, $custom_field:ident)),*]; #[$clas:ident; $($clas_field:ident),*; $(($clas_custom_field_str:expr, $clas_custom_field:ident)),*]; #[$clas2:ident; $($clas2_field:ident),*; $(($clas2_custom_field_str:expr, $clas2_custom_field:ident)),*]) => (
        if let Some(summary_path) = &$self.base_conf.summary_file {
            let header = vec![$(stringify!($field),)*  $($custom_field_str,)*  $(stringify!($clas_field),)*  $($clas_custom_field_str,)*   $(stringify!($clas2_field),)*  $($clas2_custom_field_str,)* ];
            let val = vec![ $($field.to_string(),)*  $($custom_field.to_string(),)*  $($clas.$clas_field.to_string(),)*  $($clas.$clas_custom_field.to_string(),)*  $($clas2.$clas2_field.to_string(),)*  $($clas2.$clas2_custom_field.to_string(),)*  ];
            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );


    // 输出参数

    ($base:ident; $mode:expr; $target:expr; $(($field_str:expr, $field_val:ident)),* ) => (
        if let Some(summary_path) = &$base.summary_file {
            // 将 所有输入参数 写入记录文件
            let header = vec![ $($field_str,)* ];
            let val = vec![ $($field_val.to_string(),)* ];

            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );


    ($base:ident; $mode:expr; $target:expr; $args:ident; $(($field_str:expr, $field_val:ident)),* ) => (
        if let Some(summary_path) = &$base.summary_file {
            // 将 所有输入参数 写入记录文件
            let header = vec![ "time", "args",  $($field_str,)* ];
            let val = vec![ chrono::Local::now().to_string(), format!("{:?}", $args).replace(",", " "), $($field_val.to_string(),)* ];

            crate::tools::file::write_to_file::write_record($mode, $target, summary_path, header, val);
        }
    );

}

#[macro_export]
macro_rules! get_conf_from_mod_or_sys {
    ($mod_conf:ident; $($field:ident),*) => (
        $(
            let $field = $mod_conf.get_conf_or_from_sys(&String::from(stringify!($field)));
        )*
    );
}


