


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