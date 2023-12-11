use crate::SYS;



/// 解析汇总文件配置
pub fn parse_summary_file(summary_file:&Option<String>) -> Option<String> {

    if let Some(_) = summary_file {
        (*summary_file).clone()
    } else {
        SYS.get_info_without_panic("conf", "summary_file")
    }

}




