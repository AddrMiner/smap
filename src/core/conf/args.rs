
//! 定义命令行参数并解析
use clap::Parser;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args{


    // mode
    #[arg(short = 'm', long, help = "操作模式名称 如: default v4 v6等")]
    pub mode:Option<String>,


    // base conf
    #[arg(short = 'i', long = "interface", help = "设置本机的网络接口")]
    pub interface:Vec<String>,

    #[arg(long, help = "随机数种子, 用来 设置加密密钥 和 生成随机数")]
    pub seed:Option<u64>,

    #[arg(long = "summary_file", help = "保存一次扫描的配置信息, 扫描结果等")]
    pub summary_file:Option<String>,


    // sender conf
    #[arg(long = "probe_v4", help = "设置ipv4探测模块")]
    pub probe_v4:Option<String>,

    #[arg(long = "probe_v6", help = "设置ipv6探测模块")]
    pub probe_v6:Option<String>,

    #[arg(long = "saddr", help = "设置本机用于发送的地址")]
    pub source_addrs:Option<String>,

    #[arg(long = "sport", help = "设置本机用于发送的端口")]
    pub source_ports:Option<String>,

    #[arg(long = "send_attempt_num", help = "发送数据包时的重试次数(如果发送失败, 最多会尝试多少次)")]
    pub send_attempt_num:Option<i32>,

    #[arg(long = "thread_num", help = "用来发送的线程数量")]
    pub send_thread_num:Option<usize>,

    #[arg(short = 'a', long = "probe_args", help = "设置探测模块的自定义参数, 如  -a my_arg=xxx")]
    pub probe_args:Vec<String>,

        // black white list
    #[arg(long = "black_list_v4", help = "Ipv4黑名单路径")]
    pub black_list_v4:Option<String>,

    #[arg(long = "black_list_v6", help = "Ipv6黑名单路径")]
    pub black_list_v6:Option<String>,

    #[arg(long = "white_list_v4", help = "Ipv4白名单路径")]
    pub white_list_v4:Option<String>,

    #[arg(long = "white_list_v6", help = "Ipv6白名单路径")]
    pub white_list_v6:Option<String>,


    #[arg(long = "source_black_list_v4", help = "Ipv4源地址黑名单路径")]
    pub source_black_list_v4:Option<String>,

    #[arg(long = "source_black_list_v6", help = "Ipv6源地址黑名单路径")]
    pub source_black_list_v6:Option<String>,

    #[arg(long = "source_white_list_v4", help = "Ipv4源地址白名单路径")]
    pub source_white_list_v4:Option<String>,

    #[arg(long = "source_white_list_v6", help = "Ipv6源地址白名单路径")]
    pub source_white_list_v6:Option<String>,

        // 全局速率参数
    #[arg(long = "send_rate", help = "发送速率 一秒多少个以太网帧")]
    pub send_rate:Option<u64>,

    #[arg(short = 'b', long = "band_width", help = "发送带宽设置(K, M, G)")]
    pub band_width:Option<String>,

    #[arg(long = "batch_size", help = "每个发送轮次的大小")]
    pub batch_size:Option<u64>,

    #[arg(long = "must_sleep", help = "每个发送轮次执行完毕后必须等待的时间")]
    pub must_sleep:Option<u64>,


    #[arg(short = 't', long = "tar_ips", help = "设置目标ip地址范围")]
    pub tar_ips:Option<String>,

    #[arg(short = 'f', long = "target_file", help = "设置目标文件路径")]
    pub target_file:Option<String>,

    #[arg(short = 'p', long = "tar_ports", help = "设置目标端口地址范围")]
    pub tar_ports:Option<String>,

    #[arg(long = "cool_seconds", help = "所有发送线程结束后到接收线程结束前的冷却时间")]
    pub cool_seconds:Option<i64>,



    // receiver
    #[arg(short = 'o', long = "output", help = "设置输出模块")]
    pub output_mod:Option<String>,

    #[arg(long = "output_file_v4", help = "设置ipv4协议输出文件路径")]
    pub output_file_v4:Option<String>,

    #[arg(long = "output_file_v6", help = "设置ipv6协议输出文件路径")]
    pub output_file_v6:Option<String>,

    #[arg(long = "allow_no_succ", default_value_t = false, help = "允许探测失败但验证成功的输出, 如icmp包裹原始数据包, rst标志数据包等")]
    pub allow_no_succ:bool,

    #[arg(long, help = "接收线程的数据包过滤方法")]
    pub filter:Option<String>,

    #[arg(long, help = "设置输出字段, 默认为输出全部字段")]
    pub fields:Vec<String>,



    // logger
    #[arg(short = 'q', long = "disable_sys_log", default_value_t = false, help = "关闭日志终端输出")]
    pub disable_sys_log:bool,

    #[arg(long = "log_level", help = "参数示例: 0 1 2 3 4 5 从0到5依次升高, 您也可以直接输入小写形式的 trace debug info warn error。默认值为trace")]
    pub log_level:Option<String>,

    #[arg(long = "log_file", help = "日志输出文件")]
    pub log_file:Option<String>,

    #[arg(long = "log_directory", help = "日志输出目录(在目录下创建规定格式的日志文件)")]
    pub log_directory:Option<String>,
    


    // help
    #[arg(long = "mode_help", help = "打印 模式 帮助")]
    pub mode_help:Option<String>,


    #[arg(long = "probe_v4_help", help = "打印 ipv4探测模块 帮助")]
    pub probe_v4_help:Option<String>,


    #[arg(long = "probe_v6_help", help = "打印 ipv6探测模块 帮助")]
    pub probe_v6_help:Option<String>,


    #[arg(long = "output_help", help = "打印 输出模块 帮助")]
    pub output_help:Option<String>,



    // 自定义参数
    // ttl
    // #[arg(long, help = "ttl  网络生存时间")]
    // pub ttl:Option<u8>,

}

impl Args {
    pub fn get_args() -> Args {
        Args::parse()
    }
}