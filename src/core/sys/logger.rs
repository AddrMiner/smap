//! 系统日志配置器

use std::path::{Path, PathBuf};
use log::{debug, LevelFilter};
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};
use std::string::String;
use crate::core::conf::args::Args;
use crate::tools::others::time::get_fmt_time;
use crate::SYS;

/// 设置日志记录器
pub fn set_logger(args:&Args){

    // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
    let pattern = &SYS.get_info("log", "log_pattern");

    // 匹配日志等级
    let level;
    if let Some(l) = &args.log_level {
        let l = l as &str;

        level = match l {
            "0" | "trace" => LevelFilter::Trace,
            "1" | "debug" => LevelFilter::Debug,
            "2" | "info" => LevelFilter::Info,
            "3" | "warn" => LevelFilter::Warn,
            "4" | "error" => LevelFilter::Error,
            _ => LevelFilter::Trace,
        };

    } else {
        level = LevelFilter::Trace;
    }


    let mut log_file_exist = true;
    let mut log_directory_exist = true;

    let log_file:String = args.log_file.clone().unwrap_or_else(|| {
        log_file_exist = false; String::new()
    });

    let log_directory:String = args.log_directory.clone().unwrap_or_else(|| {
        log_directory_exist = false; String::new()
    });

    // 日志文件和日志目录不能同时指定。
    if log_file_exist && log_directory_exist {
        panic!("{}",SYS.get_info("err", "log_file_directory_both_exist"));
    }

    if log_file_exist {

        // 如果日志文件存在，就把日志输出目标设为日志文件
        if args.disable_sys_log {
            // 如果系统日志被禁用
            set_logger_file(pattern, level,&log_file);
            println!("{}", SYS.get_info("print", "syslog_off"));
        }else {
            // 如果开启系统日志
            set_logger2(pattern,level,&log_file);
            debug!("{}", SYS.get_info("debug", "syslog_on"));
        }


    }else if log_directory_exist {

        // 如果日志目录存在，把日志输出目标设为 目录下当前时间为文件名的文件
        let log_name= get_fmt_time(&SYS.get_info("log", "log_name_pattern"));
        let log_file = PathBuf::from(log_directory).join(log_name);

        // 如果日志文件存在，就把日志输出目标设为日志文件
        if args.disable_sys_log {
            // 如果系统日志被禁用
            set_logger_file(pattern, level,&log_file);
            println!("{}", SYS.get_info("print", "syslog_off"));
        }else {
            // 如果开启系统日志
            set_logger2(pattern,level,&log_file);
            debug!("{}", SYS.get_info("debug", "syslog_on"));
        }


    }else {

        // 如果日志文件和日志目录都不存在
        if !args.disable_sys_log {
            // 如果系统日志不被禁用
            set_logger_std(pattern,level);
            debug!("{}", SYS.get_info("debug", "syslog_on"));
        } else {
            println!("{}", SYS.get_info("print", "syslog_off"));
        }

    }



}

fn set_logger2<P: AsRef<Path>>(pattern:&str, level:LevelFilter,file_path:P) {

    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .target(Target::Stderr)
        .build();

    let logfile = FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(file_path)
        .unwrap();

    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("logfile", Box::new(logfile)))
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(LevelFilter::Trace),
        )
        .unwrap();

    log4rs::init_config(config).unwrap();

}

fn set_logger_file<P: AsRef<Path>>(pattern:&str, level:LevelFilter, file_path:P) {

    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(file_path)
        .unwrap();

    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("logfile")
                .build(LevelFilter::Trace),
        )
        .unwrap();

    log4rs::init_config(config).unwrap();

}

fn set_logger_std(pattern:&str, level:LevelFilter) {

    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .target(Target::Stderr)
        .build();

    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(level)))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            Root::builder()
                .appender("stderr")
                .build(LevelFilter::Trace),
        )
        .unwrap();

    log4rs::init_config(config).unwrap();

}


