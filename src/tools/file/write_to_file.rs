use std::fs;
use std::fs::OpenOptions;
use std::io::{Write, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::exit;
use log::{error, warn};
use crate::SYS;
use crate::tools::file::get_path::get_current_path;

pub fn write_record(mode:&str, target:&str, filepath: &String, header: Vec<&str>, record: Vec<String>){

    let filepath = get_current_path(&format!("{}_{}_{}.csv", filepath, mode, target));

    let filepath = PathBuf::from(filepath);

    match OpenOptions::new().read(true).write(true).open(&filepath) {

        Ok(mut file) => {

            // 读取第一行
            let mut reader = BufReader::new(&file);
            let mut first_line = String::new();
            reader.read_line(&mut first_line).map_err(|_| {
                error!("{}", SYS.get_info("err", "write_record_err"));
                exit(1)
            }).unwrap();

            if first_line.trim() == header.join(",") {

                // 如果字段一致, 追加写入

                // 将文件指针移动到最后
                file.seek(SeekFrom::End(0)).map_err(|_|{
                    error!("{}", SYS.get_info("err", "write_record_err"));
                    exit(1)
                }).unwrap();

                writeln!(file, "{}", record.join(",")).map_err(|_| {
                    error!("{}", SYS.get_info("err", "write_record_err"));
                    exit(1)
                }).unwrap();

                return
            } else {
                // 如果字段不一致

                warn!("{}", SYS.get_info("warn","record_file_header_not_match"));

                let mut record_option = String::new();
                std::io::stdin().read_line(&mut record_option).map_err(
                    | _ | {
                        error!("{}", SYS.get_info("err","input_record_option_err"));
                        exit(1)
                    }
                ).unwrap();

                match record_option.trim() {
                    "yes" => {}
                    _ => exit(1)
                }

                fs::remove_file(&filepath).map_err(|_| {
                    error!("{}", SYS.get_info("err", "del_record_file_err"));
                    exit(1)
                }).unwrap();
            }
        }

        Err(_) => {}
    }

    // 创建记录文件
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&filepath)
        .map_err(|_| {
            error!("{} {:?}", SYS.get_info("err", "create_record_file_err"), &filepath);
            exit(1)
        }).unwrap();

    writeln!(file, "{}", header.join(",")).map_err(|_| {
        error!("{}", SYS.get_info("err", "write_record_err"));
        exit(1)
    }).unwrap();
    writeln!(file, "{}", record.join(",")).map_err(|_| {
        error!("{}", SYS.get_info("err", "write_record_err"));
        exit(1)
    }).unwrap();

}



