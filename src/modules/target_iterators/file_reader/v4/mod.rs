use std::cmp::min;
use std::fs::{OpenOptions};
use std::io::{BufReader, Seek};
use std::process::exit;
use log::{error};
use crate::modules::target_iterators::file_reader::read_target_file::TargetFileReader;
use crate::modules::target_iterators::Ipv4FileReader;
use crate::SYS;

pub mod ipv4_file_reader;


impl TargetFileReader {

    pub fn get_ipv4_file_reader(&self, assigned_targets:&(u64,u64,u64), cur_tar_port:u16) -> Option<Ipv4FileReader> {

        if let Some(_) = self.tar_num {
            // 存在目标数量, 按照目标数量进行分配

            match OpenOptions::new().read(true).write(false).open(&self.path) {
                Ok(mut file) => {

                    // 将文件指针指向 开始索引(局部) 的位置
                    file.seek(std::io::SeekFrom::Start(assigned_targets.0)).map_err(
                        |_| {
                            error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), assigned_targets.0, self.path);
                            exit(1)
                        }
                    ).unwrap();

                    return Some(
                        Ipv4FileReader {
                            current_index: assigned_targets.0,
                            end_index: assigned_targets.1,
                            reader: BufReader::with_capacity(self.max_read_buf_bytes as usize, file),

                            tar_port_from_file: cur_tar_port == 0,
                            tar_port: cur_tar_port,
                        }
                    )
                }
                Err(_) => {
                    error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                    exit(1)
                }
            }

        } else {
            let (valid, start_index) = self.get_start(assigned_targets.0, assigned_targets.1);

            if valid {
                match OpenOptions::new().read(true).write(false).open(&self.path) {
                    Ok(mut file) => {

                        // 将文件指针指向 开始索引(局部) 的位置
                        file.seek(std::io::SeekFrom::Start(start_index)).map_err(
                            |_| {
                                error!("{} {} {}", SYS.get_info("err", "seek_file_failed"), start_index, self.path);
                                exit(1)
                            }
                        ).unwrap();

                        // 取 设定的最大缓冲区大小(字节数), 当前被分配区域大小(字节) + 回退字节数, 中的 最小值 作为缓冲区大小
                        let buf_capacity = min(self.max_read_buf_bytes,
                                               assigned_targets.2 + self.fallback_bytes) as usize;

                        return Some(
                            Ipv4FileReader {
                                current_index: start_index,
                                end_index: assigned_targets.1,
                                reader: BufReader::with_capacity(buf_capacity, file),

                                tar_port_from_file: cur_tar_port == 0,
                                tar_port: cur_tar_port,
                            }
                        )
                    }
                    Err(_) => {
                        error!("{} {}", SYS.get_info("err", "open_targets_file_failed"), self.path);
                        exit(1)
                    }
                }
            }
            None
        }
    }
}