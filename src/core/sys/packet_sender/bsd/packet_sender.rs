use std::ffi::CString;
use std::mem;
use std::process::exit;
use libc::{c_int, ssize_t};
use log::error;
use crate::SYS;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;

#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios"))]
pub struct PacketSender {
    sock:c_int,
}


#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios"))]
impl PacketSender {

    #[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris"
    ))]
    fn get_fd(_attempts: usize) -> c_int {
        let c_file_name = CString::new(&b"/dev/bpf"[..]).unwrap();
        unsafe {
            libc::open(
                c_file_name.as_ptr(),
                libc::O_WRONLY,
                0,                              // 权限标识 默认权限
            )
        }
    }


    #[cfg(any(target_os = "openbsd", target_os = "macos", target_os = "ios"))]
    fn get_fd(attempts: usize) -> c_int {
        for i in 0..attempts {
            let fd = unsafe {
                let file_name = format!("/dev/bpf{}", i);
                let c_file_name = CString::new(file_name.as_bytes()).unwrap();
                libc::open(
                    c_file_name.as_ptr(),
                    libc::O_WRONLY,
                    0,
                )
            };
            if fd != -1 {
                return fd;
            }
        }

        -1
    }


    pub fn new(interface_name_index:&(String, c_int), _mac:&MacAddress) -> Self {

        let attempts:usize = SYS.get_conf("conf","get_socket_attempts");
        let fd = Self::get_fd(attempts);

        if fd == -1 {
            // 获取 fd 失败
            error!("{}", SYS.get_info("err", "get_socket_failed"));
            exit(1)
        }

        // 写入 网络接口 名称
        let mut interface:libc::ifreq = unsafe { mem::zeroed() };
        for (i, c) in interface_name_index.0.bytes().enumerate() {
            interface.ifr_name[i] = c as libc::c_char;
        }

        // 将 bpf 绑定到 网络接口
        if unsafe { libc::ioctl(fd, libc::BIOCSETIF, &interface) } == -1 {
            unsafe {
                libc::close(fd);
            }
            // 失败处理
            error!("{}", SYS.get_info("err", "bind_failed"));
            exit(1)
        }

        // 启用IO完成通知
        if unsafe { libc::ioctl(fd, libc::BIOCSHDRCMPLT, &1) } == -1 {
            unsafe {
                libc::close(fd);
            }
            // 失败处理
            error!("{}", SYS.get_info("err", "io_message_disabled"));
            exit(1)
        }

        /*
        // 设置 非阻塞模式
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
            unsafe {
                libc::close(fd);
            }
            // 错误处理
            error!("{}", SYS.get_info("err", "sender_set_nonblock"));
            exit(1)
        }
        */

        Self {
            sock: fd,
        }
    }


    #[inline]
    pub fn send_packet(&self, buf:&Vec<u8>) -> ssize_t {
        unsafe {
            libc::write(self.sock, buf.as_ptr() as *const libc::c_void, buf.len())
        }
    }


}

#[cfg(any(
target_os = "freebsd",
target_os = "netbsd",
target_os = "illumos",
target_os = "solaris",
target_os = "openbsd",
target_os = "macos",
target_os = "ios"))]
impl Drop for PacketSender {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock);
        }
    }
}


/*

let sender;
    {
        let mut socket = PacketSender::new(interface_name_index, MacAddress::new([0, 21, 93, 205, 7, 185]));
        socket.init();
        sender = socket;
    }

    sender.send_packet(&payload);
 */