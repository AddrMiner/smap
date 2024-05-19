use std::mem;
use libc;
use libc::{c_int, c_uchar};
use std::process::exit;
use log::error;
use crate::SYS;
use crate::tools::net_handle::net_interface::mac_addr::MacAddress;


#[cfg(any(target_os = "linux"))]
pub struct PacketSender {
    sock:c_int,
    sockaddr:libc::sockaddr_ll,
    // sockaddr_ptr:*const libc::sockaddr,
    addr_len:u32
}


#[cfg(any(target_os = "linux"))]
impl PacketSender {

    /// 初始化数据包发送器, 注意index为网卡的系统index, 不是输入的网卡向量下标
    pub fn new(interface_name_index:&(String, c_int), mac:&MacAddress) -> Self {

        // Every packet
        let eth_p_all:i32 = 0x0003;

        let sock = unsafe {
            libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all.to_be())
        };

        if sock <= 0 {
            // 获取 fd 失败
            error!("{}", SYS.get_info("err", "get_socket_failed"));
            exit(1)
        }

        let mut sockaddr:libc::sockaddr_ll = unsafe { mem::zeroed() };
        sockaddr.sll_ifindex = interface_name_index.1;
        sockaddr.sll_halen = libc::ETH_ALEN as c_uchar;

        for (i, e) in mac.bytes.into_iter().enumerate(){
            sockaddr.sll_addr[i] = e as c_uchar;
        }

        // 设置不阻塞模式
        // unsafe { libc::fcntl(sock, libc::F_SETFL, libc::O_NONBLOCK); }

        Self {
            sock,
            sockaddr,
            // sockaddr_ptr: unsafe { mem::zeroed() },
            addr_len:mem::size_of_val(&sockaddr) as u32
        }
    }


    /// 发送数据包
    #[inline]
    pub fn send_packet(&self, buf:&Vec<u8>) -> libc::ssize_t {
        unsafe { libc::sendto(self.sock, buf.as_ptr() as *const libc::c_void, buf.len(), 0, 
                              mem::transmute(&self.sockaddr as *const libc::sockaddr_ll), self.addr_len) }
    }


}

#[cfg(any(target_os = "linux"))]
impl Drop for PacketSender {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.sock);
        }
    }
}

/*

用法示例
    let sender;
    {
        let mut socket = PacketSender::new(interface_name_index, MacAddress::new([0, 21, 93, 205, 7, 185]));
        socket.init();
        sender = socket;
    }

    sender.send_packet(&payload);
 */







