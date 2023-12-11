use std::str::FromStr;
use default_net::interface::MacAddr;


/// 网络接口 硬件地址
pub struct MacAddress {
    pub bytes: [u8; 6],
}

pub enum MacAddressErr {
    Invalid
}


impl MacAddress {

    pub fn new(bytes: [u8;6])  -> Self {
        MacAddress { bytes }
    }

    pub fn from_mac_addr(val:MacAddr) -> Self {

        Self {
            bytes: val.octets()
        }

    }

}

impl FromStr for MacAddress {
    type Err = MacAddressErr;

    /// 从 str 生成 mac_address (带合法性检查)
    fn from_str(input:&str) -> Result<Self, Self::Err> {

        let mut arr = [0u8; 6];

        let mut index = 0;
        for byte in input.split(|c| c == ':' || c == '-') {

            // 如果间隔符数量 太多
            if index == 6 {
                return Err(MacAddressErr::Invalid)
            }

            // 将 字符串 以 16进制 转换为 u8
            arr[index] = u8::from_str_radix(byte, 16)
                .map_err(|_| MacAddressErr::Invalid)?;

            index += 1;
        }

        // 如果间隔符数量 太少
        if index != 6 {
            return Err(MacAddressErr::Invalid)
        }

        Ok(Self::new(arr))
    }


}



impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let _ = write!(
            f,
            "{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}:{:<02X}",
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
            self.bytes[4],
            self.bytes[5]
        );

        Ok(())
    }
}