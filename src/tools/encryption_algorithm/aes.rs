use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use rand::{random, Rng, SeedableRng};
use rand::rngs::StdRng;

/// AES加密机 和 随机数发生器
pub struct AesRand {
    cipher:Aes128,      // aes128 加密机
    pub seed:u64,
    pub rand_u16:u16,
    pub rng:StdRng,         // 随机数发生器

}

impl Clone for AesRand {
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            seed: self.seed,
            rand_u16: self.rand_u16,
            rng: self.rng.clone(),
        }
    }
}


impl AesRand {

    pub fn new(seed_arg:Option<u64>) -> Self {

        let seed = seed_arg.unwrap_or_else(|| random());

        // 随机数生成器
        let mut rng = StdRng::seed_from_u64(seed);

        // 初始化 aes 密钥
        let mut k = [0u8;16];

        // 填充密钥
        for i in 0..16usize {
            k[i] = rng.gen();
        }

        let key = GenericArray::from(k);

        let rand_u16:u16 = rng.gen();

        AesRand {
            cipher: Aes128::new(&key),
            seed,
            rand_u16,
            rng,
        }

    }


    /// 加密函数
    #[inline]
    pub fn encrypt(&self, block:&mut [u8;16]) {

        let mut block = GenericArray::from_mut_slice(block);
        self.cipher.encrypt_block(&mut block);
    }

    /// 解密函数
    #[allow(dead_code)]
    #[inline]
    pub fn decrypt(&self, block:&mut [u8;16]) {

        let mut block = GenericArray::from_mut_slice(block);
        self.cipher.decrypt_block(&mut block);
    }

    /// 生成验证信息 (u32)
    /// 注意, 这里的目标地址, 源地址, 源端口 是对接收线程来说的
    /// 在发送线程中, 目标地址 和 源地址 应该调换位置, 源端口位置应该输入 目的端口
    pub fn validate_gen_v4_u32(&self, dest_ip:u32, source_ip:u32, port_be_bytes:&[u8]) -> [u8;16]{

        let d = dest_ip.to_le_bytes();
        let s = source_ip.to_le_bytes();

        // 注意为 小端排序
        let mut tar = [d[0], d[1], d[2], d[3],
            s[0], s[1], s[2], s[3],
            0, 0, 0, 0,
            0, 0, port_be_bytes[1], port_be_bytes[0]];

        self.encrypt(&mut tar);

        tar
    }

    pub fn validate_gen_v4_u32_without_sport(&self, dest_ip:u32, source_ip:u32) -> [u8;16]{

        let d = dest_ip.to_le_bytes();
        let s = source_ip.to_le_bytes();

        // 注意为 小端排序
        let mut tar = [d[0], d[1], d[2], d[3],
            s[0], s[1], s[2], s[3],
            0, 0, 0, 0,
            0, 0, 0, 0];

        self.encrypt(&mut tar);

        tar
    }


    pub fn validate_gen_v6_u128(&self, dest_ip:u128, source_ip:u128, sport_be_bytes:&[u8]) -> [u8;16] {

        let mut tar = dest_ip.to_le_bytes();
        let s = source_ip.to_le_bytes();

        // 对 目标ip 进行 aes加密
        self.encrypt(&mut tar);

        // 源ip 和 第1次加密结果 进行异或, 得到异或结果后再次进行 aes加密
        for index in 0..16usize {
            tar[index] = tar[index] ^ s[index];
        }
        self.encrypt(&mut tar);

        // 源端口 和 第2次加密结果 进行异或, 得到异或结果后再次进行 aes加密
        tar[0] = tar[0] ^ sport_be_bytes[0];
        tar[1] = tar[1] ^ sport_be_bytes[1];
        self.encrypt(&mut tar);

        tar
    }


    pub fn validate_gen_v6_u128_without_sport(&self, dest_ip:u128, source_ip:u128) -> [u8;16] {

        let mut tar = dest_ip.to_le_bytes();
        let s = source_ip.to_le_bytes();

        // 对 目标ip 进行 aes加密
        self.encrypt(&mut tar);

        // 源ip 和 第一次加密结果 进行异或, 得到异或结果后再次进行 aes加密
        for index in 0..16usize {
            tar[index] = tar[index] ^ s[index];
        }
        self.encrypt(&mut tar);

        tar
    }



}