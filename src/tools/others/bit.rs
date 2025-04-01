

/// 找到第n个1的位
/// 注意: n为 0, 1, 2, 3...
pub fn find_nth_one(mut num: u32, mut n: u8) -> Option<u8> {
    while num != 0 {
        let pos = num.trailing_zeros();
        num &= !(1 << pos);
        if n == 0 {
            return Some(pos as u8);
        }
        n -= 1;
    }
    None
}