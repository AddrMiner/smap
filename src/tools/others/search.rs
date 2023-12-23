




/// 返回 目标值 是否存在
/// 注意: 传入向量必须有序(二分查找)
#[inline]
pub fn binary_search<T: Ord>(record:&Vec<T>, target:&T) -> bool {

    match record.binary_search(target){
        Ok(_) => true,
        Err(_) => false,
    }
}
