use ahash::AHashSet;
use crate::tools::check_duplicates::{DuplicateCheckerV4, NotMarkedV4};

pub struct HashSetV4 {
    set:AHashSet<u32>
}


impl HashSetV4 {

    pub fn new(cap:usize) -> Self {
        Self {
            set: AHashSet::with_capacity(cap),
        }
    }
}


impl DuplicateCheckerV4 for HashSetV4 {
    #[inline]
    fn set(&mut self, ip: u32) {
        self.set.insert(ip);
    }

    /// 警告: 哈希查重器无法验证是否在目标范围
    #[inline]
    fn not_marked_and_valid(&self, ip: u32) -> bool {
        !self.set.contains(&ip)
    }
}

impl NotMarkedV4 for HashSetV4 {
    fn is_not_marked(&self, ip: u32) -> bool {
        !self.set.contains(&ip)
    }
}

