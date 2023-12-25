

use ahash::AHashSet;
use crate::tools::check_duplicates::{DuplicateCheckerV6, NotMarkedV6};

pub struct HashSetV6 {
    set:AHashSet<u128>
}


impl HashSetV6 {

    pub fn new(cap:usize) -> Self {
        Self {
            set: AHashSet::with_capacity(cap),
        }
    }
}


impl DuplicateCheckerV6 for HashSetV6 {
    #[inline]
    fn set(&mut self, ip: u128) {
        self.set.insert(ip);
    }

    /// 警告: 哈希查重器无法验证是否在目标范围
    #[inline]
    fn not_marked_and_valid(&self, ip: u128) -> bool {
        !self.set.contains(&ip)
    }
}

impl NotMarkedV6 for HashSetV6 {
    fn is_not_marked(&self, ip: u128) -> bool {
        !self.set.contains(&ip)
    }
}

