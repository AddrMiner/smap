


pub fn fnv1(mut val:u64) -> u64 {
    let mut hash:u64 = 14695981039346656037;

    for _ in 0..8 {
        hash ^= val & 0xff;
        hash *= 1099511628211;
        val >>= 8;
    }

    hash
}