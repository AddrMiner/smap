


pub fn split_chains<T: Clone>(mut state_chain: Vec<T>, sender_count: usize) -> Vec<Vec<T>> {
    let chunk_size = (state_chain.len() / sender_count) + 1;
    let chunks = state_chain.chunks_mut(chunk_size);

    let mut res = vec![];
    for chunk in chunks.into_iter() {
        res.push(chunk.to_vec());
    }

    let res_len = res.len();
    res.swap(0, res_len - 1);
    res
}