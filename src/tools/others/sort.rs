




use std::cmp::PartialOrd;

/// 按照 arr的元素大小对 arr和index进行排序, 从大到小
pub fn quick_sort_from_big_to_small<T: PartialOrd + Copy, U>(arr:&mut Vec<T>, index:&mut Vec<U>, left:usize, right:usize){

    if left < right {

        let mut i = left;
        let mut j = right;

        let pivot = arr[ (left+right) / 2 ];

        loop {
            while arr[i] > pivot {
                i += 1;
            }
            while arr[j] < pivot {
                j -= 1;
            }
            if i >= j {
                break
            }

            arr.swap(i,j);
            index.swap(i,j);

            i += 1;
            j -= 1;
        }

        if i != 0 {
            quick_sort_from_big_to_small(arr, index, left, i-1);
        }
        quick_sort_from_big_to_small(arr, index, j+1, right);
    }
}

/// 按照 arr的元素大小对 arr和index进行排序, 从小到大
#[allow(dead_code)]
pub fn quick_sort_from_small_to_big<T: PartialOrd + Copy, U>(arr:&mut Vec<T>, index:&mut Vec<U>, left:usize, right:usize){

    if left < right {

        let mut i = left;
        let mut j = right;

        let pivot = arr[ (left+right) / 2 ];

        loop {
            while arr[i] < pivot {
                i += 1;
            }
            while arr[j] > pivot {
                j -= 1;
            }
            if i >= j {
                break
            }

            arr.swap(i,j);
            index.swap(i,j);

            i += 1;
            j -= 1;
        }

        if i != 0 {
            quick_sort_from_small_to_big(arr, index, left, i-1);
        }
        quick_sort_from_small_to_big(arr, index, j+1, right);
    }
}