

/// 将 数字 插入一个有序数组, 并使之有序, 注意为从小到大排列
pub fn insert_to_sorted_array<T: PartialOrd + Copy>(arr:&mut Vec<T>, num:T) {

    let mut index = arr.len();
    if index == 0 {
        // 如果 原向量 长度为0

        // 直接插入并返回
        arr.push(num);
        return
    }

    // 减一 得到 最后一个元素的索引
    index -= 1;

    if num >= arr[index] {
        // 如果 被插入数字 大于等于 原有向量(从小到大排序)中最右边的元素

        // 将 被插入数字 直接插入到 原向量的最右边
        arr.push(num);
    } else {

        // 如果 被插入数字 小于 原有向量最右边元素, 将 原向量最大元素复制一份, 添加在原向量的最后
        arr.push(arr[index]);

        let mut flag = true;

        // 索引从 原向量中的倒数第二个元素的索引 开始, 倒着向前
        while index > 0 {
            index -= 1;

            if num < arr[index] {
                // 如果 被插入数字 小于 当前元素
                // 将当前元素向后移动一位
                arr[index + 1] = arr[index];
            } else {
                // 如果  当前元素 小于等于  被插入数字

                // 将 被插入数字 放置在 当前元素的下一位索引上, 覆盖原有值(原有值已向后移动)
                // 注意: 此步骤只能将 被插入数字 插入到 非零索引
                arr[index + 1] = num;

                // 一旦在途中进行了 对被插入值的放置, 被插入值就一定不在 索引0 处放置
                flag = false;
                break
            }
        }

        if flag {
            // 如果 在途中没有对被插入值进行放置, 那么被插入值一定在索引处被放置
            arr[0] = num;
        }
    }

}