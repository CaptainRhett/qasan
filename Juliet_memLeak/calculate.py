import re
def split_asan_blocks(filename):
    blocks = []
    current_block = []
    
    with open(filename, 'r') as file:
        for line in file:
            # 去除行尾换行符
            stripped_line = line.rstrip('\n')
            
            if stripped_line.startswith("using ASAN_GIOVESE"):
                if current_block:
                    # 将当前块保存并开始新块
                    blocks.append('\n'.join(current_block))
                    current_block = []
                # 添加分隔符行到新块
                current_block.append(stripped_line)
            else:
                if current_block or stripped_line == "":
                    # 已开始块或空行时保留内容
                    current_block.append(stripped_line)
    
    # 添加最后一个块
    if current_block:
        blocks.append('\n'.join(current_block))
    
    return blocks

def analyze_blocks(blocks):
    # 预编译正则表达式提高效率
    leak_pattern = re.compile(r'CWE401_Memory_Leak__[^\s]+_(bad|good)')
    
    results = []
    
    for block in blocks:
        # 初始化计数器
        counters = {
            'call_good': 0,
            'call_bad': 0,
            'leak_bad': 0,
            'leak_good': 0
        }
        
        # 分割块为行
        lines = block.split('\n')
        
        for line in lines:
            # 统计函数调用
            if line.startswith("Calling good()..."):
                counters['call_good'] += 1
            elif line.startswith("Calling bad()..."):
                counters['call_bad'] += 1
            
            # 检测内存泄漏条目
            leak_match = leak_pattern.search(line)
            if leak_match:
                if leak_match.group(1) == 'bad':
                    counters['leak_bad'] += 1
                else:
                    counters['leak_good'] += 1
        
        results.append(counters)
    
    return results

def calculate_confusion_matrix(analysis):
    total = {
        'call_good': 0,
        'call_bad': 0,
        'leak_bad': 0,
        'leak_good': 0
    }
    
    # 累加所有块的统计数据
    for block in analysis:
        total['call_good'] += block['call_good']
        total['call_bad'] += block['call_bad']
        total['leak_bad'] += block['leak_bad']
        total['leak_good'] += block['leak_good']
    
    # 计算混淆矩阵
    TP = total['leak_bad']
    FN = total['call_bad'] - TP
    FP = total['leak_good']  # 假设leak_good都是误报
    TN = total['call_good'] - FP
    
    return {
        'TP': TP,
        'FN': FN,
        'FP': FP,
        'TN': TN,
        'Total Samples': total['call_good'] + total['call_bad']
    }

if __name__ == "__main__":
    blocks = split_asan_blocks("testcase_output.log")
    analysis = analyze_blocks(blocks)
    matrix = calculate_confusion_matrix(analysis)
    
    print(f"True Positives (TP):  {matrix['TP']}")
    print(f"False Negatives (FN): {matrix['FN']}")
    print(f"True Negatives (TN):  {matrix['TN']}")
    print(f"False Positives (FP): {matrix['FP']}")
    print(f"\n总测试用例: {matrix['Total Samples']}")
    print(f"准确率: {(matrix['TP']+matrix['TN'])/matrix['Total Samples']:.2%}")