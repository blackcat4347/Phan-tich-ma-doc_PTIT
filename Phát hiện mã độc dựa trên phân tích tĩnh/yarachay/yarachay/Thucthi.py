import os
import subprocess
import re
# Đường dẫn đến thư mục chứa công cụ YARA
yara_path = r'F:\yarachay'

# Đường dẫn đến thư mục chứa các tệp bạn muốn kiểm tra
files_directory = r'F:\yarachay\madoc'

# Bước 1: Chạy yarGen để tạo quy tắc YARA từ các mẫu mã độc
yarGen_cmd = f'python {yara_path}\\yarGen.py --score -m {files_directory} -r yargen_rules.yar'
subprocess.run(yarGen_cmd, shell=True)

# Đường dẫn đến tệp quy tắc YARA được tạo bởi yarGen
yara_rules = 'F:\\yarachay\\yargen_rules.yar'

# Đường dẫn đến loki.exe
loki_path = 'F:\\yarachay\\loki'
# Thực hiện quét malware bằng Loki
loki_command = f"{loki_path}\\loki.exe -p {files_directory}"
loki_output = subprocess.check_output(loki_command, shell=True, text=True)

# Tìm dòng chứa SUBSCORE trong kết quả Loki
subscore_line = None
for line in loki_output.splitlines():
    if "SUBSCORE:" in line:
        subscore_line = line
    

# Trích xuất giá trị SUBSCORE bằng biểu thức chính quy
subscore_value = 0
if subscore_line:
    match = re.search(r'SUBSCORE: (\d+)', subscore_line)
    if match:
        subscore_value = int(match.group(1))

# In số điểm subscore
print(f"Score: {subscore_value}")


# Bước 2: Sử dụng quy tắc YARA để quét thư mục và kiểm tra mã độc
# Lấy danh sách các tệp trong thư mục
for root, _, files in os.walk(files_directory):
    for filename in files:
        file_path = os.path.join(root, filename)
        
        # Chạy công cụ YARA với tệp hiện tại và tệp quy tắc yarGen
        cmd = f'{yara_path}\\yara64 -r {yara_rules} {file_path}'
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode == 0:
            # Nếu YARA tìm thấy khớp, tự động xóa tệp
            os.remove(file_path)
            print(f'Tệp {file_path} đã bị xóa do phát hiện mã độc.')
        else:
            print('Không phát hiện mã độc.')
os.remove(yara_rules)