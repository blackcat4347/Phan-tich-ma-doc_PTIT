import os
import requests
import PySimpleGUI as sg
import time
import hashlib
# import matplotlib.pyplot as plt
import shutil
import subprocess
import re
sg.theme('DefaultNoMoreNagging')
# Gan Key API cua Virus Total
API_KEY = '8e0ef80a8953128bb4e3f0d73488a8b611d1455eae3ef3abc3b301d139e3ab26'
# Tao layout giao dien
layout = [
    [sg.Text('Select a file to scan for viruses:')],
    [sg.Input(key='file_path', enable_events=True, visible=False), sg.FileBrowse()],
    [sg.Button('Scan with VirusTotal'),sg.Button('Scan with Yara'),sg.Button('Delete file')],
    [sg.Output(size=(80, 20))]
]
# Tao cua so
window = sg.Window('Virus Scanner', layout)

def delete_file(file_path):
    try:
        os.remove(file_path)
    except Exception as e:
        print(f'Error deleting file: {e}')
def is_file_infected(scan_result):
    positives = scan_result['positives']
    total = scan_result['total']
    return positives / total > 0.5

def scan_file(file_path):
    try:
        # Mo va doc noi dung trong file
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Gui file toi Virus Total de quet
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': API_KEY}
        files = {'file': ('file', file_content)}
        response = requests.post(url, files=files, params=params)

        # Lay ID scan tu reqsponse tra ve
        scan_id = response.json()['scan_id']

        # Kiem tra ket qua quet moi 15 giay cho den khi hoan tat
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': API_KEY, 'resource': scan_id}
        while True:
            response = requests.get(url, params=params)
            result = response.json()
            if 'scan_date' in result and result['scan_date'] != '1970-01-01 00:00:00':
                break
            time.sleep(15)

        # Hien thi ket qua quet ra man hinh
        sg.Print('Scan Results:')
        # In ra mã hàm băm của tệp tin
        total = 0
        detected = 0
        positives = result['positives']
        total = result['total']
        sg.Print(f'Có: {positives}/{total}')
        md5_hash = hashlib.md5(file_content).hexdigest()
        sg.Print(f'MD5 Hash: {md5_hash}')
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sg.Print(f'SHA-1 Hash: {sha1_hash}')
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        sg.Print(f'SHA-256: {sha256_hash}')
        for scanner, result in result['scans'].items():
            sg.Print(f'{scanner}: {result["result"]}')
        
    except Exception as e:
        sg.Print(f'Error: {e}')
        pass
def scan_file_with_yara():
    try:
        yara_path = r'F:\yarachay'

        # Đường dẫn đến thư mục chứa các tệp bạn muốn kiểm tra
        files_directory = r'F:\yarachay\madoc'

        # Bước 1: Chạy yarGen để tạo quy tắc YARA từ các mẫu mã độc
        yarGen_cmd = f'python {yara_path}\yarGen.py --score -m {files_directory} -r yargen_rules.yar'
        subprocess.run(yarGen_cmd, shell=True)

        # Đường dẫn đến tệp quy tắc YARA được tạo bởi yarGen
        yara_rules = 'F:\yarachay\yargen_rules.yar'

        # Đường dẫn đến loki.exe
        loki_path = 'F:\yarachay\loki'
        # Thực hiện quét malware bằng Loki
        loki_command = f"{loki_path}\loki.exe -p {files_directory}"
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
        sg.Print(f"Score: {subscore_value}")


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
                    sg.Print(f'Tệp {file_path} đã phát hiện mã độc.')
                else:
                    sg.Print('Không phát hiện mã độc.')
        os.remove(yara_rules)
    except Exception as e:
        sg.Print(f'Error: {e}')
        pass
# def scan_with_yara(file_path):

#     # Run the Yara scanner
#     yara_cmd = 'python D:\DEMO\yarachay\yarachay\Thucthi.py {}'.format(file_path)
#     os.system(yara_cmd) 
while True:
    event, values = window.read()

    # Xu ly su kien cua so
    if event == sg.WIN_CLOSED:
        break
    elif event == 'file_path':
        file_path = values['file_path']
        #os.rename(file_path, os.path.join(file_path, os.path.basename(file_path)))
        shutil.copy(file_path, 'F:\yarachay\madoc')
    elif event == 'Scan with VirusTotal':
        file_path = values['file_path']
        if not os.path.isfile(file_path):
            sg.Print('Error: Please select a valid file.')
        else:
            sg.Print(f'Scanning file: {file_path} Please wait ..')
            scan_file(file_path)
    elif event == "Delete file":
        delete_file(values['file_path'])
    elif event == 'Scan with Yara':
        # Scan the file with Yara
        #scan_with_yara(values['file_path'])
        scan_file_with_yara()
# Dong cua so
window.close()