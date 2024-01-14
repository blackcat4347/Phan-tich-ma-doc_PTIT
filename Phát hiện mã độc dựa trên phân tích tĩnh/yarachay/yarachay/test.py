import os
import requests
import PySimpleGUI as sg
import time
import hashlib
import matplotlib.pyplot as plt

sg.theme('DefaultNoMoreNagging')

# Gan Key API cua Virus Total
API_KEY = '8e0ef80a8953128bb4e3f0d73488a8b611d1455eae3ef3abc3b301d139e3ab26'


# Tao layout giao dien
layout = [
    [sg.Text('Select a file to scan for viruses:')],
    [sg.Input(key='file_path', enable_events=True, visible=False), sg.FileBrowse()],
    [sg.Button('Scan'), sg.Button('Xoa file')],
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
        
        if is_file_infected(result):
            sg.Popup('Warning: The file is infected!', title='Virus Scanner')
    
    except Exception as e:
        sg.Print(f'Error: {e}')
        pass
    
while True:
    event, values = window.read()

    # Xu ly su kien cua so
    if event == sg.WIN_CLOSED:
        break
    elif event == 'file_path':
        file_path = values['file_path']
    elif event == 'Scan':
        file_path = values['file_path']
        if not os.path.isfile(file_path):
            sg.Print('Error: Please select')
