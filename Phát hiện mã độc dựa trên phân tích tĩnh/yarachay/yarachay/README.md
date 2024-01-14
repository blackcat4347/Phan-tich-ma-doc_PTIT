# Virus-Scanner-With-Python

This is a simple Python Virus scanner using Virus Total API and PySimpleGUI interface. You can use it to scan suspicious files in the system. In this version, it can only scan 1 file at a time, you can also customize the code to have it scan the whole folder or use the CLI interface. VirusTotal's free API limits 4 requests per minute and 500 requests per day. I think this is enough for you to discover.
# Requirements
- Python 3.x
- [PySimpleGUI](https://pypi.org/project/PySimpleGUI/)
- [requests](https://pypi.org/project/requests/)
# Setup
1. Login to [VirusTotal](https://www.virustotal.com/gui/sign-in) and get the API key.
2. Clone this repository to your PC:
```
git clone https://github.com/ellyx13/Virus-Scanner-With-Python.git
```
3. In virus_Scanner.py, define a variable called API_KEY and set its value to your VirusTotal API key: 

```
API_KEY = 'KEY_API_VIRUS_TOTAL
```

4. Install dependency Python packages:

```
python install -r requirements.txt
```
# Usage

Open terminal and go to the folder containing the virus_Scanner.py file and run the command below:

```
python virus_Scanner.py
```

You will see the graphical interface open. You just need to click **Browse** and select the file you want to **scan**, then click scan and wait for the results.

