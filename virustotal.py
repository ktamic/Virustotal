import os
import sys
import json
import time
import hashlib
import requests
import argparse
clear = lambda: os.system('clear')
clear()
print('''
\x1b[34m _____  _                 _    ___  _         __ \x1b[0m
\x1b[34m|  |  ||_| ___  _ _  ___ | |_ |   || |_  ___ | ||\x1b[0m
\x1b[34m|  |  || ||  _|| | ||_ -||  _|| | ||  _|| .'|| ||\x1b[0m Github  : @timizart
\x1b[34m \___/ |_||_|  |___||___||_|  |___||_|  |__,||_||\x1b[0m

\x1b[34m[\x1b[0m Virustotal File Scanner \x1b[34m]\x1b[0m
''')
parser = argparse.ArgumentParser(description='Virustotal File Scanner (UNO)')
parser.add_argument('-f','--file', help='usage : '+os.path.basename(__file__)+' -f [file path]', required=True)
args = vars(parser.parse_args())
filename = args['file']
fileSha256 = hashlib.sha256(open(filename, 'rb').read()).hexdigest()
print('[*] Submited file : '+filename)
print('[\x1b[32m+\x1b[0m] File hash (sha256) : ',fileSha256)
statinfo = os.stat(filename)
Sizemb = statinfo.st_size / 10**6
print('[\x1b[32m+\x1b[0m] File size : ',Sizemb,'MB')
params = {'apikey': '', # <-- signup in virustotal and put your apikey here,
          'resource': fileSha256
         }
headers = {
"Accept-Encoding": "gzip, deflate",
"User-Agent" : "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:40.0) Gecko/20100001 Firefox/56.0.0"
  }
if params['apikey'] == '':
    print('[-] you need to insert APIKey in this file (signup in virustotal.com to generate it)')
    sys.exit()
elif Sizemb > 250:
    print('[-] Files cannot be larger than 256MB')
    sys.exit()
response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
  params=params, headers=headers)
json_response = response.json()
if json_response['response_code'] == 1:
    print('[\x1b[32m+\x1b[0m] virustotal recognize file hash, receving scan report . .')
    print('[\x1b[32m+\x1b[0m] Scanned in',':',json_response['scan_date'])
    print('[\x1b[32m+\x1b[0m] SHA256    ',':',json_response['sha256'])
    print('[\x1b[32m+\x1b[0m] Scanned by',json_response['total'],'Antivirus')
    for k in json_response['scans']:
        if json_response['scans'][k]['result'] == None:
            print('* ','{0: <22}'.format(k),': ','\x1b[32mClean\x1b[0m')
        elif json_response['scans'][k]['result'] != None:
            print('* ','{0: <22}'.format(k),':','\x1b[91m',json_response['scans'][k]['result'],'\x1b[0m')
    rescanOption = input('[*] Do you went re-scan it ? (yes/no) : ')
    if rescanOption == 'yes':
        rescanResponse = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
        params=params)
        responseResponse2 = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
        params=params, headers=headers)
        json_rescanResponse = responseResponse2.json()
        print('[\x1b[32m+\x1b[0m] Rescan request has been sended, please wait ..')
        time.sleep(140)
        print('[\x1b[32m+\x1b[0m] Scanned in',':',json_rescanResponse['scan_date'])
        print('[\x1b[32m+\x1b[0m] SHA256    ',':',json_rescanResponse['sha256'])
        print('[\x1b[32m+\x1b[0m] Scanned by',json_rescanResponse['total'],'Antivirus')
        for k in json_rescanResponse['scans']:
            if json_rescanResponse['scans'][k]['result'] == None:
                print('* ','{0: <22}'.format(k),': ','\x1b[32mClean\x1b[0m')
            elif json_rescanResponse['scans'][k]['result'] != None:
                print('* ','{0: <22}'.format(k),':','\x1b[91m',json_rescanResponse['scans'][k]['result'],'\x1b[0m')
    elif rescanOption == 'no':
        sys.exit()
elif json_response['response_code'] == 0:
    print("[*] VirusTotal didn't recognize to file hash, Trying to upload it . . ")
    params1 = {'apikey': params['apikey']}
    files = {'file': (filename, open(filename, 'rb'))}
    response1 = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params1)
    print('[*] Virustotal preparing scan report, please wait 5min or come back later [CTRL+C] . .')
    time.sleep(540)
    response2 = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
    json_response2 = response2.json()
    print('[\x1b[32m+\x1b[0m]',json_response2['verbose_msg'])
    print('[\x1b[32m+\x1b[0m] Scanned in',':',json_response2['scan_date'])
    print('[\x1b[32m+\x1b[0m] SHA256    ',':',json_response2['sha256'])
    print('[\x1b[32m+\x1b[0m] Scanned by',json_response2['total'],'Antivirus')
    for k in json_response2['scans']:
        if json_response2['scans'][k]['result'] == None:
            print('* ','{0: <22}'.format(k),': ','\x1b[32mClean\x1b[0m')
        elif json_response2['scans'][k]['result'] != None:
            print('* ','{0: <22}'.format(k),':','\x1b[91m',json_response2['scans'][k]['result'],'\x1b[0m')
elif json_response['response_code'] == -2:
    print('[*] Virustotal preparing scan report, please wait 4min . .')
    time.sleep(440)
    response3 = requests.get('https://www.virustotal.com/vtapi/v2/file/report',params=params, headers=headers)
    json_response3 = response3.json()
    print('[\x1b[32m+\x1b[0m]',json_response3['verbose_msg'])
    print('[\x1b[32m+\x1b[0m] Scanned in',':',json_response3['scan_date'])
    print('[\x1b[32m+\x1b[0m] SHA256    ',':',json_response3['sha256'])
    print('[\x1b[32m+\x1b[0m] Scanned by',json_response3['total'],'Antivirus')
    for k in json_response3['scans']:
        if json_response3['scans'][k]['result'] == None:
            print('* ','{0: <22}'.format(k),': ','\x1b[32mClean\x1b[0m')
        elif json_response3['scans'][k]['result'] != None:
            print('* ','{0: <22}'.format(k),':','\x1b[91m',json_response3['scans'][k]['result'],'\x1b[0m')
