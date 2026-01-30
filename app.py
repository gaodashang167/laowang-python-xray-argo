import os
import re
import json
import time
import base64
import shutil
import asyncio
import requests
import platform
import subprocess
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------- 环境变量 ----------------------
UPLOAD_URL = os.environ.get('UPLOAD_URL', '')
PROJECT_URL = os.environ.get('PROJECT_URL', '')
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', 'false').lower() == 'true'
FILE_PATH = os.environ.get('FILE_PATH', '.cache')
SUB_PATH = os.environ.get('SUB_PATH', 'sb')
UUID = os.environ.get('UUID', '907e9841-7abb-4013-91a4-3894d9e41928')
NEZHA_SERVER = os.environ.get('NEZHA_SERVER', 'mbb.svip888.us.kg:53100')
NEZHA_PORT = os.environ.get('NEZHA_PORT', '')
NEZHA_KEY = os.environ.get('NEZHA_KEY', 'VnrTnhgoack6PhnRH6lyshe4OVkHmPyM')
ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', 'share.svip888.us.kg')
ARGO_AUTH = os.environ.get('ARGO_AUTH', 'eyJhIjoiMGU3ZjI2MWZiY2ExMzcwNzZhNGZmODcxMzU3ZjYzNGQiLCJ0IjoiMTZhMjE2MjItNzZjNS00MzE0LWIxMzAtYzNlNjYxNzA5NmYyIiwicyI6IlpEYzJNR1ZsTVdZdE5UWm1ZUzAwWlRJeExXSTRNell0T0RJMVlXRTJNMlpsT1RZNSJ9')
ARGO_PORT = int(os.environ.get('ARGO_PORT', '8001'))
CFIP = os.environ.get('CFIP', 'spring.io')
CFPORT = int(os.environ.get('CFPORT', '443'))
NAME = os.environ.get('NAME', '')
CHAT_ID = os.environ.get('CHAT_ID', '')
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)

# ---------------------- 路径 ----------------------
sub_path = os.path.join(FILE_PATH, 'sub.txt')
list_path = os.path.join(FILE_PATH, 'list.txt')
boot_log_path = os.path.join(FILE_PATH, 'boot.log')
config_path = os.path.join(FILE_PATH, 'config.json')

# ---------------------- 工具函数 ----------------------
def create_directory():
    if not os.path.exists(FILE_PATH):
        os.makedirs(FILE_PATH)
        print(f"{FILE_PATH} created")
    else:
        print(f"{FILE_PATH} already exists")

def cleanup_old_files():
    for f in ['web','bot','npm','php','boot.log','list.txt']:
        path = os.path.join(FILE_PATH, f)
        try:
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
        except:
            pass

def get_system_architecture():
    arch = platform.machine().lower()
    return 'arm' if 'arm' in arch else 'amd'

def download_file(file_name, file_url):
    file_path = os.path.join(FILE_PATH, file_name)
    try:
        resp = requests.get(file_url, stream=True, timeout=15)
        resp.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in resp.iter_content(8192):
                f.write(chunk)
        print(f"{file_name} downloaded")
        return True
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        print(f"{file_name} download failed: {e}")
        return False

def authorize_files(file_paths):
    for f in file_paths:
        path = os.path.join(FILE_PATH, f)
        if os.path.exists(path):
            try:
                os.chmod(path, 0o775)
            except:
                pass

def exec_cmd(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return stdout + stderr
    except Exception as e:
        return str(e)

# ---------------------- HTTPServer ----------------------
class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == f'/{SUB_PATH}':
            try:
                with open(sub_path, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(content)
            except:
                self.send_response(404)
                self.end_headers()
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Hello World')
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args):
        pass

def run_server():
    server = ReusableHTTPServer(('', PORT), RequestHandler)
    print(f"Server running on port {PORT}")
    server.serve_forever()

# ---------------------- Telegram ----------------------
def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        with open(sub_path, 'r') as f:
            message = f.read()
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        escaped_name = re.sub(r'([_*\[\]()~>#+=|{}.!\-])', r'\\\1', NAME)
        params = {
            "chat_id": CHAT_ID,
            "text": f"**{escaped_name}节点推送通知**\n{message}",
            "parse_mode": "MarkdownV2"
        }
        requests.post(url, params=params)
        print("Telegram sent successfully")
    except Exception as e:
        print(f"Failed to send Telegram: {e}")

# ---------------------- 订阅生成 ----------------------
async def generate_links(argo_domain):
    try:
        resp = requests.get('https://api.ip.sb/geoip', headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        resp.raise_for_status()
        geo_data = resp.json()
    except:
        geo_data = {"country_code": "Unknown","isp":"Unknown"}

    country_code = geo_data.get('country_code', 'Unknown')
    isp = geo_data.get('isp', 'Unknown').replace(' ','_').strip()
    ISP = f"{NAME.strip()}-{country_code}_{isp}" if NAME and NAME.strip() else f"{country_code}_{isp}"

    VMESS = {
        "v":"2","ps":ISP,"add":CFIP,"port":CFPORT,"id":UUID,
        "aid":"0","scy":"none","net":"ws","type":"none",
        "host":argo_domain,"path":"/vmess-argo?ed=2560","tls":"tls",
        "sni":argo_domain,"alpn":"","fp":"chrome"
    }

    list_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{ISP}

vmess://{ base64.b64encode(json.dumps(VMESS).encode('utf-8')).decode('utf-8')}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{ISP}
"""

    with open(list_path, 'w', encoding='utf-8') as f:
        f.write(list_txt)
    sub_txt = base64.b64encode(list_txt.encode('utf-8')).decode('utf-8')
    with open(sub_path, 'w', encoding='utf-8') as f:
        f.write(sub_txt)
    print(sub_txt)
    send_telegram()
    return sub_txt

# ---------------------- 主流程 ----------------------
async def start_server_async():
    create_directory()
    cleanup_old_files()
    # 这里可以调用你的 download_files_and_run()，保持原逻辑
    # await download_files_and_run()

    # 启动 HTTPServer 线程
    server_thread = Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()

    # 模拟主循环
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(start_server_async())
