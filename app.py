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

def get_ip_geolocation(ip):
    """Fetch geolocation data from ipinfo.io."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",")
            return float(loc[0]) if loc else None, float(loc[1]) if loc else None, data
    except Exception as e:
        logging.error(f"IP Geolocation error: {e}")
    return None, None, {}

def collect_data(request):
    """Collect client-side and server-side data."""
    ip_header = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip_header.split(",")[0].strip() if ip_header else request.remote_addr
    user_agent = request.headers.get('User-Agent', 'unknown')
    cookies = request.cookies
    tls_metadata = request.environ.get('wsgi.url_scheme')

    client_data = {
        'screenWidth': request.form.get('screenWidth'),
        'screenHeight': request.form.get('screenHeight'),
        'colorDepth': request.form.get('colorDepth'),
        'pixelDepth': request.form.get('pixelDepth'),
        'language': request.form.get('language'),
        'platform': request.form.get('platform'),
        'connection': request.form.get('connection'),
        'pageLoadTime': request.form.get('pageLoadTime'),
        'clickTime': request.form.get('clickTime'),
        'dwellTime': request.form.get('dwellTime'),
        'lastMouseX': request.form.get('lastMouseX'),
        'lastMouseY': request.form.get('lastMouseY'),
        'referrer': request.form.get('referrer'),
        'canvasFingerprint': request.form.get('canvasFingerprint'),
        'hardwareConcurrency': request.form.get('hardwareConcurrency'),
        'deviceMemory': request.form.get('deviceMemory'),
        'timezoneOffset': request.form.get('timezoneOffset'),
        'touchSupport': request.form.get('touchSupport'),
        'batteryLevel': request.form.get('batteryLevel'),
        'charging': request.form.get('charging'),
        'downlink': request.form.get('downlink'),
        'plugins': request.form.get('plugins')
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
        'request_headers': dict(request.headers),
        'cookies': cookies,
        'tls_metadata': tls_metadata
    }
    return log_message

def embed_data_in_image(data):
    """Embed encrypted data in an image using steganography."""
    encrypted_data = CIPHER.encrypt(json.dumps(data).encode())
    # Create a simple base image (in production, use a pre-existing image)
    base_img = PILImage.new('RGB', (100, 100), color='white')
    temp_path = 'temp_base.png'
    base_img.save(temp_path)
    stego_img = lsb.hide(temp_path, encrypted_data)
    os.remove(temp_path)
    return stego_img

def generate_pdf(logged_data):
    """Generate a PDF with fake content and embedded steganographic data."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Fake content
    story.append(Paragraph("Fake PDF Document", styles['Title']))
    story.append(Paragraph(f"Name: {fake.name()}", styles['Normal']))
    story.append(Paragraph(f"Address: {fake.address().replace('\n', ', ')}", styles['Normal']))
    story.append(Paragraph("Additional Info:", styles['Normal']))
    story.append(Paragraph(fake.text(max_nb_chars=200), styles['Normal']))

    # Embed data in an image
    stego_img = embed_data_in_image(logged_data)
    img_buffer = BytesIO()
    stego_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    story.append(Image(img_buffer, width=100, height=100))

    # Verification link with unique token
    token = str(uuid.uuid4())
    verification_link = f"https://pdf-ops.onrender.com/verify?token={token}"
    story.append(Paragraph(f"Please <a href='{verification_link}'>click here</a> to verify you opened this PDF.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer, token

# HTML page with a styled download button and embedded JavaScript to capture client-side data.
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
        <!-- Hidden fields for basic client-side data -->
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
        <!-- Hidden fields for advanced client-side data -->
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
    <!-- Link to view logs (for admin/development only) -->
    <a href="/logs">View Logged Data</a>
    <script>
        // Record page load time
        var pageLoadTime = Date.now();
        document.getElementById('pageLoadTime').value = pageLoadTime;
        
        // Capture last mouse position
        var lastMouseX = 0, lastMouseY = 0;
        document.addEventListener('mousemove', function(e) {
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
        });
        
        // Function to gather extra client data
        function gatherExtraData(callback) {
            // Canvas fingerprinting
            var canvas = document.createElement("canvas");
            var ctx = canvas.getContext("2d");
            ctx.textBaseline = "top";
            ctx.font = "14px Arial";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = "#069";
            ctx.fillText("Hello, world!", 2, 15);
            document.getElementById('canvasFingerprint').value = canvas.toDataURL();
            
            // Hardware and system details
            document.getElementById('hardwareConcurrency').value = navigator.hardwareConcurrency || '';
            document.getElementById('deviceMemory').value = navigator.deviceMemory || '';
            document.getElementById('timezoneOffset').value = new Date().getTimezoneOffset();
            document.getElementById('touchSupport').value = ('ontouchstart' in window) ? true : false;
            
            // Installed plugins
            if (navigator.plugins) {
                var plugins = Array.from(navigator.plugins).map(function(p) { return p.name; });
                document.getElementById('plugins').value = plugins.join(', ');
            } else {
                document.getElementById('plugins').value = '';
            }
            
            // Network downlink info
            if (navigator.connection && navigator.connection.downlink) {
                document.getElementById('downlink').value = navigator.connection.downlink;
            } else {
                document.getElementById('downlink').value = '';
            }
            
            // Battery information
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
        
        // Intercept form submission to capture client-side data
        document.getElementById('downloadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            // Populate basic hidden fields
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
            
            // Gather extra data then submit the form
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
    # Collect and log initial data
    logged_data = collect_data(request)
    logging.info(json.dumps(logged_data))

    # Generate PDF with embedded data and verification token
    pdf_buffer, token = generate_pdf(logged_data)
    logged_tokens[token] = logged_data

    return send_file(pdf_buffer, as_attachment=True, download_name='sample.pdf', mimetype='application/pdf')

@app.route('/verify', methods=['GET'])
def verify():
    """Handle PDF open verification via token."""
    token = request.args.get('token')
    if token in logged_tokens:
        logging.info(f"PDF opened for token: {token} - Data: {json.dumps(logged_tokens[token])}")
        # Optionally remove token after verification
        del logged_tokens[token]
        return "Thank you for verifying!", 200
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
