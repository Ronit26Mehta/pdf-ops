from flask import Flask, request, render_template_string, send_file
import logging
from faker import Faker
from io import BytesIO
from reportlab.pdfgen import canvas
import os

app = Flask(__name__)

# Configure logging to a file
logging.basicConfig(
    level=logging.INFO,
    filename='user_logs.log',
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize Faker
fake = Faker()

# HTML page with a styled download button
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
        h1 {
            color: #333;
        }
        button {
            padding: 15px 30px;
            font-size: 18px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <h1>Click to Download PDF and Log Your Data</h1>
    <form action="/download" method="post">
        <button type="submit">Download PDF</button>
    </form>
    <br>
    <!-- Link to view logs (for admin/development only) -->
    <a href="/logs">View Logged Data</a>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/download', methods=['POST'])
def download():
    # Fetch the client's IP address (using X-Forwarded-For if available)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    # Log the IP, user agent, and the download action
    log_message = f"IP: {ip}, User-Agent: {user_agent}, Action: Downloaded PDF"
    logging.info(log_message)
    
    # Generate a PDF using ReportLab and Faker
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    
    # Generate fake text content using Faker
    fake_name = fake.name()
    fake_address = fake.address().replace("\n", ", ")
    fake_text = fake.text(max_nb_chars=200)
    
    # Draw text on the PDF
    p.drawString(100, 750, "Fake PDF Document")
    p.drawString(100, 730, f"Name: {fake_name}")
    p.drawString(100, 710, f"Address: {fake_address}")
    p.drawString(100, 690, "Additional Info:")
    
    # Add a block of fake text starting at y=670
    text_object = p.beginText(100, 670)
    text_object.textLines(fake_text)
    p.drawText(text_object)
    
    p.showPage()
    p.save()
    buffer.seek(0)
    
    # Send the PDF as a file download
    return send_file(buffer, as_attachment=True, download_name='sample.pdf', mimetype='application/pdf')

# Admin/Development-only endpoint to display the logged user data
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
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                background-color: #f9f9f9; 
            }
            h1 { color: #333; }
            pre { 
                background: #eee; 
                padding: 15px; 
                border-radius: 5px; 
                overflow: auto; 
            }
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
