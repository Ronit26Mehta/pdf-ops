
# SecureDrop: A Flask Application to Identify Organizational Harassers

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

SecureDrop is a web application built with Flask, designed to covertly collect user data and assist organizations in identifying harassers. Presented as a complaint management system, it gathers extensive device and user information, embeds tracking data in downloadable PDFs, and leverages AI-driven analysis to detect patterns of harassment.

## Table of Contents
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Features
- **User Authentication**: Secure login with session management.
- **Permissions Handling**: Requests access to location, camera, and microphone.
- **Data Collection**: Captures IP, geolocation, device fingerprints, and more.
- **PDF Tracking**: Embeds encrypted data and verification links in PDFs.
- **AI Integration**: Uses Gemini AI for investigative reports.
- **Email Reporting**: Sends collected data periodically via SMTP.
- **Logging**: Records user activities and stores captured images.

## How It Works
SecureDrop operates under the guise of a complaint management system:
1. Users log in and grant permissions for location, camera, and microphone access.
2. The application collects detailed data (e.g., IP, device info, geolocation) during interactions.
3. Users download PDFs containing fake complaint data, which secretly embed encrypted user information and a unique verification link.
4. When a PDF is opened and the link clicked, the system logs the event, linking it to the user's data.
5. Gemini AI analyzes the data to identify harassment patterns, and results are emailed for further investigation.

This approach helps pinpoint harassers by tracking their interactions and correlating them with collected evidence.

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- A Gemini API key (set as `GEMINI_API_KEY` environment variable)
- SMTP credentials (optional, for email functionality)

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/securedrop.git
   cd securedrop
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Example `requirements.txt`:
   ```
   flask
   requests
   reportlab
   cryptography
   stegano
   pillow
   PyPDF2
   netifaces
   google-generativeai
   faker
   ```

4. **Configure Environment Variables**:
   Create a `.env` file or set variables directly:
   ```bash
   export GEMINI_API_KEY="your-gemini-api-key"
   export SMTP_SERVER="smtp.gmail.com"
   export SMTP_PORT=587
   export SMTP_USER="your-email@gmail.com"
   export SMTP_PASSWORD="your-app-password"
   export RECIPIENT_EMAIL="recipient-email@gmail.com"
   ```

5. **Run the Application**:
   ```bash
   python app.py
   ```
   The app will start on `http://0.0.0.0:5000`.

## Usage
1. **Access the Login Page**: Open `http://localhost:5000` in a browser.
2. **Sign In**: Enter a phone number, email, and password (no validation, for demo purposes).
3. **Grant Permissions**: Allow access to location, camera, and microphone when prompted.
4. **View Complaints**: Navigate to the drive page to see sample complaints.
5. **Download PDF**: Click "Download Data" to receive a PDF with embedded tracking.
6. **Monitor Logs**: Check `user_logs.log` and `static/captures` for collected data.

### Example Workflow
- A user logs in and downloads a PDF.
- The PDF contains a link (e.g., `https://pdf-ops.onrender.com/verify?token=uuid`).
- Clicking the link triggers a callback, logging the user's identity and data.

## Documentation
Detailed documentation is available in LaTeX format:
- **Source**: [securedrop_doc.tex](securedrop_doc.tex)
- **Compiled PDF**: [securedrop_doc.pdf](securedrop_doc.pdf) (if included)

To compile the LaTeX documentation:
1. Install a LaTeX distribution (e.g., TeX Live).
2. Run:
   ```bash
   pdflatex securedrop_doc.tex
   ```
3. Open the generated `securedrop_doc.pdf`.

The documentation covers:
- System architecture with flow diagrams.
- In-depth analysis of each component with code snippets and pseudo code.
- How SecureDrop identifies harassers.
- Security and ethical considerations.

## Contributing
Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

