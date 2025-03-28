
---

# Technical & Cybersecurity Documentation for the User Data Capture PDF System

## Overview

This project implements a system designed to capture client-side data at the time of a PDF download. The system is implemented using a Flask application (in `app(3).py`) and leverages modern libraries including ReportLab for PDF generation, Faker for generating fake content, Fernet for encryption, and Stegano for steganography. The solution is particularly useful in forensic analysis and cybersecurity investigations, such as identifying internal harassment within an organization.

## Features

- **Client-Side Data Capture:**  
  Collects detailed metadata such as screen dimensions, user-agent, canvas fingerprints, and various timing metrics via an HTML/JavaScript form.

- **Server-Side Processing:**  
  Processes the collected data using Flask. This includes:
  - Extracting IP addresses and performing geolocation lookups (via ipinfo.io).
  - Logging data with timestamps to ensure forensic traceability.
  
- **PDF Generation:**  
  - Generates a PDF document with fake content (using Faker) to obfuscate real data.
  - Embeds an image that hides encrypted data using steganography.
  - Integrates custom metadata and JavaScript callbacks for token-based verification.

- **Security & Forensic Readiness:**  
  - Employs encryption (Fernet) and steganography to protect and hide sensitive data.
  - Implements token verification via embedded JavaScript callbacks.
  - Simulates multi-stage payloads and DLL injection (for demonstration purposes) to test system robustness.

## System Architecture

The project is modularized into three main groups:
- **Client Module:**  
  HTML/JavaScript form that captures user data.
  
- **Server Module:**  
  Flask-based backend managing:
  - Data collection and logging.
  - PDF generation.
  - Encryption and steganography.
  - Verification callbacks.
  - Simulation of payloads for testing.
  
- **External Services & Libraries:**  
  Integration with external services (like ipinfo.io) and libraries (ReportLab, PyPDF2, Fernet, Stegano).

*Detailed diagrams (component, sequence, activity, use-case, and optional deployment diagrams) are provided in the accompanying technical documentation.*

## Documentation

Comprehensive technical documentation is included in the LaTeX report provided with the project. This report covers:

1. **Introduction & Overview** – Purpose, context, and system objectives.
2. **System Architecture** – Detailed module breakdown and diagrams.
3. **Data Collection & Logging** – Client-side capture and server-side logging mechanisms.
4. **PDF Generation Process** – How fake content is created and embedded.
5. **Encryption & Steganography** – Techniques for protecting and hiding data.
6. **Verification & Callback Mechanisms** – Token generation and callback processing.
7. **Security & Simulated Payloads** – Demonstrations of multi-stage payloads and risk mitigation.
8. **Forensic & Cybersecurity Analysis** – Compliance, data integrity, and forensic handling.

Please refer to the compiled `documentation.pdf` for complete details.

## Setup and Usage

### Prerequisites

- Python 3.x
- Flask, ReportLab, PyPDF2, cryptography, Stegano, Faker, Pillow, and other dependencies

### Installation

Install the required Python packages using pip:

```bash
pip install flask reportlab pypdf2 cryptography stegano faker pillow requests
```

### Running the Application

Run the Flask server by executing:

```bash
python app(3).py
```

By default, the application will run on port 5000. Open your browser and navigate to `http://localhost:5000` to access the PDF download page.

### Using the Application

1. Access the download page.
2. Submit the form to initiate the PDF generation.
3. The system will capture client data, generate a PDF with embedded hidden data, and log all interactions.
4. When the PDF is opened, embedded JavaScript callbacks will verify the token and log the access for forensic tracking.

## Forensic and Cybersecurity Considerations

- **Chain-of-Custody:**  
  Logs and captured data are maintained with integrity and timestamping for potential legal proceedings.
  
- **Data Integrity:**  
  Encryption and secure logging practices ensure the evidence remains untampered.

- **Audit and Monitoring:**  
  Detailed logging and callback verifications create a robust audit trail essential for forensic investigations, especially in cases involving harassment.

## Contributing

Contributions to improve functionality, enhance security features, or extend documentation are welcome. Please follow the coding standards and update the documentation accordingly.



---
