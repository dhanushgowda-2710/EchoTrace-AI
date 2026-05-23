# EchoTrace-AI
AI-powered scam detection and phishing analysis system
# EchoTrace AI 🚨

EchoTrace AI is a smart scam detection assistant designed to help users identify suspicious links, scam PDFs, fake voice calls and potentially harmful files directly through WhatsApp.

The project combines AI-based analysis with cybersecurity tools to provide quick risk detection and safety suggestions in a simple chat interface.

## What This Project Can Do

- Detect phishing or suspicious URLs
- Analyse PDF files for scam-related content
- Analyse voice recordings and scam calls
- Scan uploaded files using VirusTotal
- Respond directly through WhatsApp chatbot
- Handle multiple Gemini API keys automatically

## Technologies Used

- Python
- FastAPI
- Gemini AI
- WhatsApp Cloud API
- VirusTotal API
- Librosa
- NumPy

## Project Flow

User sends message/file/audio on WhatsApp  
↓  
FastAPI backend receives the request  
↓  
AI and security analysis is performed  
↓  
Risk level and safety advice are returned to the user

## Modules

### URL Analysis
Checks links for phishing patterns and suspicious behaviour.

### PDF Analysis
Analyses document content for scam phrases, fake financial messages and suspicious instructions.

### Audio Scam Detection
Uses Gemini AI and Librosa-based signal analysis to identify suspicious or AI-generated voice recordings.

### Malware/File Scan
Files are scanned using VirusTotal for possible threats.

## Installation
Install required packages:

```bash
pip install -r requirements.txt
```
Run the server:
```bash
uvicorn main:app --reload

## Configuration

Create a `config.py` file and add your API keys:

```python
GEMINI_API_KEYS=["YOUR_API_KEY"]
VIRUSTOTAL_API_KEY="YOUR_KEY"
WHATSAPP_TOKEN="YOUR_TOKEN"
WHATSAPP_PHONE_ID="YOUR_PHONE_ID"
VERIFY_TOKEN="YOUR_VERIFY_TOKEN"
```

---

## Future Scope

- Real-time call monitoring
- AI voice cloning detection
- Android application
- Dashboard for analytics
- Multi-language support

## License

MIT License
