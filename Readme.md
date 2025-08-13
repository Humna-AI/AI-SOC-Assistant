# 🛡AI SOC Assistant

An **AI-powered Security Operations Center (SOC) Assistant** that checks IP addresses for malicious activity using **VirusTotal** and provides AI-generated cybersecurity explanations using **Groq Cloud (LangChain + LLaMA)**.

---

## Features
- **Malicious IP Detection** via VirusTotal API.
- **AI-powered explanation** of threat severity for SOC analysts.
- Uses **Groq Cloud API** with LangChain for natural language explanations.
- Supports real-time IP checks and automated security insights.

---

## Project Structure
AI-SOC-Assistant/
│
├── SOC_agent.py # Main program to run the tool
├── .env # Store your API keys (not pushed to GitHub)
├── requirements.txt # Project dependencies
├── README.md # Project documentation
└── screenshots/ # Project screenshots


---

## 🔧 Installation

### 1️Clone the repository
```bash
git clone https://github.com/Humna-AI/AI-SOC-Assistant.git
cd AI-SOC-Assistant

Create and activate virtual environment
python -m venv venv

source venv/bin/activate   # On Mac/Linux
venv\Scripts\activate      # On Windows
Install dependencies

pip install -r requirements.txt
 Setup API Keys
 This is where you set your environment variables — Create a .env file in the root folder and add:

.env

VIRUSTOTAL_API_KEY=your_virustotal_api_key
GROQ_API_KEY=your_groq_api_key

Do not share this file or push it to GitHub.
.gitignore is already set to hide .env.


Run the script:
python SOC_agent.py
Example Output:
Enter IP to check: 45.33.32.156
--- Report ---
This IP has been reported malicious 5 times. It may be linked to known botnets...

