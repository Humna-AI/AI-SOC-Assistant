# AI SOC Assistant – Automated Threat Analysis

## 📌 Overview
This project is part of my **AI for Cybersecurity journey** where I combine my cybersecurity skills with **AI agent technology** to build tools that make Security Operations Center (SOC) work faster, easier, and less repetitive.

---

## 🚀 Features

### **Day 1 – Manual AI SOC Assistant**
- Looks up suspicious IP addresses via **VirusTotal API**.
- Uses **LangChain + OpenAI** to explain the results in natural, analyst-friendly language.
- Helps analysts save time by reducing manual threat lookups.

---

### **Day 2 – Automated Threat Analysis with n8n + Groq**
- **n8n Workflow** automatically triggers IP lookups via **VirusTotal API**.
- **Groq LLM** generates concise, analyst-friendly threat intelligence reports.
- Fully automated — from input to final analysis — no manual steps required.
- Runs in seconds, freeing SOC analysts for deeper security investigations.

---

## 🛠️ Tech Stack
- **VirusTotal API**
- **LangChain**
- **OpenAI API**
- **Groq LLM**
- **n8n** (Workflow Automation)

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

