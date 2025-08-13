import requests
from langchain_groq import ChatGroq

# API keys for VirusTotal and Groq
VT_API_KEY = os.getenv("VT_API_KEY")      #  VirusTotal
GROQ_API_KEY = os.getenv("GROQ_API_KEY")  #  Groq

# Function to check IP with VirusTotal
def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data['data']['attributes']['last_analysis_stats']['malicious']
    else:
        return None

# Initialize Groq LLM
llm = ChatGroq(
    groq_api_key=GROQ_API_KEY,
    model_name="llama3-8b-8192"
)

# Function to explain the result
def explain_result(ip, malicious_count):
    if malicious_count is None:
        prompt = f"Unable to check IP {ip}. Explain possible reasons in cybersecurity terms."
    elif malicious_count > 0:
        prompt = f"The IP {ip} has {malicious_count} malicious reports in VirusTotal. Explain what this means for a SOC analyst."
    else:
        prompt = f"The IP {ip} has no malicious reports in VirusTotal. Explain what this means for a SOC analyst."
    
    return llm.invoke(prompt).content

# Main execution
if __name__ == "__main__":
    ip = input("Enter IP to check: ")
    malicious_count = check_ip(ip)

    if malicious_count is None:
        print(f"\n Could not check IP {ip} — API error or no data.")
    elif malicious_count > 0:
        print(f"\n MALICIOUS: {ip} flagged by {malicious_count} security vendors.")
    else:
        print(f"\n CLEAN: {ip} not flagged by any security vendors.")

    explanation = explain_result(ip, malicious_count)
    print("\n--- AI Report ---\n", explanation)
