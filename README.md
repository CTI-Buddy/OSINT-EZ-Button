Here’s a **README.md** for your GitHub repo:  

---

# OSINT EZ Button 

## 🔍 Overview  
**OSINT EZ Button ** is a Python-based **automated reconnaissance tool** that gathers open-source intelligence (OSINT) on domains, IPs, emails, and usernames using publicly available APIs.  

## 🚀 Features  
- **Domain Reconnaissance** – WHOIS lookup, VirusTotal domain reputation  
- **IP Intelligence** – Shodan for open ports, GreyNoise for scanner detection  
- **Email Breach Check** – HaveIBeenPwned for breach history  
- **Username Enumeration** – GitHub user profile lookup  

## 📌 Installation  

1. Clone the repository:  
   ```bash
   git clone https://github.com/GrandpaRoger/OSINT-EZ-Button.git
   cd osint_recon
   ```
2. Install dependencies:  
   ```bash
   pip install -r requirements.txt  
   ```

## 🔧 Usage  
Run the tool with the appropriate mode and API keys:  

### 🖥️ Domain Recon  
```bash
python osint_recon.py --target example.com --mode domain --virustotal YOUR_VT_API_KEY
```
### 🌍 IP Intelligence  
```bash
python osint_recon.py --target 8.8.8.8 --mode ip --shodan YOUR_SHODAN_API_KEY --greynoise YOUR_GN_API_KEY
```
### 📧 Email Breach Check  
```bash
python osint_recon.py --target test@example.com --mode email --hibp YOUR_HIBP_API_KEY
```
### 👤 Username Lookup  
```bash
python osint_recon.py --target johndoe --mode username
```

## 🔑 API Keys  
This tool requires API keys for some services:  
- **Shodan**: [Get API Key](https://www.shodan.io/)  
- **VirusTotal**: [Get API Key](https://www.virustotal.com/)  
- **GreyNoise**: [Get API Key](https://www.greynoise.io/)  
- **HaveIBeenPwned**: [Get API Key](https://haveibeenpwned.com/)  

## 📄 License  
This project is licensed under the **MIT License**.  

## 🛠️ Contributing  
Pull requests are welcome! Feel free to improve functionality, add more OSINT sources, or enhance performance.  

## 🐛 Issues  
Report bugs and feature requests on [GitHub Issues](https://github.com/GrandpaRoger/OSINT-EZ-Button/issues).  

---

Let me know if you’d like any modifications! 🚀
