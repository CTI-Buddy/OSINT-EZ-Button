import requests
import argparse
import json

def shodan_lookup(api_key, target):
    url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {"error": "Shodan lookup failed"}

def whois_lookup(target):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_API_KEY&domainName={target}&outputFormat=json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {"error": "WHOIS lookup failed"}

def hibp_lookup(api_key, email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": api_key, "User-Agent": "OSINT-Recon-Tool"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {"error": "No breaches found or API limit exceeded"}

def github_username_lookup(username):
    url = f"https://api.github.com/users/{username}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {"error": "GitHub user not found"}

def virustotal_lookup(api_key, target):
    url = f"https://www.virustotal.com/api/v3/domains/{target}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {"error": "VirusTotal lookup failed"}

def greynoise_lookup(api_key, ip):
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": api_key, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {"error": "GreyNoise lookup failed"}

def main():
    parser = argparse.ArgumentParser(description="Automated OSINT Recon Tool")
    parser.add_argument("--target", required=True, help="Domain, IP, email, or username to search")
    parser.add_argument("--shodan", help="Shodan API key")
    parser.add_argument("--hibp", help="HaveIBeenPwned API key")
    parser.add_argument("--virustotal", help="VirusTotal API key")
    parser.add_argument("--greynoise", help="GreyNoise API key")
    parser.add_argument("--mode", choices=["domain", "ip", "email", "username"], required=True, help="Type of target")
    
    args = parser.parse_args()
    results = {}
    
    if args.mode == "ip":
        if args.shodan:
            results["Shodan"] = shodan_lookup(args.shodan, args.target)
        if args.greynoise:
            results["GreyNoise"] = greynoise_lookup(args.greynoise, args.target)
    
    if args.mode == "domain":
        results["WHOIS"] = whois_lookup(args.target)
        if args.virustotal:
            results["VirusTotal"] = virustotal_lookup(args.virustotal, args.target)
    
    if args.mode == "email" and args.hibp:
        results["HIBP"] = hibp_lookup(args.hibp, args.target)
    
    if args.mode == "username":
        results["GitHub"] = github_username_lookup(args.target)
    
    print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
