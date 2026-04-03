import requests

def get_virustotal(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        reputation = data["data"]["attributes"].get("reputation", "N/A")

        return {
            "reputation": reputation,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    except Exception as e:
        return {"error": str(e)}