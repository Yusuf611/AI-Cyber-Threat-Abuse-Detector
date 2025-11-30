import requests
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSEIPDB_KEY")  

def check_ip_reputation(ip_address):
    """
    
    """
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 180
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()

        if "data" not in data:
            return None, "Invalid response from AbuseIPDB"

        return data["data"], None

    except Exception as e:
        return None, str(e)
