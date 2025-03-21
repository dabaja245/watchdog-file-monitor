import requests

# Replace 'your_api_key_here' with your actual VirusTotal API key
api_key = ''
file_hash = ''

url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

headers = {
    "x-apikey": api_key,
    "accept": "application/json"
}

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    report = response.json()
    print("VirusTotal report:", report)
except requests.exceptions.RequestException as e:
    print("Error retrieving VirusTotal report:", e)
