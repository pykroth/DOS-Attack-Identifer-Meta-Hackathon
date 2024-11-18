import requests

# API key (replace with your actual key)
api_key = "ebb99605cb21412fce5a2d2138650f14cab69d41f67f462d0824bec93161df55bc5320f93498c736"

# Base URL for AbuseIPDB Reports
url = "https://api.abuseipdb.com/api/v2/reports"

# Set up headers with your API key
headers = {
    "Key": api_key,
    "Accept": "application/json"
}

# Set parameters for your search (e.g., past 30 days)
params = {
    "maxAgeInDays": 30,  # Reports from the past 30 days
    "page": 1,           # Pagination (first page)
    "limit": 100         # Limit the number of results per request (max 100 per page)
}

# Make the API request
response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()

    # Extract the list of IPs from the reports
    ip_addresses = [report['ipAddress'] for report in data['data']]
    print("List of IPs from reports:")
    print(ip_addresses)
else:
    print(f"Error: {response.status_code}")