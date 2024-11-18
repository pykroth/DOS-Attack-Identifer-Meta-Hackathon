import requests

def getDangerousIpAddress():
    # API key (replace with your actual key)
    api_key = "ebb99605cb21412fce5a2d2138650f14cab69d41f67f462d0824bec93161df55bc5320f93498c736"
    
    # Base URL for AbuseIPDB Reports
    url = "https://api.abuseipdb.com/api/v2/reports"
    
    # Set up headers with your API key
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    # Set parameters for your search
    params = {
        "ipAddress": "8.8.8.8",   # Add the specific IP address you're querying about
        "maxAgeInDays": 30,        # Reports from the past 30 days
        "page": 1,                 # Pagination (first page)
        "limit": 100               # Limit the number of results per request (max 100 per page)
    }
    
    # Make the API request
    response = requests.get(url, headers=headers, params=params)
    
    # Check if the request was successful
    if response.status_code == 200:
        try:
            data = response.json()  # Attempt to parse the response as JSON
            print(data)
            # Check if 'data' exists and is a list of reports
            if 'data' in data and isinstance(data['data'], list):
                # Extract the IP addresses from the response data
                ip_addresses = [report['ipAddress'] for report in data['data']]
                
            else:
                ip_addresses = []  # Return an empty list if no 'data' is found
                

        except ValueError as e:
            print("Error parsing JSON:", e)
            ip_addresses = []  # Return an empty list in case of JSON parsing error
            
    
    else:
        print(f"Error: {response.status_code}")
        print("Response content:", response.text)
        ip_addresses = []  # Return an empty list in case of HTTP request failure
    
    # Print the list of IP addresses for debugging
       
    
    # Return the list of IP addresses
    return ip_addresses
print(getDangerousIpAddress())

