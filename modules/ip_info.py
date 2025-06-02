import requests
import socket

def run(domain):
    print(f"\n[IP INFO] Getting geolocation and host info for: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()

        print(f" IP Address: {ip}")
        print(f" Country: {data.get('country')}")
        print(f" Region: {data.get('region')}")
        print(f" City: {data.get('city')}")
        print(f" Org: {data.get('org')}")
        print(f" Location (Lat,Long): {data.get('loc')}")
        print(f" Timezone: {data.get('timezone')}")
    except Exception as e:
        print(f" [ERROR] Failed to get IP info: {e}")
