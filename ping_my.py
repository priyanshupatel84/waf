
import requests
import time
import sys
from datetime import datetime

def ping_localhost():
    # url = "http://localhost:3000"
    url = "https://waf-1-rspr.onrender.com/health"
    
    try:
        response = requests.get(url, timeout=5)
        return response.status_code, response.elapsed.total_seconds()
    except requests.exceptions.RequestException as e:
        return None, str(e)

def main():
    # print("Pinging localhost:3000...")
    print("https://waf-1-rspr.onrender.com/health")
    
    # Single ping
    status, time_taken = ping_localhost()
    if status:
        print(f"HTTP Status: {status} | Response Time: {time_taken:.3f}s")
    else:
        print(f"Failed to connect: {time_taken}")
    
    print("\nStarting continuous ping (Press Ctrl+C to stop)...")
    
    try:
        while True:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status, time_taken = ping_localhost()
            
            if status:
                print(f"[{timestamp}] localhost:3000 is reachable (HTTP {status}) - {time_taken:.3f}s")
            else:
                print(f"[{timestamp}] localhost:3000 is not reachable - {time_taken}")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping ping...")
        sys.exit(0)

if __name__ == "__main__":
    main()