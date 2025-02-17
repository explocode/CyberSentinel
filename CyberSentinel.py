import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import time
import sys
import socket
from termcolor import colored

def typewriter_effect(text, speed=0.05):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()

def print_colored(text, color='white', attrs=None):
    print(colored(text, color, attrs=attrs))

def scan_website(domain):
    base_url = f"http://{domain}"
    typewriter_effect(f"\n{colored('[INFO] Starting scan for domain ' + base_url, 'cyan')}...", 0.1)
    
    try:
        response = requests.get(base_url)
        if response.status_code != 200:
            print_colored(f"[ERROR] Website is not reachable. Status code: {response.status_code}", 'red')
            return

        print_colored(f"[INFO] Website reachable successfully. Status code: {response.status_code}", 'green')
        
        all_links = crawl_website(base_url)

        vulnerabilities = []

        for link in all_links:
            print_colored(f"\n[INFO] Scanning page: {link}", 'yellow')
            page_response = requests.get(link)
            if page_response.status_code == 200:
                page_vulnerabilities = check_vulnerabilities(link, page_response)
                vulnerabilities.extend(page_vulnerabilities)
            else:
                print_colored(f"[WARNING] Page not reachable: {link} ({page_response.status_code})", 'yellow')

        vulnerabilities.extend(scan_for_login_panels(base_url))
        vulnerabilities.extend(scan_for_data_collectors(base_url))
        vulnerabilities.extend(scan_ports(domain))

        print_summary(vulnerabilities)

    except requests.exceptions.RequestException as e:
        print_colored(f"[ERROR] An error occurred while connecting to the website: {e}", 'red')

def crawl_website(base_url):
    all_links = set()
    print_colored(f"\n[INFO] Crawling the website {base_url}...", 'magenta')
    
    response = requests.get(base_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(base_url, href)
        
        if urlparse(full_url).netloc == urlparse(base_url).netloc and full_url not in all_links:
            all_links.add(full_url)
    
    print_colored(f"[INFO] Found {len(all_links)} links during crawling.", 'green')
    return all_links

def check_vulnerabilities(url, response):
    print_colored(f"\n[INFO] Checking vulnerabilities for {url}", 'cyan')
    vulnerabilities = []

    vulnerabilities.extend(check_sql_injection(url, response))
    vulnerabilities.extend(check_xss(url, response))
    vulnerabilities.extend(check_server_errors(url, response))
    vulnerabilities.extend(check_file_inclusion(url, response))
    vulnerabilities.extend(check_csrf(url, response))
    vulnerabilities.extend(check_insecure_headers(url, response))
    vulnerabilities.extend(check_directory_traversal(url, response))
    
    return vulnerabilities

def check_sql_injection(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for SQL Injection on {url}", 'yellow')
    sql_patterns = ["' OR 1=1 --", "1' OR '1'='1", "'; DROP TABLE", "OR 1=1"]
    
    for pattern in sql_patterns:
        test_url = f"{url}?q={pattern}"
        try:
            test_response = requests.get(test_url)
            if "error" in test_response.text.lower() or "Warning" in test_response.text:
                vulnerabilities.append(f"[VULNERABILITY] Possible SQL Injection vulnerability in {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def check_xss(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for XSS vulnerability on {url}", 'yellow')
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}"
        try:
            test_response = requests.get(test_url)
            if payload in test_response.text:
                vulnerabilities.append(f"[VULNERABILITY] Possible XSS vulnerability in {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def check_server_errors(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for server errors on {url}", 'yellow')
    error_patterns = [r"Warning", r"Error", r"SQLException", r"Uncaught", r"Traceback", r"Stack"]
    
    for pattern in error_patterns:
        if re.search(pattern, response.text):
            vulnerabilities.append(f"[VULNERABILITY] Server error found on {url}: {pattern}")
    return vulnerabilities

def check_file_inclusion(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for file inclusion on {url}", 'yellow')
    include_patterns = ["../", "%2e%2e%2f", "/etc/passwd"]
    
    for pattern in include_patterns:
        test_url = f"{url}{pattern}"
        try:
            test_response = requests.get(test_url)
            if "error" in test_response.text.lower():
                vulnerabilities.append(f"[VULNERABILITY] Possible File Inclusion vulnerability in {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def check_csrf(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for CSRF vulnerability on {url}", 'yellow')
    csrf_patterns = ["<form", "<input type='hidden' name='csrf_token'"]
    
    for pattern in csrf_patterns:
        if pattern not in response.text:
            vulnerabilities.append(f"[VULNERABILITY] Possible CSRF vulnerability in {url}")
    return vulnerabilities

def check_insecure_headers(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for insecure HTTP headers on {url}", 'yellow')
    
    insecure_headers = [
        "X-Frame-Options", "Strict-Transport-Security", "X-Content-Type-Options", "X-XSS-Protection"
    ]
    
    for header in insecure_headers:
        if header not in response.headers:
            vulnerabilities.append(f"[VULNERABILITY] Missing security header: {header}")
    
    return vulnerabilities

def check_directory_traversal(url, response):
    vulnerabilities = []
    print_colored(f"[INFO] Checking for Directory Traversal vulnerability on {url}", 'yellow')
    traversal_patterns = ["../", "..\\", "/etc/passwd", "/proc/self/environ", "/var/log/"]

    for pattern in traversal_patterns:
        test_url = f"{url}/{pattern}"
        try:
            test_response = requests.get(test_url)
            if "error" not in test_response.text and "Not Found" not in test_response.text:
                vulnerabilities.append(f"[VULNERABILITY] Possible Directory Traversal vulnerability in {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def scan_for_login_panels(base_url):
    vulnerabilities = []
    login_patterns = ["/login", "/admin", "/user", "/admin.php", "/wp-login.php", "/signin"]
    print_colored(f"[INFO] Checking for login panels or data collectors on {base_url}", 'yellow')
    
    for pattern in login_patterns:
        test_url = f"{base_url}{pattern}"
        try:
            test_response = requests.get(test_url)
            if test_response.status_code == 200:
                vulnerabilities.append(f"[VULNERABILITY] Login panel found: {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def scan_for_data_collectors(base_url):
    vulnerabilities = []
    data_collector_patterns = ["/register", "/signup", "/subscribe", "/contact"]
    print_colored(f"[INFO] Checking for potential data collectors on {base_url}", 'yellow')
    
    for pattern in data_collector_patterns:
        test_url = f"{base_url}{pattern}"
        try:
            test_response = requests.get(test_url)
            if test_response.status_code == 200:
                vulnerabilities.append(f"[VULNERABILITY] Data collector found: {test_url}")
        except requests.exceptions.RequestException:
            pass
    return vulnerabilities

def scan_ports(domain):
    vulnerabilities = []
    print_colored(f"[INFO] Scanning open ports for {domain}...", 'magenta')
    open_ports = []
    common_ports = [80, 443, 21, 22, 25, 110, 3306, 5432, 8080, 8443]
    
    for port in common_ports:
        try:
            sock = socket.create_connection((domain, port), timeout=1)
            open_ports.append(port)
            sock.close()
        except (socket.timeout, socket.error):
            pass
    
    if open_ports:
        vulnerabilities.append(f"[INFO] Open ports found: {', '.join(map(str, open_ports))}")
    else:
        vulnerabilities.append("[INFO] No open ports found.")
    
    return vulnerabilities

def print_summary(vulnerabilities):
    print_colored("\n[INFO] Vulnerability Scan Summary:", 'cyan')
    if vulnerabilities:
        for vuln in vulnerabilities:
            print_colored(vuln, 'red')
    else:
        print_colored("[INFO] No vulnerabilities found!", 'green')

def main():
    while True:
        domain = input("Enter the domain to scan (e.g. yoursite.com): ").strip()

        if not domain:
            print_colored("[ERROR] Domain cannot be empty.", 'red')
            continue
        
        scan_website(domain)

        again = input("\nDo you want to scan another website? (y/n): ").strip().lower()
        if again != 'y':
            print_colored("[INFO] Exiting the program. Goodbye!", 'cyan')
            break

if __name__ == "__main__":
    main()
