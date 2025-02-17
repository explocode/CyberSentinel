# CyberSentinel

CyberSentinel is a comprehensive web security scanner designed to identify potential vulnerabilities in websites. It performs an in-depth analysis of your website, detecting common security flaws such as SQL injection, XSS, CSRF, file inclusion vulnerabilities, insecure HTTP headers, and more. CyberSentinel also scans for login panels, data collectors, and open ports to ensure your web application is secure.

## Features

- **Website Crawling**: Automatically crawl and discover all accessible pages on the website.
- **Vulnerability Detection**: Identify common vulnerabilities including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Cross-Site Request Forgery (CSRF)
  - File Inclusion
  - Insecure HTTP Headers
  - Directory Traversal
- **Login Panel Detection**: Find login pages and admin panels on the website.
- **Data Collector Scanning**: Detect potential data collection forms (e.g., registration, contact forms).
- **Port Scanning**: Scan for open ports on the domain to check for unnecessary exposed services.
- **Detailed Reporting**: Provides a summary of found vulnerabilities with recommendations.

## Installation

To use CyberSentinel, ensure that you have Python 3.6+ installed on your system. You can install the required dependencies using `pip`:

```bash
git clone https://github.com/explocode/CyberSentinel.git
cd CyberSentinel
pip install -r requirements.txt
