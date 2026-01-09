# OSINT Phone Number Scanner (Clean Version)
# -----------------------------------------------------------
# This is a fully cleaned, structured, and error-free version
# of your OSINT phone scanning tool.

import json
import csv
import requests
import phonenumbers
from phonenumbers import carrier, timezone, geocoder
import hashlib
import time
from datetime import datetime
import os
import time
import sys

GREEN = "\033[92m"
RESET = "\033[0m"

os.system("cls" if os.name == "nt" else "clear")

banner = r"""
   ____                 __     ___           ____     ___                    __  _             _  __           __          
  / __/__ ___ _________/ /    / _/__  ____  /  _/__  / _/__  ______ _  ___ _/ /_(_)__  ___    / |/ /_ ____ _  / /  ___ ____
 _\ \/ -_) _ `/ __/ __/ _ \  / _/ _ \/ __/ _/ // _ \/ _/ _ \/ __/  ' \/ _ `/ __/ / _ \/ _ \  /    / // /  ' \/ _ \/ -_) __/
/___/\__/\_,_/_/  \__/_//_/ /_/ \___/_/   /___/_//_/_/ \___/_/ /_/_/_/\_,_/\__/_/\___/_//_/ /_/|_/\_,_/_/_/_/_.__/\__/_/   
                                                                                                                           
"""

def animated_print(text, delay=0.0005):
    for char in text:
        sys.stdout.write(GREEN + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)

animated_print(banner)
animated_print("\nDeveloped by Mr.Ghost\n\n")
# -----------------------------------------------------------
# Load Configuration
# -----------------------------------------------------------
def load_config(path="config.json"):
    """Load API keys and service options."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        template = {
            "hibp_api_key": "",
            "dehashed_api_key": "",
            "snusbase_api_key": "",
            "leakcheck_api_key": "",
            "use_services": ["hibp", "dehashed", "snusbase", "leakcheck"]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=2)
        print("⚠️ Created config.json template. Add API keys if needed.")
        return template

# -----------------------------------------------------------
# Phone Validation & Formatting
# -----------------------------------------------------------
def validate_phone_number(phone_number):
    """Validate phone number format and extract metadata."""
    try:
        # تحديد المنطقة إذا الرقم مغربي
        if phone_number.startswith("+212"):
            region = "MA"
        else:
            region = None

        # استخدم phone_number وليس phone
        parsed = phonenumbers.parse(phone_number, region)

        if phonenumbers.is_valid_number(parsed):
            formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            carrier_name = carrier.name_for_number(parsed, "en")
            time_zone = timezone.time_zones_for_number(parsed)
            region_name = geocoder.description_for_number(parsed, "en")

            print(f"✓ Valid Phone Number: {formatted}")
            print(f"  Carrier: {carrier_name}")
            print(f"  Region: {region_name}")
            print(f"  Timezone: {time_zone}")

            return formatted
        else:
            print("✗ Invalid Phone Number")
            return None

    except Exception as e:
        print(f"✗ Parsing Error: {e}")
        return None



def format_phone_for_sites(phone_number):
    """Prepare phone number formats for different OSINT websites."""
    clean = "".join(filter(str.isdigit, phone_number))

    if phone_number.startswith('+'):
        clean_with_plus = phone_number
    elif phone_number.startswith('00'):
        clean_with_plus = '+' + phone_number[2:]
    else:
        clean_with_plus = '+966' + clean if clean.startswith('5') else '+' + clean

    return {
        'raw': clean,
        'with_plus': clean_with_plus,
        'without_plus': clean_with_plus.replace('+', ''),
        'with_dashes': f"{clean[:3]}-{clean[3:6]}-{clean[6:]}",
        'with_spaces': f"{clean[:3]} {clean[3:6]} {clean[6:]}"
    }

# -----------------------------------------------------------
# Breached Databases Checks
# -----------------------------------------------------------
def check_hibp(account, api_key, save_writer=None):
    base = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
    headers = {
        "User-Agent": "OSINT-Phone-Scanner",
        "Accept": "application/json"
    }
    if api_key:
        headers["hibp-api-key"] = api_key

    url = base.format(requests.utils.requote_uri(account))
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            breaches = resp.json()
            print(f"🔥 HIBP: Found {len(breaches)} breaches")
            if save_writer:
                save_writer.writerow(["Breached DB", "HIBP", url, "FOUND", 200, f"{len(breaches)} breaches"])
            return {"service": "hibp", "status": "FOUND", "data": breaches}

        elif resp.status_code == 404:
            print("✓ HIBP: No breaches found")
            if save_writer:
                save_writer.writerow(["Breached DB", "HIBP", url, "NOT FOUND", 404, "No breaches"])
            return {"service": "hibp", "status": "NOT FOUND"}

        else:
            print(f"❗ HIBP HTTP {resp.status_code}")
            if save_writer:
                save_writer.writerow(["Breached DB", "HIBP", url, f"HTTP {resp.status_code}", resp.status_code, ""])
            return {"service": "hibp", "status": f"HTTP {resp.status_code}"}

    except Exception as e:
        print(f"❌ HIBP Error: {e}")
        return {"service": "hibp", "status": "ERROR", "data": str(e)}


def check_dehashed(query, api_key, save_writer=None):
    if not api_key:
        print("⚠️ DeHashed API key missing — skipping.")
        return {"service": "dehashed", "status": "SKIP"}

    url = f"https://api.dehashed.com/search?query={requests.utils.requote_uri(query)}"

    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, auth=(api_key, ""), timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            entries = len(data.get("entries", [])) if isinstance(data, dict) else 0
            print(f"🔍 DeHashed: {entries} entries found")
            if save_writer:
                save_writer.writerow(["Breached DB", "DeHashed", url, "FOUND", 200, entries])
            return {"service": "dehashed", "status": "OK", "data": data}

        else:
            print(f"❗ DeHashed HTTP {resp.status_code}")
            return {"service": "dehashed", "status": f"HTTP {resp.status_code}"}

    except Exception as e:
        print(f"❌ DeHashed Error: {e}")
        return {"service": "dehashed", "status": "ERROR", "data": str(e)}


def check_snusbase(query, api_key, save_writer=None):
    if not api_key:
        print("⚠️ Snusbase API key missing — skipping.")
        return {"service": "snusbase", "status": "SKIP"}

    url = "https://api.snusbase.com/v3/search"
    headers = {"Auth": api_key, "Content-Type": "application/json"}
    payload = {"query": query}

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            results = len(data.get("results", []))
            print(f"🔍 Snusbase: {results} results")
            if save_writer:
                save_writer.writerow(["Breached DB", "Snusbase", url, "FOUND", 200, results])
            return {"service": "snusbase", "status": "OK", "data": data}

        else:
            print(f"❗ Snusbase HTTP {resp.status_code}")
            return {"service": "snusbase", "status": f"HTTP {resp.status_code}"}

    except Exception as e:
        print(f"❌ Snusbase Error: {e}")
        return {"service": "snusbase", "status": "ERROR", "data": str(e)}


def check_leakcheck(query, api_key, save_writer=None):
    url = "https://leakcheck.io/api"
    headers = {"Accept": "application/json"}
    params = {"q": query}

    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            results = len(data.get("result", [])) if isinstance(data, dict) else 0
            print(f"🔍 LeakCheck: {results} results")
            if save_writer:
                save_writer.writerow(["Breached DB", "LeakCheck", url, "FOUND", 200, results])
            return {"service": "leakcheck", "status": "OK", "data": data}

        else:
            print(f"❗ LeakCheck HTTP {resp.status_code}")
            return {"service": "leakcheck", "status": f"HTTP {resp.status_code}"}

    except Exception as e:
        print(f"❌ LeakCheck Error: {e}")
        return {"service": "leakcheck", "status": "ERROR", "data": str(e)}


# -----------------------------------------------------------
# Aggregate all breached DB checks
# -----------------------------------------------------------
def check_breached_dbs(phone_formats, config, csv_writer=None):
    print("\n🔓 Checking Breached Databases...")
    print("=" * 60)

    account = phone_formats.get("with_plus")
    services = config.get("use_services", [])
    results = []

    if "hibp" in services:
        results.append(check_hibp(account, config.get("hibp_api_key"), csv_writer))
        time.sleep(1.6)

    if "dehashed" in services:
        results.append(check_dehashed(account, config.get("dehashed_api_key"), csv_writer))
        time.sleep(1.0)

    if "snusbase" in services:
        results.append(check_snusbase(account, config.get("snusbase_api_key"), csv_writer))
        time.sleep(1.0)

    if "leakcheck" in services:
        results.append(check_leakcheck(account, config.get("leakcheck_api_key"), csv_writer))
        time.sleep(1.0)

    return results


# -----------------------------------------------------------
# Website OSINT Checking
# -----------------------------------------------------------
def check_phone_sites(phone_number):
    with open("phone_sites.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    phone_formats = format_phone_for_sites(phone_number)
    print(f"\n📞 Searching using: {phone_formats['with_plus']}")

    results = []
    csv_filename = f"phone_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    with open(csv_filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Category", "Site Name", "URL", "Status", "HTTP Code", "Notes"])

        for category, sites in data["phone_number_osint_sites"].items():
            print("\n" + "=" * 60)
            print(f"🔍 CATEGORY: {category.upper()}")
            print("=" * 60)

            for site_name, url_pattern in sites.items():
                try:
                    if any(k in site_name.lower() for k in ["truecaller", "sync"]):
                        phone_to_use = phone_formats['without_plus']
                    elif any(k in site_name.lower() for k in ["whatsapp", "telegram"]):
                        phone_to_use = phone_formats['with_plus']
                    else:
                        phone_to_use = phone_formats['with_plus']

                    url = url_pattern.format(phone_to_use)

                    headers = {
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': '*/*',
                    }

                    response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
                    content = response.text.lower() if response.status_code == 200 else ""

                    if response.status_code == 200:
                        indicators = ['profile', 'account', 'user', 'member', 'exists', 'found']
                        matches = [i for i in indicators if i in content[:5000]]
                        if matches:
                            status = "LIKELY FOUND"
                            notes = f"Indicators: {', '.join(matches)}"
                        else:
                            status = "NOT FOUND"
                            notes = "Page OK but no indicators"

                    elif response.status_code == 404:
                        status = "NOT FOUND"
                        notes = "404 Not Found"

                    elif response.status_code == 403:
                        status = "ACCESS DENIED"
                        notes = "403 Forbidden"

                    else:
                        status = f"HTTP {response.status_code}"
                        notes = "Unknown"

                    print(f"  {'✓' if 'FOUND' in status else '✗'} {site_name}: {status}")

                    writer.writerow([category, site_name, url, status, response.status_code, notes])
                    results.append([category, site_name, url, status])

                except requests.Timeout:
                    print(f"⏰ TIMEOUT: {site_name}")
                    writer.writerow([category, site_name, url_pattern, "TIMEOUT", "N/A", "Timeout"])

                except Exception as e:
                    print(f"❗ ERROR {site_name}: {e}")
                    writer.writerow([category, site_name, url_pattern, "ERROR", "N/A", str(e)])

        config = load_config()
        breached_results = check_breached_dbs(phone_formats, config, writer)
        for r in breached_results:
            results.append(["Breached DB", r.get("service", "unknown"), "-", r.get("status", "unknown")])

    print(f"\n💾 Results saved in: {csv_filename}")
    return results


# -----------------------------------------------------------
# Final Report
# -----------------------------------------------------------
def generate_report(results):
    print("\n" + "=" * 60)
    print("📊 FINAL REPORT")
    print("=" * 60)

    found = [r for r in results if "FOUND" in r[3]]
    possible = [r for r in results if "POSSIBLE" in r[3]]

    print(f"\n✅ Total FOUND: {len(found)}")
    for r in found:
        print(f" - {r[1]} ({r[0]})")

    print(f"\n⚠️ POSSIBLE matches: {len(possible)}")
    for r in possible:
        print(f" - {r[1]} ({r[0]})")

    print(f"\n📄 Full details in the CSV file.")


# -----------------------------------------------------------
# MAIN EXECUTION
# -----------------------------------------------------------
if __name__ == "__main__":
    print("🔍 OSINT Phone Number Scanner")
    print("=" * 40)

    phone_input = input("Enter phone number (ex: +966501234567): ").strip()
    validated = validate_phone_number(phone_input)

    if validated:
        results = check_phone_sites(phone_input)
        generate_report(results)
    else:
        print("❌ Invalid number. Try again.")
