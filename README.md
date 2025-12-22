# SHADOW ENUM

**cipher** is an asynchronous passive reconnaissance tool in Python for subdomain enumeration.  
It aggregates passive sources (crt.sh, CertSpotter, BufferOver, RapidDNS, Wayback, Google) and optionally uses API-backed sources (VirusTotal, SecurityTrails, Shodan, AlienVault OTX). The tool performs DNS validation, wildcard detection, candidate permutation, and optional HTTP probing (status + title).

<p align="center">
  <img src="https://github.com/fawadqureshi007/cipher/blob/main/cipher.png?raw=true" alt="cipher banner" width="600"/>
</p>

---

## ⚠️ Security Notice

This repository does **NOT** contain any hard-coded API keys.  
API keys are loaded via **environment variables** or a local **`.env` file**.

🚫 **Never commit your `.env` file** to GitHub.

---

## 🚀 Quick Setup & Usage

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/fawadqureshi007/cipher.git
cd cipher
````

---

### 2️⃣ Create & Activate Virtual Environment

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**

```powershell
python -m venv venv
venv\Scripts\activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install aiohttp aiodns python-dotenv rich
```

---

### 4️⃣ Download Subdomain Wordlist

```bash
wget -O subdomains-top1million-110000.txt \
https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt
```

Verify:

```bash
wc -l subdomains-top1million-110000.txt
```

---

### 5️⃣ (Optional) API Keys Setup

Create a `.env` file in the project root:

```env
ST_API=
SHODAN_API=
OTX_API=
VT_API=
CERTSPOTTER_API=
```

> `.env` is automatically loaded if `python-dotenv` is installed.

**OR export manually**

```bash
export VT_API="your_virustotal_key"
export SHODAN_API="your_shodan_key"
export OTX_API="your_otx_key"
export CERTSPOTTER_API="your_certspotter_key"
```

---

### 6️⃣ Run Cipher

**Basic**

```bash
python cipher.py example.com
```

**With HTTP Probing**

```bash
python cipher.py example.com --http
```

---

## 🛑 Disclaimer

For **educational and authorized security testing only**.
Do not use against systems without permission.

---

⭐ If you like this project, give it a star!

```
```

