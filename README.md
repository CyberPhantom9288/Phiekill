# 🛡️ Phiekill — Advanced Phishing URL Threat Detection System

Phiekill is a **rule-based phishing URL detection tool** designed to identify suspicious and potentially malicious links.
It analyzes URLs based on multiple heuristic features such as domain structure, suspicious TLDs, phishing-related keywords, URL shorteners, and more, to calculate a **risk score (0–100)** and classify links as:

* ✅ **Likely Legit**
* ⚠️ **Suspicious**
* 🚨 **Likely Phishing**

---

## ✨ Features

* Detects **phishing-prone TLDs** (e.g., `.tk`, `.ml`, `.xyz`, `.cf`, `.gq`, etc.)
* Flags **common phishing keywords** (e.g., `login`, `verify`, `paypal`, `banking`, etc.)
* Identifies **known URL shorteners** (`bit.ly`, `tinyurl.com`, etc.)
* Analyzes **suspicious patterns** (`@`, `//`, `--`, `__`, etc.)
* Extracts and evaluates:

  * ✅ HTTPS usage
  * 🌐 Domain & subdomain depth
  * 🔢 Digit ratio in domains
  * 🧾 Path & query string length
  * 🔍 Special character count
* Generates a **risk score & classification**
* Supports **single URL** or **batch analysis via file input**
* Provides **detailed verbose reports** and summary stats

---

## 🚀 Installation

Clone the repository and install required dependencies:

```bash
git clone https://github.com/CyberPhantom9288/Phiekill.git
cd Phiekill
pip install tldextract
python3 Phiekill.py
```


---

## 📖 Usage

### Analyze a single URL

```bash
python3 Phiekill.py https://example.com
```

### Analyze multiple URLs from a file

```bash
python3 Phiekill.py -f urls.txt
```

### Verbose mode (detailed feature analysis)

```bash
python3 Phiekill.py -f urls.txt -v
```

### Quiet mode (suppress banner/header)

```bash
python3 Phiekill.py https://phishingsite.com -q
```

---


## ⚠️ Disclaimer

This tool is for **educational and research purposes only**.
The author does not condone malicious use, and misuse may violate laws.
The creator is **not responsible** for any damages or consequences.
Use responsibly, ethically, and within the law.
