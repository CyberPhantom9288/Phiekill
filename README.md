# 🛡️ Phiekill — Advanced URL Threat Detection System

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
pip install -r requirements.txt
```

### Requirements

* Python 3.7+
* Dependencies:

  * `tldextract`

You can install manually with:

```bash
pip install tldextract
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

## 📝 Example Output

```
============================================================
URL ANALYSIS REPORT
============================================================
URL: http://paypal.verify-login.secure-update.tk
Risk Score: 85/100
Classification: Likely Phishing

Feature Analysis:
  - HTTPS: No
  - Domain: secure-update.tk
  - Subdomains: paypal.verify-login
  - Subdomain depth: 2
  - Contains IP: No
  - TLD: tk
  - Suspicious TLD: Yes
  - Special chars: 6
  - Digit ratio: 0.000
  - Contains bait: Yes
  - URL shortener: No

Risk Factors:
  - Uses HTTP instead of HTTPS
  - Suspicious TLD: tk
  - High number of special characters (6)
  - Contains known phishing bait keywords
============================================================
```

---

## 📊 Classification Thresholds

* **0–29** → ✅ Likely Legit
* **30–69** → ⚠️ Suspicious
* **70–100** → 🚨 Likely Phishing

---

## 🛠️ Roadmap / Possible Improvements

* [ ] Export results to **JSON/CSV**
* [ ] Add **machine learning classifier** for higher accuracy
* [ ] Integrate with **threat intelligence feeds**
* [ ] Build a **web-based UI**

---

## 👤 Author

Created by **CyberPhantom9288**
