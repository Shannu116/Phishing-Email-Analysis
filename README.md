# Phishing-Email-Analysis
This project involves the analysis of a suspicious email to identify phishing indicators through its header and content characteristics.

## 🔍 Summary

A detailed inspection of the email header and body reveals multiple traits commonly associated with phishing attacks. These include the absence of standard authentication mechanisms, blacklisted domains, suspicious links, and psychological manipulation through deceptive content.

---

## 🧠 Key Findings

### ✅ Technical Indicators:
- ❌ **Missing SPF, DKIM, and DMARC** authentication headers.
- ⚠️ **Suspicious Message-ID**: Possibly spoofed or malformed.
- ⛔ **Blacklisted Domain**: Sender's domain found on multiple threat databases.
- 🔗 **Phishing URLs** detected using [VirusTotal](https://www.virustotal.com).

### 🎯 Social Engineering Clues:
- 📩 Email content claims an **"unknown login from a foreign country"** to create urgency and fear.
---

## 📂 Files
- `sample-1039.eml`: Raw email header used for the investigation.
- `Task-2-report.pdf`: Detailed write-up of phishing traits and recommendations.
- `README.md`: This file.

---

## 🛡️ Conclusion

This email is highly suspicious and exhibits classic signs of a **phishing attack**. The combination of missing authentication, malicious links, and manipulative content suggests it should be flagged, reported, and blocked within the mail system.

---

## 🚨 Disclaimer

This analysis is for educational and security awareness purposes only. Do not interact with or open any of the links or attachments found in phishing emails.

