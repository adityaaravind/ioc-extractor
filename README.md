
# 🛡️ IOC Extractor & Community Analyzer

A web-based cybersecurity tool to extract Indicators of Compromise (IOCs) from logs or emails, analyze them with VirusTotal, and share them with a collaborative community. Built with ❤️ using [Streamlit](https://streamlit.io).

---

## 🚀 Features

- 🔍 **Extract IOCs**: IPv4 addresses, URLs, file hashes (MD5/SHA)
- 🧠 **Classify Automatically**: Tags like `malware`, `credentials`, `internal`
- 🧪 **Check Threats**: Lookup each IOC with VirusTotal (3 free lookups included)
- 🌍 **Community Sharing**: Post your findings to a searchable public forum
- 💬 **Add Comments**: Discuss or annotate findings with context
- 📊 **Dashboard View**: Charts showing top IOCs, tags, and contributors

---

## 📦 How to Run Locally

1. **Install Python** (if not already):  
   https://www.python.org/downloads/

2. **Install with pipx** (recommended on Ubuntu):

```bash
pipx ensurepath
pipx install streamlit
```

3. **Clone the repo:**

```bash
git clone https://github.com/adityaaravind/ioc-extractor.git
cd ioc-extractor
```

4. **Install dependencies:**

```bash
pip install -r requirements.txt
```

5. **Run the app:**

```bash
streamlit run app.py
```

---

## ☁️ Streamlit Cloud Deployment

You can also deploy this app for free at:  
➡️ [https://streamlit.io/cloud](https://streamlit.io/cloud)

1. Upload your repo to GitHub
2. Go to Streamlit Cloud and click **New app**
3. Select your repo and choose `app.py` as the entry point
4. Done! 🎉

---

## 🧪 Sample Test Input

Paste this in the text box for demo:

```
Suspicious login from http://phishing-login.biz
Internal IP 192.168.100.24 accessed https://malicious-app.xyz/update.php
SHA256: d41d8cd98f00b204e9800998ecf8427e
```

---

## 🛂 VirusTotal API Key (optional)

- You get **3 free lookups** per session with our default key.
- To unlock unlimited checks:
  - Get your own free key 👉 [https://docs.virustotal.com/docs/please-give-me-an-api-key](https://docs.virustotal.com/docs/please-give-me-an-api-key)
  - Paste it in the app under the 🔑 section

---

## 👤 Author

Made with 💡 and 💻 by:

**Aditya Aravind Medepalli**  
🔗 [LinkedIn](https://www.linkedin.com/in/aditya-aravind-medepalli/)

---

## 📃 License

MIT License – use freely, improve openly, credit kindly.
