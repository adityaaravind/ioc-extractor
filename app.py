
import streamlit as st
import re
import json
import os
import pandas as pd
import requests
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt
import base64

# Constants
USER_FILE = "users.json"
COMMUNITY_FILE = "community_iocs.json"
COMMENTS_FILE = "ioc_comments.json"
VT_KEY_HASHED = "ODdmMGRkNTBlOTZhOTA1MjEzMmRmM2VmOGI4OWU1MjU4Yzk3MGI2NzI0MDk2Yjc5MDU2ZjNhMmViOGY4ZDBlZQ=="

def get_default_vt_key():
    return base64.b64decode(VT_KEY_HASHED).decode()

for file, default in [(USER_FILE, {}), (COMMUNITY_FILE, []), (COMMENTS_FILE, [])]:
    if not os.path.exists(file):
        with open(file, "w") as f:
            json.dump(default, f)

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

st.set_page_config("IOC Extractor & Analyzer", layout="wide")
st.title("🛡️ IOC Extractor & Community Forum")
st.markdown("Extract IOCs from logs, check them, and collaborate.")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.current_user = ""
    st.session_state.search_count = 0
    st.session_state.vt_api_key = ""

users = load_json(USER_FILE)
if not st.session_state.authenticated:
    st.subheader("🔐 Login / Register")
    uname = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    mode = st.radio("Action", ["Login", "Register"])
    if st.button("Submit"):
        if not uname or not pwd:
            st.error("Fill both fields.")
        elif mode == "Register":
            if uname in users:
                st.error("User exists.")
            else:
                users[uname] = pwd
                save_json(USER_FILE, users)
                st.success("Registered.")
        elif mode == "Login":
            if users.get(uname) == pwd:
                st.session_state.authenticated = True
                st.session_state.current_user = uname
                st.success(f"Welcome {uname}")
            else:
                st.error("Invalid.")
    st.stop()

# VT Key
st.markdown("### 🔑 VirusTotal API Key")
key_input = st.text_input("Optional custom VT API key", type="password")
if key_input:
    st.session_state.vt_api_key = key_input
    st.success("Saved custom VT key.")

st.markdown("### 📥 Input Logs or Emails")
text_file = st.file_uploader("Upload .txt/.log/.eml", type=["txt", "log", "eml"])
text_content = text_file.read().decode("utf-8") if text_file else ""
manual_input = st.text_area("Paste log content", height=200)
full_text = f"{text_content}\n{manual_input}"

ioc_patterns = {
    "IPv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "URL": r"https?://[\w./\-]+",
    "Hash": r"\b[a-fA-F0-9]{32,64}\b"
}

def extract_iocs(text):
    out = []
    for typ, pat in ioc_patterns.items():
        found = re.findall(pat, text)
        out.extend([(f, typ) for f in set(found)])
    return out

def run_vt(ioc):
    api_key = st.session_state.vt_api_key or get_default_vt_key()
    try:
        res = requests.get(f"https://www.virustotal.com/api/v3/search?query={ioc}",
                           headers={"x-apikey": api_key})
        if res.status_code == 200 and res.json().get("data"):
            return "🔴 Malicious"
        return "🟢 Clean"
    except:
        return "⚠️ Error"

def auto_tag(ioc, typ):
    tags = [typ.lower()]
    if "login" in ioc: tags.append("credentials")
    if "virus" in ioc or "mal" in ioc: tags.append("malware")
    if typ == "IPv4" and ioc.startswith("192."): tags.append("internal")
    return tags

results = []
if st.button("🚀 Extract IOCs"):
    iocs = extract_iocs(full_text)
    if not iocs:
        st.info("No IOCs found.")
    for ioc, typ in iocs:
        with st.expander(ioc):
            tags = auto_tag(ioc, typ)
            st.write(f"Type: {typ}")
            vt_res = st.empty()
            if st.button(f"Check {ioc}"):
                if st.session_state.search_count < 3 or st.session_state.vt_api_key:
                    vt = run_vt(ioc)
                    st.session_state.search_count += 1
                else:
                    vt = "Limit reached. Enter API key."
                vt_res.write(vt)
            results.append({
                "IOC": ioc,
                "Type": typ,
                "Tags": tags,
                "User": st.session_state.current_user,
                "Time": datetime.utcnow().isoformat()
            })

if results and st.button("🌍 Share to Forum"):
    all_data = load_json(COMMUNITY_FILE)
    all_data.extend(results)
    save_json(COMMUNITY_FILE, all_data)
    st.success("Shared to community.")

st.markdown("### 📊 Dashboard")
community = load_json(COMMUNITY_FILE)
if community:
    df = pd.DataFrame(community)
    col1, col2, col3 = st.columns(3)
    with col1:
        st.write("Top IOCs")
        st.dataframe(df["IOC"].value_counts().head(5))
    with col2:
        st.write("Top Tags")
        tags = sum(df["Tags"].tolist(), [])
        tag_df = pd.DataFrame(Counter(tags).items(), columns=["Tag", "Count"]).sort_values("Count", ascending=False)
        st.dataframe(tag_df.head(5))
    with col3:
        st.write("Top Users")
        st.dataframe(df["User"].value_counts().head(5))
    fig, ax = plt.subplots()
    ax.pie(tag_df["Count"], labels=tag_df["Tag"], autopct="%1.1f%%")
    st.pyplot(fig)

st.markdown("### 🔎 Search Community")
search = st.text_input("Search IOC / tag / user")
filt = [r for r in community if search.lower() in r["IOC"].lower() or
        search.lower() in " ".join(r["Tags"]).lower() or
        search.lower() in r["User"].lower()] if search else community

for entry in filt:
    st.markdown(f"`{entry['IOC']}` ({entry['Type']}) | Tags: {', '.join(entry['Tags'])} | by {entry['User']} at {entry['Time'][:19]}")
with st.sidebar:
    st.markdown("**👤 Creator:**")
    st.markdown(
        "[Aditya Aravind Medepalli](https://www.linkedin.com/in/aditya-aravind-medepalli/)",
        unsafe_allow_html=True
    )
