# app.py
import streamlit as st
import socket
import ssl
import requests
from urllib.parse import urlparse, urljoin
import datetime
import whois
import re
from bs4 import BeautifulSoup
import tldextract

# -------------------------
# Utility functions
# -------------------------
def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return True, cert.get('notAfter', 'Unknown')
    except Exception as e:
        return False, str(e)

def check_domain_age(domain):
    try:
        info = whois.whois(domain)
        if info.creation_date:
            creation = info.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_days = (datetime.datetime.now() - creation).days
            return age_days
        return None
    except Exception:
        return None

def suspicious_keywords(url):
    keywords = ["login", "update", "verify", "secure", "banking", "paypal", "signin", "account", "confirm"]
    found = [k for k in keywords if k in url.lower()]
    return found

def check_redirects(url):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True)
        if len(r.history) > 2:
            return True, len(r.history), r.status_code
        return False, len(r.history), r.status_code
    except Exception as e:
        return None, str(e), None

def extract_domain(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path
        ext = tldextract.extract(netloc)
        domain = ext.registered_domain or netloc
        return domain.lower()
    except Exception:
        return url.lower()

def looks_like_ip(host):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

def is_punycode(s):
    return "xn--" in s.lower()

# -------------------------
# Email header analysis
# -------------------------
def analyze_email_headers(header_text):
    findings = []

    # Received fields (too many hops = suspicious)
    hops = header_text.lower().count("received:")
    if hops > 6:
        findings.append(f"⚠️ Too many 'Received' hops ({hops})")

    # SPF / DKIM checks (text-based indicators)
    if "spf=fail" in header_text.lower():
        findings.append("❌ SPF check failed")
    if "dkim=fail" in header_text.lower():
        findings.append("❌ DKIM check failed")

    # From / Reply-To mismatch
    from_match = re.search(r"^From:\s*(.*)$", header_text, re.IGNORECASE | re.MULTILINE)
    reply_match = re.search(r"^Reply-To:\s*(.*)$", header_text, re.IGNORECASE | re.MULTILINE)
    if from_match and reply_match:
        if from_match.group(1).strip() != reply_match.group(1).strip():
            findings.append("⚠️ From and Reply-To mismatch")

    # Suspicious subject keywords
    subject_match = re.search(r"^Subject:\s*(.*)$", header_text, re.IGNORECASE | re.MULTILINE)
    if subject_match:
        subj = subject_match.group(1).lower()
        for word in ["urgent", "verify", "lottery", "password", "bank", "account", "click", "suspend"]:
            if word in subj:
                findings.append(f"❌ Suspicious subject keyword: '{word}'")

    if not findings:
        findings.append("✅ No obvious phishing patterns detected in headers")

    return findings

# -------------------------
# Browser Extension Simulator - HTML analysis rules
# -------------------------
def analyze_page_html(base_url, html):
    findings = []
    safe = True
    parsed = urlparse(base_url)
    page_domain = extract_domain(base_url)
    page_host = parsed.hostname or ""

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        return [f"❌ Unable to parse HTML: {e}"], False

    # 1) Password fields / login forms
    password_inputs = soup.find_all("input", {"type": "password"})
    if password_inputs:
        findings.append(f"⚠️ Page contains {len(password_inputs)} password field(s) — potential login form.")
        safe = False

    # 2) Form action domain mismatch
    forms = soup.find_all("form")
    for idx, f in enumerate(forms, start=1):
        action = f.get("action") or ""
        if action.strip() == "" or action.strip().startswith("#"):
            findings.append(f"⚠️ Form #{idx} has empty or fragment action (possible JS submission).")
            safe = False
        else:
            action_url = urljoin(base_url, action)
            action_domain = extract_domain(action_url)
            if action_domain and action_domain != page_domain:
                findings.append(f"❌ Form #{idx} posts to external domain: {action_domain} (page domain: {page_domain})")
                safe = False

    # 3) External favicon
    favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    if favicon and favicon.get("href"):
        fav_url = urljoin(base_url, favicon.get("href"))
        fav_domain = extract_domain(fav_url)
        if fav_domain != page_domain:
            findings.append(f"⚠️ Favicon served from different domain: {fav_domain}")
            safe = False

    # 4) Links that use IP addresses or point to different registered domains
    links = soup.find_all("a", href=True)
    ip_links = 0
    external_links = 0
    for a in links:
        href = a.get("href")
        if href.startswith("mailto:") or href.startswith("tel:"):
            continue
        abs_href = urljoin(base_url, href)
        href_host = urlparse(abs_href).hostname or ""
        if looks_like_ip(href_host):
            ip_links += 1
        href_domain = extract_domain(abs_href)
        if href_domain and href_domain != page_domain:
            external_links += 1
    if ip_links:
        findings.append(f"⚠️ {ip_links} link(s) use raw IP addresses — suspicious.")
        safe = False
    if external_links > 10:
        findings.append(f"⚠️ Many links ({external_links}) point to external domains (could be phishing).")
        safe = False

    # 5) Suspicious JS patterns (eval, document.write, iframe injection)
    scripts = soup.find_all("script")
    suspicious_js = 0
    for s in scripts:
        txt = (s.string or "") + " " + (s.get("src") or "")
        if any(pattern in txt.lower() for pattern in ["eval(", "document.write(", "unescape(", "fromcharcode(", "window.location", "innerhtml", "setinterval(", "atob(", "btoa("]):
            suspicious_js += 1
    if suspicious_js:
        findings.append(f"⚠️ {suspicious_js} script(s) contain obfuscation-like or dangerous JS patterns.")
        safe = False

    # 6) Punycode in domain or links
    if is_punycode(page_host):
        findings.append("❌ Page uses punycode in hostname (IDN tricks) — suspicious.")
        safe = False
    for a in links[:200]:
        href = urljoin(base_url, a.get("href"))
        if is_punycode(urlparse(href).hostname or ""):
            findings.append("⚠️ Link uses punycode — potential homograph attack.")
            safe = False
            break

    # 7) Tiny/empty textual content (common in throwaway phishing pages)
    text_len = len(soup.get_text(strip=True) or "")
    if text_len < 50 and (password_inputs or forms):
        findings.append("⚠️ Very little visible text with login form — typical of phishing landing pages.")
        safe = False

    # 8) Check meta refresh redirect
    meta_refresh = soup.find("meta", attrs={"http-equiv": lambda x: x and x.lower() == "refresh"})
    if meta_refresh:
        findings.append("⚠️ Meta refresh tag detected — automatic redirect may be used to hide behavior.")
        safe = False

    if not findings:
        findings.append("✅ No obvious extension-level phishing indicators found (rule-based).")

    return findings, safe

# -------------------------
# Streamlit App
# -------------------------
st.set_page_config(page_title="Anti-Phishing Dashboard + Extension Simulator", page_icon="🛡️", layout="wide")
st.title("🛡️ Anti-Phishing Dashboard — URL, Email & Browser-Extension Simulator")
st.write("Rule-based, real-time checks only — no datasets or ML models. Use the tabs to test URLs, email headers, and simulate a browser extension detecting phishing pages.")

tabs = st.tabs(["🌐 URL Analyzer", "📧 Email Header Analyzer", "🧩 Browser Extension Simulator"])

# -------------------------
# URL Analyzer
# -------------------------
with tabs[0]:
    st.header("URL Analyzer")
    url_input = st.text_input("Enter URL (e.g., https://example.com):", key="url_input")
    if st.button("Analyze URL", key="analyze_url"):
        if url_input:
            parsed = urlparse(url_input)
            domain = parsed.netloc or parsed.path
            st.subheader("🔎 URL Analysis Results")

            # SSL Check
            ssl_status, ssl_info = check_ssl_certificate(domain)
            if ssl_status:
                st.success(f"✅ SSL Certificate Found, Valid Until: {ssl_info}")
            else:
                st.error(f"❌ SSL Certificate Issue: {ssl_info}")

            # Domain Age
            age = check_domain_age(domain)
            if age is not None:
                if age < 180:
                    st.warning(f"⚠️ Domain is very new ({age} days old) → Suspicious")
                else:
                    st.success(f"✅ Domain age: {age} days")
            else:
                st.info("ℹ️ Could not fetch domain age (whois may be rate-limited)")

            # Suspicious Keywords
            found = suspicious_keywords(url_input)
            if found:
                st.error(f"❌ Suspicious keywords found in URL: {', '.join(found)}")
            else:
                st.success("✅ No suspicious keywords in URL")

            # Redirects
            redirect_status, redirect_info, status_code = check_redirects(url_input)
            if redirect_status is True:
                st.warning(f"⚠️ Multiple redirects detected ({redirect_info} redirects). Final HTTP status: {status_code}")
            elif redirect_status is False:
                st.success(f"✅ No unusual redirects ({redirect_info} redirects). Final HTTP status: {status_code}")
            else:
                st.error(f"❌ Redirect check failed: {redirect_info}")

            st.info("📌 Note: This is a rule-based phishing analyzer. No datasets/models used.")

# -------------------------
# Email Header Analyzer
# -------------------------
with tabs[1]:
    st.header("Email Header Analyzer")
    header_input = st.text_area("Paste raw email headers here:", height=250, key="headers")
    if st.button("Analyze Email Headers", key="analyze_headers"):
        if header_input.strip():
            st.subheader("📊 Email Header Analysis Results")
            results = analyze_email_headers(header_input)
            for r in results:
                if r.startswith("✅"):
                    st.success(r)
                elif r.startswith("⚠️"):
                    st.warning(r)
                else:
                    st.error(r)

# -------------------------
# Browser Extension Simulator
# -------------------------
with tabs[2]:
    st.header("Browser Extension Simulator (Demo)")
    st.write("Enter a URL to fetch the page and simulate what a browser extension would flag. Or paste raw HTML if you prefer offline/demo content.")

    col1, col2 = st.columns([2,1])
    with col1:
        sim_url = st.text_input("URL to fetch (or leave blank if pasting HTML):", key="sim_url")
        html_input = st.text_area("Or paste raw HTML here (optional):", height=200, key="sim_html")
        depth_fetch = st.slider("Max bytes to fetch (for large pages)", 10000, 200000, 50000, step=10000)
    with col2:
        st.info("Simulator checks (examples):\n• Password fields & forms\n• Form action mismatches\n• External favicon\n• IP-based links\n• Suspicious JS patterns\n• Punycode / homograph indicators\n• Meta refresh redirects")

    if st.button("Run Extension Simulation", key="run_sim"):
        page_source = ""
        base = ""
        if html_input.strip():
            page_source = html_input
            base = sim_url or "http://example.local"
        elif sim_url.strip():
            base = sim_url
            try:
                resp = requests.get(sim_url, timeout=8, stream=True)
                # limit content size
                content = resp.raw.read(depth_fetch)
                page_source = content.decode(errors="replace")
            except Exception as e:
                st.error(f"❌ Failed to fetch URL: {e}")
                page_source = ""
        else:
            st.error("Please provide a URL or paste HTML to analyze.")
            page_source = ""

        if page_source:
            with st.spinner("Analyzing page..."):
                findings, safe = analyze_page_html(base, page_source)
            st.subheader("🔍 Extension Findings")
            for f in findings:
                if f.startswith("✅"):
                    st.success(f)
                elif f.startswith("⚠️"):
                    st.warning(f)
                else:
                    st.error(f)

            # Show a small rendered preview (beware of unsafe HTML)
            if st.checkbox("Show raw HTML preview (unsafe)", key="preview_html"):
                st.markdown("**Raw page preview (unsafe rendering):**")
                st.components.v1.html(page_source, height=400, scrolling=True)

            # Simulated extension popup overlay
            st.subheader("🔔 Simulated Extension Popup")
            if safe:
                st.success("Extension Popup: This page looks reasonably safe (rule-based).")
                st.write("Actions: [Allow]  [Inspect further]  [Report]")
            else:
                st.error("Extension Popup: ⚠️ Potential phishing indicators detected.")
                st.write("Actions: [Block navigation]  [Open detailed report]  [Report to admin]")
                if st.button("Open detailed report"):
                    st.info("Detailed report (simulated):")
                    st.write("- Source URL:", base)
                    st.write("- Timestamp:", datetime.datetime.now().isoformat())
                    st.write("- Issues found:")
                    for f in findings:
                        st.write("  -", f)

st.markdown("---")
st.caption("Built for FI1962 — Current Trends in Web Security. Rule-based heuristics only. No datasets / no pretrained models used.")
