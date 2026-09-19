#!/usr/bin/env python3
# TEAM AHZA CYBER SECURITY
# Defensive / authorized security toolkit.
# Standard-library only. No DDoS, credential attacks, exploits, malware, or destructive actions.

import argparse
import base64
import configparser
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import random
import re
import secrets
import shutil
import socket
import ssl
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

APP = "TEAM AHZA CYBER SECURITY"
VERSION = "3.0.0"
LOG_FILE = Path.home() / ".team_ahza_cyber.log"
RESULTS = []
HISTORY = []

# ---------- UI ----------
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

def c(text, color=RESET):
    if sys.stdout.isatty():
        return f"{color}{text}{RESET}"
    return str(text)

def clear():
    os.system("clear" if os.name != "nt" else "cls")

BANNER = r"""
████████╗███████╗ █████╗ ███╗   ███╗     █████╗ ██╗  ██╗███████╗ █████╗
╚══██╔══╝██╔════╝██╔══██╗████╗ ████║    ██╔══██╗██║  ██║╚══███╔╝██╔══██╗
   ██║   █████╗  ███████║██╔████╔██║    ███████║███████║  ███╔╝ ███████║
   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║    ██╔══██║██╔══██║ ███╔╝  ██╔══██║
   ██║   ███████╗██║  ██║██║ ╚═╝ ██║    ██║  ██║██║  ██║███████╗██║  ██║
   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                         TEAM AHZA CYBER SECURITY
"""

def banner():
    clear()
    print(c(BANNER, CYAN))
    print(c("Defensive security • authorized testing • local auditing", DIM))
    print(c(f"Version {VERSION} • 203 implemented commands", GREEN))
    print()

def log(msg):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{dt.datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    except Exception:
        pass

def record(name, value):
    item = {
        "time": dt.datetime.now().isoformat(timespec="seconds"),
        "feature": name,
        "result": value,
    }
    RESULTS.append(item)
    log(f"{name}: {str(value)[:1000]}")
    return value

def out(value):
    if isinstance(value, (dict, list, tuple)):
        print(json.dumps(value, indent=2, ensure_ascii=False, default=str))
    else:
        print(value)

def ask(prompt, default=None):
    s = input(c(prompt, YELLOW)).strip()
    if not s and default is not None:
        return default
    return s

def run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def command_exists(name):
    return shutil.which(name) is not None

def safe_path(prompt="Path: ", default="."):
    p = Path(ask(prompt, default)).expanduser()
    return p

def read_text(path, limit=2_000_000):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(limit)

def http_request(url, method="GET", timeout=10, headers=None):
    headers = headers or {"User-Agent": "TEAM-AHZA-CYBER-SECURITY/3.0"}
    req = urllib.request.Request(url, method=method, headers=headers)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2_000_000)
            elapsed = time.perf_counter() - start
            return {
                "ok": True, "status": r.status, "url": r.geturl(),
                "headers": dict(r.headers), "body": body,
                "elapsed_ms": round(elapsed * 1000, 2)
            }
    except urllib.error.HTTPError as e:
        elapsed = time.perf_counter() - start
        body = e.read(200_000) if hasattr(e, "read") else b""
        return {"ok": False, "status": e.code, "url": url,
                "headers": dict(e.headers), "body": body,
                "elapsed_ms": round(elapsed * 1000, 2), "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}

def normalize_url(url):
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        return "https://" + url
    return url

# ---------- 1-20 Network ----------
def f01(): 
    h=ask("Hostname/domain: "); r=socket.getaddrinfo(h,None); return record("01 DNS lookup", sorted({x[4][0] for x in r}))
def f02():
    ip=ask("IP/hostname: "); return record("02 Reverse DNS", socket.gethostbyaddr(ip))
def f03():
    v=ask("IPv4 address: "); return record("03 IPv4 validation", {"valid": bool(ipaddress.ip_address(v).version==4) if ipaddress.ip_address(v) else False})
def f04():
    v=ask("IPv6 address: "); return record("04 IPv6 validation", {"valid": ipaddress.ip_address(v).version==6})
def f05():
    h=ask("Hostname: "); return record("05 Resolve all", sorted({x[4][0] for x in socket.getaddrinfo(h,None)}))
def f06():
    h=ask("Host: "); p=int(ask("Port: ", "443")); s=socket.socket(); s.settimeout(3)
    try: ok=s.connect_ex((h,p))==0
    finally: s.close()
    return record("06 TCP connectivity", {"host":h,"port":p,"open":ok})
def f07():
    h=ask("Host: "); p=int(ask("Port: ","80")); s=socket.socket(); s.settimeout(3)
    try: ok=s.connect_ex((h,p))==0
    finally: s.close()
    return record("07 Single port check", ok)
def f08():
    h=ask("Authorized host/IP: "); a=int(ask("Start port: ","1")); b=int(ask("End port: ","1024"))
    a=max(1,a); b=min(65535,b)
    if b-a+1>4096: b=a+4095
    found=[]
    for p in range(a,b+1):
        s=socket.socket(); s.settimeout(.25)
        try:
            if s.connect_ex((h,p))==0: found.append(p)
        finally: s.close()
    return record("08 Bounded TCP port scan", {"host":h,"ports":found})
def f09(): return record("09 Local hostname", socket.gethostname())
def f10():
    names=socket.gethostbyname_ex(socket.gethostname()); return record("10 Local addresses", names)
def f11():
    data={}
    if command_exists("ip"):
        rc,o,e=run(["ip","-br","addr"]); data={"command":"ip -br addr","output":o or e}
    else: data={"hostname":socket.gethostname(),"addresses":sorted({x[4][0] for x in socket.getaddrinfo(socket.gethostname(),None)})}
    return record("11 Network interfaces",data)
def f12():
    if command_exists("ip"): return record("12 Routing table", run(["ip","route"])[1])
    return record("12 Routing table","ip command not installed")
def f13():
    p=Path("/proc/net/arp")
    return record("13 ARP table", p.read_text(errors="replace") if p.exists() else "Not available")
def f14():
    for p in ["/etc/resolv.conf"]:
        if Path(p).exists(): return record("14 DNS configuration", Path(p).read_text(errors="replace"))
    return record("14 DNS configuration","/etc/resolv.conf not found")
def f15(): return record("15 Ping availability", {"installed":command_exists("ping")})
def f16(): return record("16 Traceroute availability", {"traceroute":command_exists("traceroute"),"tracepath":command_exists("tracepath")})
def f17(): return record("17 Curl availability", {"installed":command_exists("curl"),"path":shutil.which("curl")})
def f18(): return record("18 OpenSSL availability", {"installed":command_exists("openssl"),"path":shutil.which("openssl")})
def f19():
    h=ask("Domain: "); ips=sorted({x[4][0] for x in socket.getaddrinfo(h,443)})
    return record("19 DNS addresses", {"host":h,"addresses":ips})
def f20():
    path=ask("Subdomain wordlist (max 100 lines): ")
    base=ask("Base domain: ")
    if not Path(path).is_file(): return record("20 Subdomain check","Wordlist not found")
    words=[x.strip() for x in read_text(path,10000).splitlines() if x.strip()][:100]
    found=[]
    for w in words:
        host=f"{w}.{base}".strip(".")
        try:
            socket.gethostbyname(host); found.append(host)
        except socket.gaierror: pass
    return record("20 Conservative subdomain check",found)

# ---------- 21-40 HTTP/TLS ----------
def f21():
    u=normalize_url(ask("URL: ")); r=http_request(u,"GET"); return record("21 HTTP status", {k:r.get(k) for k in ("ok","status","url","elapsed_ms","error")})
def f22():
    u=normalize_url(ask("URL: ")); r=http_request(u,"GET"); return record("22 HTTP headers",r.get("headers",{}))
def f23():
    u=normalize_url(ask("URL: ")); h=http_request(u).get("headers",{})
    keys=["Content-Security-Policy","Strict-Transport-Security","X-Content-Type-Options","X-Frame-Options","Referrer-Policy","Permissions-Policy"]
    return record("23 Security headers", {k:h.get(k) for k in keys})
def f24():
    u=normalize_url(ask("URL: ")); h=http_request(u).get("headers",{}); return record("24 Server header",h.get("Server"))
def f25():
    u=normalize_url(ask("URL: ")); r=http_request(u); return record("25 Redirect destination",r.get("url"))
def f26():
    u=normalize_url(ask("URL: ")); r=http_request(u); return record("26 HTTP response time",r.get("elapsed_ms"))
def f27():
    u=normalize_url(ask("URL: ")).rstrip("/")+"/robots.txt"; r=http_request(u); return record("27 robots.txt",{"status":r.get("status"),"body":r.get("body",b"").decode(errors="replace")[:10000]})
def f28():
    u=normalize_url(ask("URL: ")).rstrip("/")+"/sitemap.xml"; r=http_request(u); return record("28 sitemap.xml",{"status":r.get("status"),"body":r.get("body",b"").decode(errors="replace")[:10000]})
def f29():
    u=normalize_url(ask("URL: ")); p=urllib.parse.urlparse(u); return record("29 HTTPS check",{"scheme":p.scheme,"uses_https":p.scheme=="https"})
def f30():
    h=ask("TLS hostname: "); port=int(ask("Port: ","443"))
    ctx=ssl.create_default_context()
    with socket.create_connection((h,port),timeout=5) as raw:
        with ctx.wrap_socket(raw,server_hostname=h) as s:
            cert=s.getpeercert()
            return record("30 TLS certificate",{"version":s.version(),"cipher":s.cipher(),"subject":cert.get("subject"),"issuer":cert.get("issuer"),"notAfter":cert.get("notAfter")})
def f31():
    h=ask("TLS hostname: "); p=int(ask("Port: ","443")); 
    with socket.create_connection((h,p),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=h) as s: return record("31 TLS version",s.version())
def f32():
    h=ask("TLS hostname: "); p=int(ask("Port: ","443")); 
    with socket.create_connection((h,p),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=h) as s: return record("32 TLS cipher",s.cipher())
def f33():
    u=ask("URL: "); p=urllib.parse.urlparse(normalize_url(u)); return record("33 URL parse",dict(p._asdict()))
def f34(): return record("34 URL encode",urllib.parse.quote(ask("Text: "),safe=""))
def f35(): return record("35 URL decode",urllib.parse.unquote(ask("Encoded: ")))
def f36():
    u=normalize_url(ask("URL: ")); p=urllib.parse.urlparse(u); return record("36 Query parser",urllib.parse.parse_qs(p.query))
def f37():
    u=ask("URL: "); p=urllib.parse.urlparse(u); return record("37 Userinfo detector",{"has_userinfo":bool(p.username or p.password)})
def f38():
    u=normalize_url(ask("URL: ")); r=http_request(u,"HEAD"); return record("38 HTTP HEAD",{"status":r.get("status"),"headers":r.get("headers",{})})
def f39():
    u=normalize_url(ask("URL: ")); r=http_request(u,"OPTIONS"); return record("39 HTTP OPTIONS",{"status":r.get("status"),"allow":r.get("headers",{}).get("Allow")})
def f40():
    u=normalize_url(ask("URL: ")); h=http_request(u).get("headers",{}); 
    cookies=[v for k,v in h.items() if k.lower()=="set-cookie"]
    flags={"cookies":cookies,"secure":all("Secure" in x for x in cookies) if cookies else None,"httponly":all("HttpOnly" in x for x in cookies) if cookies else None}
    return record("40 Cookie flags",flags)

# ---------- 41-70 Files ----------
def hash_file(p, alg):
    h=hashlib.new(alg)
    with open(p,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()
def file_cmd(alg):
    p=safe_path()
    if not p.is_file(): return record(alg,p.as_posix()+" is not a file")
    return record(alg,hash_file(p,alg))
def f41(): return file_cmd("md5")
def f42(): return file_cmd("sha1")
def f43(): return file_cmd("sha224")
def f44(): return file_cmd("sha256")
def f45(): return file_cmd("sha384")
def f46(): return file_cmd("sha512")
def f47():
    p=safe_path(); return record("47 File size",p.stat().st_size if p.exists() else "not found")
def f48():
    p=safe_path(); 
    if command_exists("file"): return record("48 File type",run(["file","-b",str(p)])[1])
    return record("48 File type",p.suffix or "unknown")
def f49():
    p=safe_path(); 
    if not p.exists(): return record("49 Permissions","not found")
    s=p.stat(); return record("49 Permissions",oct(s.st_mode & 0o7777))
def f50():
    p=safe_path(); 
    if not p.exists(): return record("50 Owner","not found")
    try:
        import pwd, grp
        s=p.stat(); return record("50 Owner",{"uid":s.st_uid,"user":pwd.getpwuid(s.st_uid).pw_name,"gid":s.st_gid,"group":grp.getgrgid(s.st_gid).gr_name})
    except Exception as e: return record("50 Owner",str(e))
def f51():
    p=safe_path(); s=p.stat(); return record("51 Timestamps",{"modified":dt.datetime.fromtimestamp(s.st_mtime).isoformat(),"accessed":dt.datetime.fromtimestamp(s.st_atime).isoformat(),"changed":dt.datetime.fromtimestamp(s.st_ctime).isoformat()})
def f52():
    p=safe_path(); return record("52 Directory listing",sorted(x.name for x in p.iterdir()) if p.is_dir() else "not directory")
def f53():
    p=safe_path(); items=[]
    if p.is_dir():
        for x in p.rglob("*"):
            items.append(str(x))
            if len(items)>=5000: break
    return record("53 Recursive inventory",items)
def f54():
    p=safe_path(); total=0
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file(): total+=x.stat().st_size
            except OSError: pass
    return record("54 Directory size",total)
def f55():
    p=safe_path(); return record("55 File count",sum(1 for x in p.rglob("*") if x.is_file()) if p.is_dir() else 0)
def f56():
    p=safe_path(); d={}
    if p.is_dir():
        for x in p.rglob("*"):
            if x.is_file(): d[x.suffix.lower() or "[no extension]"]=d.get(x.suffix.lower() or "[no extension]",0)+1
    return record("56 Extension statistics",dict(sorted(d.items(),key=lambda kv:-kv[1])))
def f57():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file(): arr.append((x.stat().st_size,str(x)))
            except OSError: pass
    return record("57 Largest files",sorted(arr,reverse=True)[:20])
def f58():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file(): arr.append((x.stat().st_mtime,str(x)))
            except OSError: pass
    return record("58 Newest files",[(dt.datetime.fromtimestamp(t).isoformat(),n) for t,n in sorted(arr,reverse=True)[:20]])
def f59():
    p=safe_path(); return record("59 Empty files",[str(x) for x in p.rglob("*") if x.is_file() and x.stat().st_size==0][:200] if p.is_dir() else [])
def f60():
    p=safe_path(); return record("60 Symlink inventory",[str(x) for x in p.rglob("*") if x.is_symlink()][:500] if p.is_dir() else [])
def f61():
    p=safe_path(); bad=[]
    if p.is_dir():
        for x in p.rglob("*"):
            if x.is_symlink():
                try: x.resolve(strict=True)
                except FileNotFoundError: bad.append(str(x))
    return record("61 Broken symlinks",bad)
def f62():
    p=safe_path(); return record("62 Hidden files",[str(x) for x in p.rglob("*") if x.name.startswith(".")][:500] if p.is_dir() else [])
def f63():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file() and os.access(x,os.X_OK): arr.append(str(x))
            except OSError: pass
    return record("63 Executable files",arr[:500])
def f64():
    p=safe_path(); exts={".zip",".tar",".gz",".bz2",".xz",".7z",".rar",".tgz"}
    return record("64 Archive files",[str(x) for x in p.rglob("*") if x.is_file() and x.suffix.lower() in exts][:500] if p.is_dir() else [])
def f65():
    p=safe_path(); return record("65 File exists",{"exists":p.exists(),"is_file":p.is_file(),"is_dir":p.is_dir()})
def f66():
    p=safe_path(); return record("66 Absolute path",str(p.resolve()))
def f67():
    p=safe_path(); return record("67 Real path",os.path.realpath(p))
def f68():
    p=safe_path(); return record("68 Read permission",os.access(p,os.R_OK))
def f69():
    p=safe_path(); return record("69 Write permission",os.access(p,os.W_OK))
def f70():
    p=safe_path(); return record("70 Execute permission",os.access(p,os.X_OK))

# ---------- 71-100 Content/code audit ----------
def text_file_feature(label, fn):
    p=safe_path()
    if not p.is_file(): return record(label,"not a file")
    try: return record(label,fn(read_text(p)))
    except Exception as e: return record(label,str(e))
def f71(): return text_file_feature("71 Line count",lambda s:len(s.splitlines()))
def f72(): return text_file_feature("72 Word count",lambda s:len(s.split()))
def f73(): return text_file_feature("73 Character count",len)
def f74():
    p=safe_path(); q=ask("Text to search: "); return record("74 Text search",[i+1 for i,l in enumerate(read_text(p).splitlines()) if q in l][:500])
def f75():
    p=safe_path(); q=ask("Case-insensitive text: ").lower(); return record("75 Case-insensitive search",[i+1 for i,l in enumerate(read_text(p).splitlines()) if q in l.lower()][:500])
def f76():
    p=safe_path(); q=ask("Regex: ")
    try: rg=re.compile(q); return record("76 Regex search",[{"line":i+1,"text":l[:300]} for i,l in enumerate(read_text(p).splitlines()) if rg.search(l)][:500])
    except Exception as e: return record("76 Regex search",str(e))
def f77(): return text_file_feature("77 TODO/FIXME scan",lambda s:[{"line":i+1,"text":l[:300]} for i,l in enumerate(s.splitlines()) if re.search(r"\b(TODO|FIXME)\b",l,re.I)][:500])
def f78(): return text_file_feature("78 URL pattern scan",lambda s:re.findall(r"https?://[^\s\"'<>]+",s)[:500])
def f79(): return text_file_feature("79 Email pattern scan",lambda s:re.findall(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",s)[:500])
def f80(): return text_file_feature("80 IPv4 pattern scan",lambda s:re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b",s)[:500])
def f81(): return text_file_feature("81 Hash pattern scan",lambda s:re.findall(r"\b[a-fA-F0-9]{32,128}\b",s)[:500])
def f82(): return text_file_feature("82 Base64-like pattern scan",lambda s:re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])",s)[:200])
def f83():
    return text_file_feature("83 Private-key marker scan",lambda s:re.findall(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",s)[:50])
def f84():
    pats=r"(password|passwd|secret|api[_-]?key|token|access[_-]?key)"
    return text_file_feature("84 Secret-name scan",lambda s:[{"line":i+1,"text":l[:300]} for i,l in enumerate(s.splitlines()) if re.search(pats,l,re.I)][:500])
def f85():
    p=safe_path()
    try: compile(read_text(p),str(p),"exec"); return record("85 Python syntax","OK")
    except Exception as e: return record("85 Python syntax",str(e))
def f86():
    p=safe_path()
    if not command_exists("bash"): return record("86 Bash syntax","bash not installed")
    return record("86 Bash syntax",run(["bash","-n",str(p)])[1] or "OK")
def f87():
    p=safe_path()
    try: return record("87 JSON validation",json.loads(read_text(p)))
    except Exception as e:return record("87 JSON validation",str(e))
def f88():
    p=safe_path()
    try:
        import tomllib
        return record("88 TOML validation",tomllib.loads(read_text(p)))
    except Exception as e:return record("88 TOML validation",str(e))
def f89():
    p=safe_path()
    try: return record("89 INI validation",dict(configparser.ConfigParser().read(p)))
    except Exception as e:return record("89 INI validation",str(e))
def f90():
    p=safe_path()
    try: ET.parse(p); return record("90 XML validation","OK")
    except Exception as e:return record("90 XML validation",str(e))
def f91():
    p=safe_path()
    try:
        rows=list(csv.reader(read_text(p).splitlines())); widths=sorted({len(r) for r in rows}); return record("91 CSV validation",{"rows":len(rows),"column_counts":widths,"consistent":len(widths)<=1})
    except Exception as e:return record("91 CSV validation",str(e))
def f92(): return text_file_feature("92 Markdown links",lambda s:re.findall(r"\[[^\]]+\]\(([^)]+)\)",s)[:500])
def f93(): return text_file_feature("93 IPv6 pattern scan",lambda s:re.findall(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])",s)[:200])
def f94(): return text_file_feature("94 Domain pattern scan",lambda s:re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",s,re.I)[:500])
def f95(): return text_file_feature("95 Comment line count",lambda s:sum(1 for l in s.splitlines() if l.lstrip().startswith(("#","//",";"))))
def f96(): return text_file_feature("96 Blank line count",lambda s:sum(1 for l in s.splitlines() if not l.strip()))
def f97(): return text_file_feature("97 Long line audit",lambda s:[i+1 for i,l in enumerate(s.splitlines()) if len(l)>120][:500])
def f98(): return text_file_feature("98 Trailing whitespace audit",lambda s:[i+1 for i,l in enumerate(s.splitlines()) if l.rstrip()!=l][:500])
def f99(): return text_file_feature("99 Non-ASCII character count",lambda s:sum(1 for ch in s if ord(ch)>127))
def f100():
    p=safe_path(); b=Path(p).read_bytes(); return record("100 Binary entropy estimate",round(-sum((b.count(bytes([i]))/len(b))*__import__("math").log2(b.count(bytes([i]))/len(b)) for i in range(256) if b.count(bytes([i]))) if b else 0,4))

# ---------- 101-120 System ----------
def f101(): return record("101 OS",platform.platform())
def f102(): return record("102 Kernel",platform.release())
def f103(): return record("103 Architecture",platform.machine())
def f104(): return record("104 Python version",sys.version)
def f105(): return record("105 Hostname",socket.gethostname())
def f106():
    p=Path("/proc/uptime")
    return record("106 Uptime",p.read_text().split()[0]+" seconds" if p.exists() else "unavailable")
def f107(): return record("107 Timezone",dt.datetime.now().astimezone().tzname())
def f108(): return record("108 Current time",dt.datetime.now().astimezone().isoformat())
def f109(): return record("109 CPU count",os.cpu_count())
def f110():
    p=Path("/proc/meminfo"); d={}
    if p.exists():
        for l in p.read_text().splitlines()[:20]:
            k,_,v=l.partition(":"); d[k]=v.strip()
    return record("110 Memory summary",d)
def f111():
    return record("111 Disk usage",shutil.disk_usage("/")._asdict())
def f112():
    if command_exists("df"): return record("112 Mounted filesystems",run(["df","-h"])[1])
    return record("112 Mounted filesystems","df unavailable")
def f113():
    if command_exists("lsblk"): return record("113 Block devices",run(["lsblk","-o","NAME,SIZE,TYPE,MOUNTPOINT"])[1])
    return record("113 Block devices","lsblk unavailable")
def f114():
    if command_exists("lsusb"): return record("114 USB devices",run(["lsusb"])[1])
    return record("114 USB devices","lsusb unavailable")
def f115():
    if command_exists("lspci"): return record("115 PCI devices",run(["lspci"])[1])
    return record("115 PCI devices","lspci unavailable")
def f116():
    p=Path("/proc/modules"); return record("116 Loaded modules",p.read_text(errors="replace")[:10000] if p.exists() else "unavailable")
def f117():
    if command_exists("ps"): return record("117 Process list",run(["ps","-eo","pid,user,%cpu,%mem,comm","--sort=-%cpu"],10)[1][:12000])
    return record("117 Process list","ps unavailable")
def f118():
    if command_exists("ps"): return record("118 Process count",len(run(["ps","-e","-o","pid="])[1].splitlines()))
    return record("118 Process count","ps unavailable")
def f119():
    if command_exists("ps"): return record("119 Resource-heavy processes",run(["ps","-eo","pid,user,%cpu,%mem,comm","--sort=-%mem"],10)[1][:5000])
    return record("119 Resource-heavy processes","ps unavailable")
def f120():
    if command_exists("systemctl"): return record("120 Service summary",run(["systemctl","--no-pager","--type=service","--state=running"],10)[1][:12000])
    return record("120 Service summary","systemctl unavailable")

# ---------- 121-145 Linux security posture ----------
def f121():
    if command_exists("ufw"): return record("121 UFW status",run(["ufw","status"],10)[1])
    return record("121 UFW status","ufw not installed")
def f122(): return record("122 iptables availability",{"installed":command_exists("iptables"),"path":shutil.which("iptables")})
def f123(): return record("123 nftables availability",{"installed":command_exists("nft"),"path":shutil.which("nft")})
def f124():
    if command_exists("aa-status"): return record("124 AppArmor status",run(["aa-status"],10)[1] or run(["aa-status"],10)[2])
    return record("124 AppArmor status","aa-status unavailable")
def f125():
    if command_exists("getenforce"): return record("125 SELinux status",run(["getenforce"])[1])
    return record("125 SELinux status","getenforce unavailable")
def f126(): return record("126 Sudo availability",{"installed":command_exists("sudo"),"path":shutil.which("sudo")})
def f127():
    if Path("/etc/passwd").exists():
        return record("127 Users summary",[l.split(":")[0] for l in Path("/etc/passwd").read_text(errors="replace").splitlines()])
    return record("127 Users summary","/etc/passwd unavailable")
def f128():
    if Path("/etc/group").exists(): return record("128 Groups summary",[l.split(":")[0] for l in Path("/etc/group").read_text(errors="replace").splitlines()])
    return record("128 Groups summary","/etc/group unavailable")
def f129():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file() and x.stat().st_uid==0: arr.append(str(x))
            except OSError: pass
    return record("129 Root-owned files",arr[:500])
def f130():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file() and (x.stat().st_mode & 2): arr.append(str(x))
            except OSError: pass
    return record("130 World-writable files",arr[:500])
def f131():
    p=safe_path(); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file() and (x.stat().st_mode & 0o4000 or x.stat().st_mode & 0o2000): arr.append(str(x))
            except OSError: pass
    return record("131 SUID/SGID files",arr[:500])
def f132():
    p=safe_path(); names=re.compile(r"(password|passwd|secret|token|key|credential)",re.I); arr=[]
    if p.is_dir():
        for x in p.rglob("*"):
            try:
                if x.is_file() and names.search(x.name) and (x.stat().st_mode & 4): arr.append(str(x))
            except OSError: pass
    return record("132 World-readable secret-like filenames",arr[:500])
def f133(): return record("133 SSH config",Path.home().joinpath(".ssh/config").exists())
def f134():
    d=Path.home()/".ssh"; return record("134 SSH key inventory",[x.name for x in d.iterdir() if x.is_file() and ("key" in x.name.lower() or x.name.startswith("id_"))] if d.exists() else [])
def f135():
    p=Path.home()/".ssh/authorized_keys"; return record("135 Authorized keys presence",p.exists())
def f136():
    if command_exists("crontab"): return record("136 Crontab availability",run(["crontab","-l"],5)[1] or "no visible crontab")
    return record("136 Crontab availability","crontab unavailable")
def f137():
    paths=[Path.home()/".config/autostart",Path.home()/".config/systemd/user"]
    return record("137 Startup entries",{str(p):[x.name for x in p.iterdir()] if p.exists() else [] for p in paths})
def f138():
    p=Path("/tmp"); return record("138 /tmp permissions",oct(p.stat().st_mode & 0o7777) if p.exists() else "missing")
def f139():
    p=Path.home(); return record("139 Home inventory",[x.name for x in p.iterdir()][:500])
def f140():
    managers=["apt","apt-get","dnf","yum","pacman","apk","zypper"]
    return record("140 Package manager detection",{x:shutil.which(x) for x in managers if shutil.which(x)})
def f141():
    managers=["apt","dnf","yum","pacman","apk","zypper"]
    return record("141 Security update tools",{x:shutil.which(x) for x in managers if shutil.which(x)})
def f142(): return record("142 Git config",Path.home().joinpath(".gitconfig").exists())
def f143(): return record("143 SSH directory permissions",oct((Path.home()/".ssh").stat().st_mode & 0o7777) if (Path.home()/".ssh").exists() else "missing")
def f144():
    p=Path("/etc/ssh/sshd_config"); return record("144 SSH server config",p.exists())
def f145():
    return record("145 PATH audit",{"PATH":os.environ.get("PATH",""),"entries":os.environ.get("PATH","").split(os.pathsep)})

# ---------- 146-165 Git/project ----------
def git(args, cwd=None): return run(["git"]+args,10)
def repo_root(p):
    rc,o,e=git(["rev-parse","--show-toplevel"],p)
    return Path(o) if rc==0 and o else None
def project_path():
    return safe_path("Project/repo path: ",".")
def f146(): return record("146 Git repository",bool(repo_root(project_path())))
def f147():
    p=project_path(); return record("147 Git status",git(["status","--short"],p)[1] or git(["status","--short"],p)[2])
def f148():
    p=project_path(); return record("148 Git branch",git(["branch","--show-current"],p)[1])
def f149():
    p=project_path(); return record("149 Commit count",git(["rev-list","--count","HEAD"],p)[1])
def f150():
    p=project_path(); return record("150 Git remotes",git(["remote","-v"],p)[1])
def f151():
    p=project_path(); return record("151 Git diff summary",git(["diff","--stat"],p)[1])
def f152():
    p=project_path(); return record("152 Ignored files",git(["status","--ignored","--short"],p)[1][:10000])
def f153():
    p=project_path(); return record("153 Repo root",repo_root(p) or "not a git repo")
def f154():
    p=project_path(); return record("154 Tracked file count",git(["ls-files"],p)[1].count("\n") if repo_root(p) else 0)
def f155():
    p=project_path(); return record("155 Untracked count",sum(1 for l in git(["status","--porcelain"],p)[1].splitlines() if l.startswith("??")))
def f156():
    p=project_path(); return record("156 Project tree",[str(x.relative_to(p)) for x in p.rglob("*")][:1000] if p.is_dir() else [])
def f157():
    p=project_path(); return record("157 Python files",[str(x.relative_to(p)) for x in p.rglob("*.py")][:500])
def f158():
    p=project_path(); return record("158 Shell files",[str(x.relative_to(p)) for x in p.rglob("*.sh")][:500])
def f159():
    p=project_path(); exts={".json",".toml",".ini",".cfg",".yaml",".yml",".env"}; return record("159 Config files",[str(x.relative_to(p)) for x in p.rglob("*") if x.is_file() and x.suffix.lower() in exts][:500])
def f160():
    p=project_path(); return record("160 Log files",[str(x.relative_to(p)) for x in p.rglob("*") if x.is_file() and x.suffix.lower()==".log"][:500])
def f161():
    p=project_path(); return record("161 Test files",[str(x.relative_to(p)) for x in p.rglob("*") if x.is_file() and ("test" in x.name.lower() or "spec" in x.name.lower())][:500])
def f162():
    p=project_path(); arr=[]
    for x in p.rglob("*") if p.is_dir() else []:
        if x.is_file():
            try:
                s=read_text(x,500000)
                if re.search(r"\b(TODO|FIXME)\b",s,re.I): arr.append(str(x.relative_to(p)))
            except Exception: pass
    return record("162 Repo TODO scan",arr[:500])
def f163():
    p=project_path(); d={}
    for x in p.rglob("*") if p.is_dir() else []:
        if x.is_file(): d.setdefault(x.name,[]).append(str(x.relative_to(p)))
    return record("163 Duplicate filenames",{k:v for k,v in d.items() if len(v)>1})
def f164():
    p=project_path(); arr=[]
    for x in p.rglob("*") if p.is_dir() else []:
        try:
            if x.is_file(): arr.append((x.stat().st_size,str(x.relative_to(p))))
        except OSError: pass
    return record("164 Largest repo files",sorted(arr,reverse=True)[:20])
def f165(): return record("165 Git version",git(["--version"])[1] if command_exists("git") else "git unavailable")

# ---------- 166-190 Data utilities ----------
def f166(): return record("166 Base64 encode",base64.b64encode(ask("Text: ").encode()).decode())
def f167():
    try:return record("167 Base64 decode",base64.b64decode(ask("Base64: ")).decode(errors="replace"))
    except Exception as e:return record("167 Base64 decode",str(e))
def f168(): return record("168 Hex encode",ask("Text: ").encode().hex())
def f169():
    try:return record("169 Hex decode",bytes.fromhex(ask("Hex: ")).decode(errors="replace"))
    except Exception as e:return record("169 Hex decode",str(e))
def f170(): return record("170 URL encode",urllib.parse.quote(ask("Text: "),safe=""))
def f171(): return record("171 URL decode",urllib.parse.unquote(ask("Encoded: ")))
def f172():
    import codecs; return record("172 ROT13",codecs.encode(ask("Text: "),"rot_13"))
def f173(): return record("173 UUID",str(uuid.uuid4()))
def f174(): return record("174 Random token",secrets.token_urlsafe(32))
def f175(): return record("175 Random bytes hex",secrets.token_hex(32))
def f176():
    n=max(8,min(128,int(ask("Length 8-128: ","24")))); alphabet=string.ascii_letters+string.digits+"-_"; return record("176 Random token custom","".join(secrets.choice(alphabet) for _ in range(n)))
def f177():
    s=ask("Entropy text: "); from collections import Counter; import math
    n=len(s); e=-sum(v/n*math.log2(v/n) for v in Counter(s).values()) if n else 0
    return record("177 Text entropy",{"bits_per_char":round(e,4),"approx_total_bits":round(e*n,2)})
def f178():
    try:return record("178 JSON pretty print",json.dumps(json.loads(ask("JSON: ")),indent=2,ensure_ascii=False))
    except Exception as e:return record("178 JSON pretty print",str(e))
def f179():
    try:return record("179 JSON minify",json.dumps(json.loads(ask("JSON: ")),separators=(",",":"),ensure_ascii=False))
    except Exception as e:return record("179 JSON minify",str(e))
def f180():
    p=safe_path(); rows=list(csv.reader(read_text(p).splitlines()))[:10]; return record("180 CSV preview",rows)
def f181():
    s=ask("Unix timestamp: "); return record("181 Timestamp converter",dt.datetime.fromtimestamp(float(s)).astimezone().isoformat())
def f182():
    u=normalize_url(ask("URL: ")); return record("182 URL parser",urllib.parse.urlsplit(u)._asdict())
def f183():
    s=ask("CIDR: "); n=ipaddress.ip_network(s,strict=False); return record("183 CIDR parser",{"network":str(n),"netmask":str(n.netmask),"broadcast":str(n.broadcast_address),"hosts":n.num_addresses-(2 if n.version==4 and n.num_addresses>=2 else 0)})
def f184():
    s=ask("IP address: "); ip=ipaddress.ip_address(s); return record("184 IP classification",{"version":ip.version,"private":ip.is_private,"global":ip.is_global,"loopback":ip.is_loopback,"multicast":ip.is_multicast})
def f185(): return record("185 JSON escape",json.dumps(ask("Text: "))[1:-1])
def f186(): return record("186 JSON unescape",json.loads('"'+ask("Escaped JSON text: ")+'"'))
def f187():
    p=safe_path(); return record("187 SHA256 verification",hash_file(p,"sha256") if p.is_file() else "not a file")
def f188():
    p=safe_path(); expected=ask("Expected SHA256: ").lower(); actual=hash_file(p,"sha256") if p.is_file() else ""; return record("188 SHA256 compare",{"match":actual==expected,"actual":actual})
def f189(): return record("189 Random UUID4 list",[str(uuid.uuid4()) for _ in range(5)])
def f190(): return record("190 Current UTC",dt.datetime.now(dt.timezone.utc).isoformat())

# ---------- 191-200 Reports/meta ----------
def export_json(path):
    Path(path).write_text(json.dumps(RESULTS,indent=2,ensure_ascii=False,default=str),encoding="utf-8")
def f191():
    p=ask("JSON report path: ","ahza_report.json"); export_json(p); return record("191 JSON report",str(Path(p).resolve()))
def f192():
    p=ask("CSV report path: ","ahza_report.csv")
    with open(p,"w",newline="",encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["time","feature","result"])
        for x in RESULTS: w.writerow([x["time"],x["feature"],json.dumps(x["result"],ensure_ascii=False,default=str)])
    return record("192 CSV report",str(Path(p).resolve()))
def f193():
    p=ask("TXT report path: ","ahza_report.txt")
    with open(p,"w",encoding="utf-8") as f:
        for x in RESULTS: f.write(f'[{x["time"]}] {x["feature"]}\n{json.dumps(x["result"],ensure_ascii=False,default=str)}\n\n')
    return record("193 TXT report",str(Path(p).resolve()))
def f194():
    p=ask("Session path: ","ahza_session.json"); export_json(p); return record("194 Save session",str(Path(p).resolve()))
def f195():
    p=ask("Session path: ","ahza_session.json")
    try:return record("195 View session",json.loads(Path(p).read_text(encoding="utf-8")))
    except Exception as e:return record("195 View session",str(e))
def f196(): RESULTS.clear(); return record("196 Clear results","cleared")
def f197():
    if not RESULTS: return record("197 Export current result","no results")
    p=ask("Export path: ","ahza_current_result.json"); Path(p).write_text(json.dumps(RESULTS[-1],indent=2,ensure_ascii=False,default=str),encoding="utf-8"); return record("197 Export current result",str(Path(p).resolve()))
def f198(): return record("198 Logger status",{"path":str(LOG_FILE),"exists":LOG_FILE.exists()})
def f199(): return record("199 Self-test",self_test())
def f200(): return record("200 Help/about",{"app":APP,"version":VERSION,"commands":203,"safe_scope":"authorized defensive auditing"})


# ---------- 201-203 network utilities ----------
def f201():
    """Discover devices on an authorized local Wi-Fi/LAN using Nmap."""
    import shutil
    import subprocess
    import re

    if not shutil.which("nmap"):
        return record("201 Wi-Fi/LAN device detector", {
            "error": "Nmap belum terpasang. Install dengan: sudo apt install nmap"
        })

    raw_net = ask(
        "Subnet Wi-Fi/LAN milikmu (contoh 192.168.1.0/24, Enter=otomatis): "
    ).strip()

    try:
        if raw_net:
            net = ipaddress.ip_network(raw_net, strict=False)
        else:
            candidates = []
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                    addr = info[4][0]
                    if not addr.startswith("127."):
                        candidates.append(addr)
            except Exception:
                pass
            if not candidates:
                return record("201 Wi-Fi/LAN device detector", {
                    "error": "IP lokal tidak ditemukan; masukkan subnet manual"
                })
            net = ipaddress.ip_network(candidates[0] + "/24", strict=False)
    except ValueError:
        return record("201 Wi-Fi/LAN device detector", {"error": "Subnet tidak valid"})

    if net.version != 4 or net.num_addresses > 256:
        return record("201 Wi-Fi/LAN device detector", {
            "error": "Gunakan subnet IPv4 maksimal 256 alamat"
        })

    # Host discovery only; no service exploitation or credential testing.
    cmd = ["nmap", "-sn", "-n", str(net)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    except Exception as e:
        return record("201 Wi-Fi/LAN device detector", {"error": str(e)})

    if p.returncode != 0:
        return record("201 Wi-Fi/LAN device detector", {
            "error": p.stderr.strip() or "Nmap gagal",
            "command": " ".join(cmd)
        })

    devices = []
    current = None
    for line in p.stdout.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            if current:
                devices.append(current)
            current = {"ip": m.group(1), "mac": None, "vendor": None}
            continue

        m = re.search(r"MAC Address:\s+([0-9A-Fa-f:]{17})(?:\s+\((.*?)\))?", line)
        if m and current:
            current["mac"] = m.group(1).upper()
            current["vendor"] = m.group(2) or "Unknown"

    if current:
        devices.append(current)

    # Nmap may omit MAC data for the local host depending on permissions.
    return record("201 Wi-Fi/LAN device detector", {
        "network": str(net),
        "device_count": len(devices),
        "devices": devices,
        "note": (
            "Vendor/Merek berasal dari MAC OUI dan tidak selalu menunjukkan "
            "merek/model HP secara pasti. Hanya perangkat yang terhubung/terlihat "
            "di jaringan yang dipindai yang dapat terdeteksi."
        ),
        "scope": "authorized local network only",
    })


def f202():
    """Bounded discovery of live hosts on a local/authorized IPv4 subnet."""
    raw = ask("Authorized local subnet (example 192.168.1.0/24): ")
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return record("202 Authorized local subnet scanner", {"error": "Invalid network"})

    if net.version != 4:
        return record("202 Authorized local subnet scanner",
                      {"error": "IPv4 only for this scanner"})

    hosts = list(net.hosts())
    if len(hosts) > 256:
        return record("202 Authorized local subnet scanner",
                      {"error": "Maximum 256 hosts per scan"})

    def probe(ip):
        ip_s = str(ip)
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_s)[0]
        except Exception:
            pass

        open_ports = []
        for port in (22, 80, 443, 3389):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.25)
            try:
                if s.connect_ex((ip_s, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                s.close()

        return {
            "ip": ip_s,
            "hostname": hostname,
            "common_open_ports": open_ports,
        }

    import concurrent.futures
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        for item in ex.map(probe, hosts):
            if item["hostname"] or item["common_open_ports"]:
                found.append(item)

    return record("202 Authorized local subnet scanner", {
        "subnet": str(net),
        "hosts_checked": len(hosts),
        "hosts_found": len(found),
        "hosts": found,
        "scope": "local/authorized network only",
    })


def f203():
    """List nearby Wi-Fi networks visible to the local wireless adapter."""
    import shutil
    import subprocess
    import re

    # Prefer iw; fall back to nmcli if available.
    if shutil.which("iw"):
        try:
            iface_out = subprocess.run(
                ["iw", "dev"], capture_output=True, text=True, timeout=10
            ).stdout
            m = re.search(r"Interface\s+(\S+)", iface_out)
            if not m:
                return record("203 Nearby Wi-Fi networks", {
                    "error": "Wireless interface tidak ditemukan"
                })
            iface = m.group(1)
            p = subprocess.run(
                ["sudo", "iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            if p.returncode != 0:
                return record("203 Nearby Wi-Fi networks", {
                    "error": p.stderr.strip() or "Wi-Fi scan gagal",
                    "note": "Perlu adapter Wi-Fi dan izin scan."
                })

            networks = []
            current = {}
            for line in p.stdout.splitlines():
                line = line.strip()
                if line.startswith("BSS "):
                    if current:
                        networks.append(current)
                    bssid = line.split()[1].split("(")[0]
                    current = {"bssid": bssid, "ssid": None, "signal_dbm": None}
                elif line.startswith("SSID:") and current:
                    current["ssid"] = line[5:].strip() or "<hidden>"
                elif "signal:" in line and current:
                    sm = re.search(r"signal:\s*(-?\d+(?:\.\d+)?)", line)
                    if sm:
                        current["signal_dbm"] = float(sm.group(1))
            if current:
                networks.append(current)

            return record("203 Nearby Wi-Fi networks", {
                "interface": iface,
                "network_count": len(networks),
                "networks": networks,
                "note": "Ini hanya menampilkan jaringan Wi-Fi yang terlihat; tidak memindai perangkat yang terhubung ke jaringan lain."
            })
        except Exception as e:
            return record("203 Nearby Wi-Fi networks", {"error": str(e)})

    if shutil.which("nmcli"):
        try:
            p = subprocess.run(
                ["nmcli", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=20
            )
            return record("203 Nearby Wi-Fi networks", {
                "output": p.stdout.strip(),
                "note": "Daftar SSID/BSSID yang terlihat oleh adapter Wi-Fi."
            })
        except Exception as e:
            return record("203 Nearby Wi-Fi networks", {"error": str(e)})

    return record("203 Nearby Wi-Fi networks", {
        "error": "Butuh iw atau nmcli serta adapter Wi-Fi."
    })


FEATURES = [
("01","DNS lookup",f01),("02","Reverse DNS",f02),("03","IPv4 validation",f03),("04","IPv6 validation",f04),
("05","Resolve all addresses",f05),("06","TCP connectivity",f06),("07","Single port check",f07),("08","Bounded TCP port scan",f08),
("09","Local hostname",f09),("10","Local addresses",f10),("11","Network interfaces",f11),("12","Routing table",f12),
("13","ARP table",f13),("14","DNS configuration",f14),("15","Ping availability",f15),("16","Traceroute availability",f16),
("17","Curl availability",f17),("18","OpenSSL availability",f18),("19","DNS addresses",f19),("20","Conservative subdomain check",f20),
("21","HTTP status",f21),("22","HTTP headers",f22),("23","Security headers",f23),("24","Server header",f24),
("25","Redirect destination",f25),("26","HTTP response time",f26),("27","robots.txt",f27),("28","sitemap.xml",f28),
("29","HTTPS check",f29),("30","TLS certificate",f30),("31","TLS version",f31),("32","TLS cipher",f32),
("33","URL parse",f33),("34","URL encode",f34),("35","URL decode",f35),("36","Query parser",f36),
("37","Userinfo detector",f37),("38","HTTP HEAD",f38),("39","HTTP OPTIONS",f39),("40","Cookie flags",f40),
("41","MD5 hash",f41),("42","SHA1 hash",f42),("43","SHA224 hash",f43),("44","SHA256 hash",f44),
("45","SHA384 hash",f45),("46","SHA512 hash",f46),("47","File size",f47),("48","File type",f48),
("49","File permissions",f49),("50","File owner",f50),("51","File timestamps",f51),("52","Directory listing",f52),
("53","Recursive inventory",f53),("54","Directory size",f54),("55","File count",f55),("56","Extension statistics",f56),
("57","Largest files",f57),("58","Newest files",f58),("59","Empty files",f59),("60","Symlink inventory",f60),
("61","Broken symlinks",f61),("62","Hidden files",f62),("63","Executable files",f63),("64","Archive files",f64),
("65","File exists/type",f65),("66","Absolute path",f66),("67","Real path",f67),("68","Read permission",f68),
("69","Write permission",f69),("70","Execute permission",f70),("71","Line count",f71),("72","Word count",f72),
("73","Character count",f73),("74","Text search",f74),("75","Case-insensitive search",f75),("76","Regex search",f76),
("77","TODO/FIXME scan",f77),("78","URL pattern scan",f78),("79","Email pattern scan",f79),("80","IPv4 pattern scan",f80),
("81","Hash pattern scan",f81),("82","Base64-like pattern scan",f82),("83","Private-key marker scan",f83),("84","Secret-name scan",f84),
("85","Python syntax",f85),("86","Bash syntax",f86),("87","JSON validation",f87),("88","TOML validation",f88),
("89","INI validation",f89),("90","XML validation",f90),("91","CSV validation",f91),("92","Markdown links",f92),
("93","IPv6 pattern scan",f93),("94","Domain pattern scan",f94),("95","Comment line count",f95),("96","Blank line count",f96),
("97","Long line audit",f97),("98","Trailing whitespace audit",f98),("99","Non-ASCII count",f99),("100","Binary entropy estimate",f100),
("101","OS",f101),("102","Kernel",f102),("103","Architecture",f103),("104","Python version",f104),
("105","Hostname",f105),("106","Uptime",f106),("107","Timezone",f107),("108","Current time",f108),
("109","CPU count",f109),("110","Memory summary",f110),("111","Disk usage",f111),("112","Mounted filesystems",f112),
("113","Block devices",f113),("114","USB devices",f114),("115","PCI devices",f115),("116","Loaded modules",f116),
("117","Process list",f117),("118","Process count",f118),("119","Resource-heavy processes",f119),("120","Service summary",f120),
("121","UFW status",f121),("122","iptables availability",f122),("123","nftables availability",f123),("124","AppArmor status",f124),
("125","SELinux status",f125),("126","Sudo availability",f126),("127","Users summary",f127),("128","Groups summary",f128),
("129","Root-owned files",f129),("130","World-writable files",f130),("131","SUID/SGID files",f131),("132","World-readable secret-like names",f132),
("133","SSH config",f133),("134","SSH key inventory",f134),("135","Authorized keys presence",f135),("136","Crontab availability",f136),
("137","Startup entries",f137),("138","/tmp permissions",f138),("139","Home inventory",f139),("140","Package manager detection",f140),
("141","Security update tools",f141),("142","Git config",f142),("143","SSH directory permissions",f143),("144","SSH server config",f144),
("145","PATH audit",f145),("146","Git repository",f146),("147","Git status",f147),("148","Git branch",f148),
("149","Commit count",f149),("150","Git remotes",f150),("151","Git diff summary",f151),("152","Ignored files",f152),
("153","Repo root",f153),("154","Tracked file count",f154),("155","Untracked count",f155),("156","Project tree",f156),
("157","Python files",f157),("158","Shell files",f158),("159","Config files",f159),("160","Log files",f160),
("161","Test files",f161),("162","Repo TODO scan",f162),("163","Duplicate filenames",f163),("164","Largest repo files",f164),
("165","Git version",f165),("166","Base64 encode",f166),("167","Base64 decode",f167),("168","Hex encode",f168),
("169","Hex decode",f169),("170","URL encode",f170),("171","URL decode",f171),("172","ROT13",f172),
("173","UUID",f173),("174","Random token",f174),("175","Random bytes hex",f175),("176","Random token custom",f176),
("177","Text entropy",f177),("178","JSON pretty print",f178),("179","JSON minify",f179),("180","CSV preview",f180),
("181","Timestamp converter",f181),("182","URL parser",f182),("183","CIDR parser",f183),("184","IP classification",f184),
("185","JSON escape",f185),("186","JSON unescape",f186),("187","SHA256 verification",f187),("188","SHA256 compare",f188),
("189","UUID4 list",f189),("190","Current UTC",f190),("191","JSON report",f191),("192","CSV report",f192),
("193","TXT report",f193),("194","Save session",f194),("195","View session",f195),("196","Clear results",f196),
("197","Export current result",f197),("198","Logger status",f198),("199","Self-test",f199),("200","Help/About",f200),
("201","Wi-Fi/LAN connected device detector",f201),("202","Authorized local subnet scanner",f202),("203","Nearby Wi-Fi networks",f203),
]

def self_test():
    checks = {
        "feature_count": len(FEATURES),
        "unique_numbers": len({x[0] for x in FEATURES}) == 203,
        "callables": all(callable(x[2]) for x in FEATURES),
        "python": sys.version.split()[0],
        "openssl": command_exists("openssl"),
        "git": command_exists("git"),
    }
    return checks

def menu():
    print(c("COMMANDS", MAGENTA))
    for i in range(0,len(FEATURES),4):
        row=FEATURES[i:i+4]
        print("   ".join(f"{n}. {name[:28]:28}" for n,name,_ in row))
    print("\n0. Exit")
    print(c("Tip: commands that scan files should be used on directories you own or are authorized to audit.", DIM))

def main():
    parser=argparse.ArgumentParser(add_help=True)
    parser.add_argument("--no-banner",action="store_true")
    args=parser.parse_args()
    if not args.no_banner: banner()
    while True:
        if args.no_banner: print()
        menu()
        choice=ask("\nTEAM-AHZA > ")
        if choice in ("0","q","quit","exit"):
            print(c("Keluar. Stay safe.", GREEN)); break
        if not choice.isdigit() or not 1<=int(choice)<=202:
            print(c("Command tidak valid.", RED)); continue
        num=int(choice); code,name,fn=FEATURES[num-1]
        HISTORY.append(code)
        print(c(f"\n[{code}] {name}", BLUE))
        try:
            result=fn()
            if result is not None: out(result)
        except KeyboardInterrupt:
            print(c("\nDibatalkan.", YELLOW))
        except Exception as e:
            record(name,{"error":type(e).__name__,"message":str(e)})
            print(c(f"Error aman: {type(e).__name__}: {e}", RED))
        input(c("\nEnter untuk kembali ke menu...", DIM))
        if not args.no_banner: banner()

if __name__=="__main__":
    main()
