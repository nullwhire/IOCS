#!/usr/bin/env python3
"""artex-tracker: junta feeds públicos de instâncias ARTEX expostas.

Fontes:
  threatbook  feed IP:porta da ThreatBook
  maltrail    stamparm/trails malicious/artexai.txt (IP:porta + domínios)
  scanmalware feed Atom do hunt ScanMalware (URL em SCANMALWARE_FEED, opcional)
  fofa        pesquisa por icon_hash (FOFA_KEY, opcional)

Só biblioteca standard. Uma fonte que falha não apaga nada: o histórico
mantém-se e o indicador deixa de ser "ativo" ao fim de ACTIVE_DAYS.
"""
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA = Path(os.environ.get("DATA_DIR", "data"))
ACTIVE_DAYS = int(os.environ.get("ACTIVE_DAYS", "14"))
# last_seen só é reescrito de REFRESH_DAYS em REFRESH_DAYS, para o commit
# diário não mexer em milhares de linhas. Tem de ser < ACTIVE_DAYS.
REFRESH_DAYS = int(os.environ.get("REFRESH_DAYS", "7"))
UA = "Mozilla/5.0 (compatible; artex-tracker)"
FOFA_QUERY = os.environ.get("FOFA_QUERY", 'icon_hash="-576220750"')

SOURCES = {
    "threatbook": "https://threatbook.io/hubfs/Feeds/ARTEX.txt",
    "maltrail": "https://raw.githubusercontent.com/stamparm/trails/main/malicious/artexai.txt",
}

# Gamas publicadas pela Cloudflare. IPs aqui são anycast partilhado por muitos
# sites: ficam no master.csv com cdn=1 mas fora das listas de deteção.
CDN_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 "
    "141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 "
    "197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 "
    "104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
).split()]

IGNORE_DOMAIN_SUFFIX = ("scanmalware.com", "github.com", "githubusercontent.com",
                        "threatbook.io", "fofa.info", "w3.org")

RE_IPPORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
RE_IP_ANY = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b")
RE_DOM = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
RE_DOM_ANY = re.compile(r"[a-z0-9][a-z0-9.-]*\.[a-z]{2,}")


def log(msg):
    print(msg, file=sys.stderr)


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    return ip.is_global and ip.version == 4


def valid_domain(d):
    return bool(RE_DOM.match(d)) and not d.endswith(IGNORE_DOMAIN_SUFFIX) \
        and not RE_IP_ANY.fullmatch(d)


def is_cdn(value):
    ip = value.split(":")[0]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in CDN_NETS)


def parse_plain(text):
    """Linhas IP:porta, IP ou domínio. Ignora comentários."""
    out = set()
    for line in text.splitlines():
        line = line.strip().lower().replace("[.]", ".")
        if not line or line.startswith("#"):
            continue
        m = RE_IPPORT.match(line)
        if m and valid_ip(m.group(1)) and 0 < int(m.group(2)) < 65536:
            out.add(("ipport", line))
        elif valid_ip(line):
            out.add(("ip", line))
        elif valid_domain(line):
            out.add(("domain", line))
    return out


def parse_atom(text):
    """Extrai IPs/IP:porta/domínios de todo o texto de um feed Atom."""
    root = ET.fromstring(text)
    blob = " ".join(t for el in root.iter() for t in (el.text, el.tail) if t)
    blob = blob.lower().replace("[.]", ".")
    out = set()
    for ip, port in RE_IP_ANY.findall(blob):
        if valid_ip(ip):
            out.add(("ipport", f"{ip}:{port}") if port else ("ip", ip))
    for d in RE_DOM_ANY.findall(blob):
        if valid_domain(d):
            out.add(("domain", d))
    return out


def src_fofa():
    key = os.environ.get("FOFA_KEY")
    if not key:
        raise RuntimeError("FOFA_KEY não definido, fonte ignorada")
    params = {"key": key, "fields": "ip,port,host", "size": "1000",
              "qbase64": base64.b64encode(FOFA_QUERY.encode()).decode()}
    if os.environ.get("FOFA_EMAIL"):
        params["email"] = os.environ["FOFA_EMAIL"]
    data = json.loads(fetch("https://fofa.info/api/v1/search/all?"
                            + urllib.parse.urlencode(params)))
    if data.get("error"):
        raise RuntimeError(data.get("errmsg", "erro FOFA"))
    out = set()
    for ip, port, host in data.get("results", []):
        if valid_ip(ip) and port.isdigit():
            out.add(("ipport", f"{ip}:{port}"))
        h = host.lower().split("://")[-1].split(":")[0].split("/")[0]
        if valid_domain(h):
            out.add(("domain", h))
    return out


def collect():
    """Devolve {fonte: set((tipo, valor))} e lista de fontes que falharam."""
    results, failed = {}, []
    for name, url in SOURCES.items():
        try:
            results[name] = parse_plain(fetch(url))
        except Exception as e:  # noqa: BLE001
            failed.append(f"{name}: {e}")
    sm = os.environ.get("SCANMALWARE_FEED")
    if sm:
        try:
            results["scanmalware"] = parse_atom(fetch(sm))
        except Exception as e:  # noqa: BLE001
            failed.append(f"scanmalware: {e}")
    try:
        results["fofa"] = src_fofa()
    except Exception as e:  # noqa: BLE001
        if os.environ.get("FOFA_KEY"):
            failed.append(f"fofa: {e}")
    return results, failed


def load_master():
    path = DATA / "master.csv"
    master = {}
    if path.exists():
        with path.open(newline="") as f:
            for r in csv.DictReader(f):
                master[(r["type"], r["indicator"])] = r
    return master


def save_master(master):
    DATA.mkdir(parents=True, exist_ok=True)
    cols = ["type", "indicator", "sources", "first_seen", "last_seen", "cdn"]
    with (DATA / "master.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        for k in sorted(master):
            w.writerow({c: master[k][c] for c in cols})


def _ipkey(s):
    return tuple(map(int, s.split(".")))


def write_lists(master, today):
    cutoff = (today - timedelta(days=ACTIVE_DAYS)).isoformat()
    act = [r for r in master.values()
           if r["last_seen"] >= cutoff and r["cdn"] != "1"]
    ipport = sorted({r["indicator"] for r in act if r["type"] == "ipport"})
    ips = sorted({r["indicator"].split(":")[0] for r in act
                  if r["type"] in ("ip", "ipport")}, key=_ipkey)
    domains = sorted({r["indicator"] for r in act if r["type"] == "domain"})

    # Indicadores vistos em 2+ fontes distintas. Para IPs conta-se a união das
    # fontes de todas as entradas desse IP, seja qual for a porta.
    ip_src, ipport_src = {}, {}
    for r in act:
        srcs = set(r["sources"].split("|"))
        if r["type"] in ("ip", "ipport"):
            ip_src.setdefault(r["indicator"].split(":")[0], set()).update(srcs)
        if r["type"] == "ipport":
            ipport_src.setdefault(r["indicator"], set()).update(srcs)
    multi_ips = sorted((i for i, s in ip_src.items() if len(s) >= 2), key=_ipkey)
    multi_ipport = sorted(i for i, s in ipport_src.items() if len(s) >= 2)

    files = {"ipport.txt": ipport, "ips.txt": ips, "domains.txt": domains,
             "multi_source_ips.txt": multi_ips,
             "multi_source_ipport.txt": multi_ipport}
    for fname, rows in files.items():
        (DATA / fname).write_text("\n".join(rows) + ("\n" if rows else ""))
    return {k: len(v) for k, v in files.items()}


def telegram(text):
    tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not (tok and chat):
        return
    body = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{tok}/sendMessage", data=body), timeout=30)
    except Exception as e:  # noqa: BLE001
        log(f"telegram falhou: {e}")


def main():
    today = datetime.now(timezone.utc).date()
    results, failed = collect()
    for f in failed:
        log(f"FALHOU {f}")
    if not results:
        log("nenhuma fonte respondeu")
        return 1

    master = load_master()
    first_run = not master
    new = []
    for src, items in results.items():
        for typ, val in items:
            k = (typ, val)
            if k not in master:
                master[k] = {"type": typ, "indicator": val, "sources": src,
                             "first_seen": today.isoformat(),
                             "last_seen": today.isoformat(),
                             "cdn": "1" if is_cdn(val) else "0"}
                new.append(k)
            else:
                r = master[k]
                age = (today - datetime.fromisoformat(r["last_seen"]).date()).days
                if age >= REFRESH_DAYS:
                    r["last_seen"] = today.isoformat()
                s = set(r["sources"].split("|")) | {src}
                r["sources"] = "|".join(sorted(s))

    save_master(master)
    n = write_lists(master, today)
    log(f"fontes ok: {', '.join(results)} | novos: {len(new)} | "
        f"ativos: {n['ips.txt']} IPs, {n['ipport.txt']} IP:porta, "
        f"{n['domains.txt']} domínios | 2+ fontes: {n['multi_source_ips.txt']} IPs, "
        f"{n['multi_source_ipport.txt']} IP:porta")

    new_net = [v for t, v in new if t in ("ip", "ipport") and not is_cdn(v)]
    if new_net and not first_run:
        sample = "\n".join(new_net[:15])
        more = f"\n(+{len(new_net) - 15})" if len(new_net) > 15 else ""
        telegram(f"ARTEX tracker: {len(new_net)} novos IP/IP:porta\n{sample}{more}")
    if failed and not first_run:
        telegram("ARTEX tracker: fontes com erro\n" + "\n".join(failed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
