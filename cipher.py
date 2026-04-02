#!/usr/bin/env python3
import asyncio
import aiohttp
import aiodns
import os
import socket
import random
import re
import urllib.parse
from pathlib import Path
from rich.console import Console
import argparse
from typing import Set

# Optional .env loader - only used if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env into environment if present
except Exception:
    pass  # no dotenv available, assume env vars are exported manually

console = Console()

console.print(r"""
 _________.__                .___            ___________                     
 /   _____/|  |__ _____     __| _/______  _  _\_   _____/ ____  __ __  _____  
 \_____  \ |  |  \\__  \   / __ |/  _ \ \/ \/ /|    __)_ /    \|  |  \/     \ 
 /        \|   Y  \/ __ \_/ /_/ (  <_> )     / |        \   |  \  |  /  Y Y  \
/_______  /|___|  (____  /\____ |\____/ \/\_/ /_______  /___|  /____/|__|_|  /
        \/      \/     \/      \/                     \/     \/            \/ 
""", style="bold cyan")

# ===== API KEYS (read from environment; do NOT hard-code keys here) =====
ST_API = os.getenv("ST_API", "").strip()
SHODAN_API = os.getenv("SHODAN_API", "").strip()
OTX_API = os.getenv("OTX_API", "").strip()
VT_API = os.getenv("VT_API", "").strip()
CERTSPOTTER_API = os.getenv("CERTSPOTTER_API", "").strip()

# sensible defaults (try to use SecLists if available)
DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
    "/usr/share/seclists/Discovery/DNS/combined_subdomains.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1k.txt",
]

HIGH_VALUE_PREFIXES = ["admin","dev","test","stage","mail","api","prod","uat","preprod","staging"]
resolver = aiodns.DNSResolver(timeout=4)

# ===== small retry helper =====
async def retry_coro(coro, *args, retries=3, delay=0.4, backoff=2, **kwargs):
    exc = None
    for attempt in range(retries):
        try:
            return await coro(*args, **kwargs)
        except Exception as e:
            exc = e
            await asyncio.sleep(delay * (backoff ** attempt))
    raise exc

# ===== DNS resolve with fallback and caching (A + CNAME) =====
_dns_cache = {}

async def resolve(domain):
    domain = domain.strip().rstrip(".")

    if domain in _dns_cache:
        return _dns_cache[domain]

    # -------------------------
    # PRIMARY: aiodns
    # -------------------------
    try:
        res = await retry_coro(resolver.query_dns, domain, "A", retries=2)

        if res:
            ip = res[0].host if hasattr(res[0], "host") else res[0]
            _dns_cache[domain] = ip
            return ip

    except Exception:
        pass

    # -------------------------
    # FALLBACK: socket
    # -------------------------
    loop = asyncio.get_running_loop()

    try:
        def fallback():
            return socket.getaddrinfo(domain, None, socket.AF_INET)[0][4][0]

        ip = await loop.run_in_executor(None, fallback)
        _dns_cache[domain] = ip
        return ip

    except Exception:
        _dns_cache[domain] = None
        return None
# ===== shared HTTP client with semaphore =====
class HTTPClient:
    def __init__(self, max_connections=200):
        self._session = None
        self._sem = asyncio.Semaphore(max_connections)
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30)
        self._session = aiohttp.ClientSession(timeout=timeout)
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self._session.close()
    async def get_json(self, url, headers=None, timeout=12):
        async with self._sem:
            async with self._session.get(url, headers=headers or {}, timeout=timeout) as r:
                if r.status == 200:
                    return await r.json(content_type=None)
                if r.status in (429, 503):
                    raise Exception(f"Rate limited: {r.status}")
                return None
    async def get_text(self, url, headers=None, timeout=12):
        async with self._sem:
            async with self._session.get(url, headers=headers or {"User-Agent":"Mozilla/5.0"}, timeout=timeout) as r:
                if r.status == 200:
                    return await r.text()
                if r.status in (429, 503):
                    raise Exception(f"Rate limited: {r.status}")
                return None
    async def head(self, url, headers=None, timeout=6):
        async with self._sem:
            try:
                async with self._session.head(url, headers=headers or {"User-Agent":"Mozilla/5.0"}, timeout=timeout, allow_redirects=True) as r:
                    return r.status, r.headers
            except Exception:
                raise

# ===== passive sources: crt.sh, certspotter, bufferover, rapiddns, wayback, google (best-effort) =====
async def fetch_crtsh(client: HTTPClient, root):
    try:
        q = urllib.parse.quote(f"%25.{root}")
        url = f"https://crt.sh/?q={q}&output=json"
        data = await retry_coro(client.get_json, url, retries=2)
        subs = set()
        if not data:
            return []
        for item in data:
            nv = item.get("name_value") or item.get("common_name") or ""
            for line in str(nv).splitlines():
                line = line.strip()
                if line and line.endswith(root):
                    line = line.lstrip("*.")
                    subs.add(line)
        return list(subs)
    except Exception:
        return []

async def fetch_certspotter(client: HTTPClient, root):
    """
    CertSpotter supports public queries, and also supports API keys for higher rate limits/privileged endpoints.
    If CERTSPOTTER_API is set, this function will include it as a Bearer token.
    """
    subs = set()
    try:
        base = f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(root)}&include_subdomains=true&expand=dns_names"
        headers = {}
        if CERTSPOTTER_API:
            # prefer Authorization header when token present
            headers["Authorization"] = f"Bearer {CERTSPOTTER_API}"
        page = base
        while page:
            data = await retry_coro(client.get_json, page, headers=headers, retries=2)
            if not data:
                break
            for entry in data:
                for dns in entry.get("dns_names", []):
                    if dns.endswith(root):
                        subs.add(dns.lstrip("*."))
            # CertSpotter may use Link headers for pagination; for now break to avoid infinite loops
            break
        return list(subs)
    except Exception:
        return []

async def fetch_bufferover(client: HTTPClient, root):
    try:
        url = f"https://dns.bufferover.run/dns?q={urllib.parse.quote(root)}"
        data = await retry_coro(client.get_json, url, retries=2)
        subs = set()
        if not data:
            return []
        for key in ("FDNS_A", "FDNS_CNAME", "RDNS", "ASN"):
            arr = data.get(key) or []
            for item in arr:
                if isinstance(item, str):
                    if "," in item:
                        _, host = item.split(",", 1)
                        host = host.strip().lstrip("*.")
                        if host.endswith(root):
                            subs.add(host)
                    else:
                        host = item.strip().lstrip("*.")
                        if host.endswith(root):
                            subs.add(host)
        return list(subs)
    except Exception:
        return []

async def fetch_rapiddns(client: HTTPClient, root):
    subs = set()
    try:
        url_api = f"https://rapiddns.io/subdomain/{urllib.parse.quote(root)}?full=1"
        text = await retry_coro(client.get_text, url_api, retries=2, delay=0.6)
        if text:
            for m in re.finditer(r"([a-z0-9A-Z\-\_\.]+\." + re.escape(root) + r")", text):
                host = m.group(1).strip().lstrip("*.")
                subs.add(host)
        return list(subs)
    except Exception:
        return []

async def fetch_wayback(client: HTTPClient, root):
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{root}/*&output=json&fl=original&collapse=urlkey"
    subs = set()
    try:
        data = await retry_coro(client.get_json, url, retries=2)
        if data:
            for row in data[1:]:
                host = urllib.parse.urlparse(row[0]).hostname
                if host and host.endswith(root):
                    subs.add(host)
    except Exception:
        pass
    return list(subs)

async def fetch_google(client: HTTPClient, root):
    query = f"site:*.{root} -www.{root}"
    url = f"https://www.google.com/search?q={urllib.parse.quote(query)}&num=100"
    subs = set()
    try:
        text = await retry_coro(client.get_text, url, retries=2)
        if text:
            for token in text.split():
                if f".{root}" in token:
                    token = token.split("/")[0]
                    if root in token:
                        subs.add(token.replace("https://", "").replace("http://", "").strip())
    except Exception:
        pass
    return list(subs)

# ===== Virustotal, SecurityTrails, Shodan, OTX wrappers (best-effort, may need API keys)
async def fetch_securitytrails(client, root):
    if not ST_API:
        return []
    url = f"https://api.securitytrails.com/v1/domain/{root}/subdomains"
    headers = {"APIKEY": ST_API}
    try:
        data = await retry_coro(client.get_json, url, headers=headers, retries=2)
        return [f"{s}.{root}" for s in data.get("subdomains", [])] if data else []
    except Exception:
        return []

async def fetch_shodan(client, root):
    if not SHODAN_API:
        return []
    url = f"https://api.shodan.io/dns/domain/{root}?key={SHODAN_API}"
    try:
        data = await retry_coro(client.get_json, url, retries=2)
        return [rec['subdomain'] + '.' + root for rec in (data.get("data", []) if data else []) if rec.get('subdomain')]
    except Exception:
        return []

async def fetch_otx(client, root):
    if not OTX_API:
        return []
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root}/passive_dns"
    headers = {"X-OTX-API-KEY": OTX_API}
    try:
        data = await retry_coro(client.get_json, url, headers=headers, retries=2)
        return [x['hostname'] for x in (data.get("passive_dns", []) if data else []) if 'hostname' in x]
    except Exception:
        return []

async def fetch_virustotal(client, root):
    """
    Uses VT_API (x-apikey header) for VirusTotal v3 subdomains endpoint and follows pagination where present.
    """
    if not VT_API:
        return []
    url = f"https://www.virustotal.com/api/v3/domains/{root}/subdomains?limit=40"
    headers = {"x-apikey": VT_API}
    subs = []
    next_url = url
    try:
        while next_url:
            data = await retry_coro(client.get_json, next_url, headers=headers, retries=2)
            if not data:
                break
            # each item id is usually 'sub.example.com'
            subs += [item.get("id") for item in data.get("data", []) if item.get("id")]
            # pagination
            next_url = None
            links = data.get("links", {})
            if isinstance(links, dict):
                next_url = links.get("next")
    except Exception:
        pass
    return subs

# ===== permutation / mutation helpers =====
SUFFIXES = ["-prod","-dev","-staging","-test","1","2","01","02"]
INFIXES = ["-","."]
def generate_mutations(label: str):
    """Yield common mutations for a label to increase hit rate"""
    yield label
    for s in SUFFIXES:
        yield f"{label}{s}"
    parts = re.split(r"[\-\.]", label)
    if len(parts) == 1 and len(label) > 3:
        for i in range(1, min(len(label), 6)):
            yield f"{label[:i]}-{label[i:]}"
    for n in ("1","2","3"):
        yield f"{label}{n}"

# ===== candidate generator (prioritized, concurrent) =====
async def stream_candidates(root, wordlist, max_words=50000):
    prefixes = HIGH_VALUE_PREFIXES + ["www","shop","cdn","static","qa","us","eu"]
    for p in prefixes:
        yield f"{p}.{root}"
    if wordlist and os.path.isfile(wordlist):
        with open(wordlist, "r", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if i >= max_words:
                    break
                w = line.strip()
                if not w:
                    continue
                for mutated in generate_mutations(w):
                    yield f"{mutated}.{root}"
                    for p in prefixes[:6]:
                        yield f"{mutated}.{p}.{root}"
                if i % 5000 == 0:
                    await asyncio.sleep(0)
    else:
        for p in ["admin","api","mail","dev","test"]:
            yield f"{p}.{root}"

# ===== writer queue (ensure flush at close) =====
class FileWriter:
    def __init__(self):
        self._queue = asyncio.Queue()
        self._task = asyncio.create_task(self._consumer())
    async def write(self, path, line):
        await self._queue.put((path, line))
    async def _consumer(self):
        while True:
            item = await self._queue.get()
            if item is None:
                break
            path, line = item
            try:
                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass
            self._queue.task_done()
    async def close(self):
        await self._queue.put(None)
        await self._task

# ===== Counter & worker (with HTTP probe option) =====
class Counter:
    def __init__(self):
        self.value = 0
        self._lock = asyncio.Lock()
    async def inc(self):
        async with self._lock:
            self.value += 1
            return self.value

async def http_probe(client: HTTPClient, host):
    urls = [f"https://{host}", f"http://{host}"]
    for url in urls:
        try:
            status, headers = await retry_coro(client.head, url, retries=1)
            async with client._session.get(url, timeout=6, headers={"User-Agent":"Mozilla/5.0"}) as resp:
                text = await resp.text()
                title_m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I|re.S)
                title = title_m.group(1).strip() if title_m else None
                clen = len(text)
                return resp.status, title, clen
        except Exception:
            continue
    return None, None, None

async def worker(queue: asyncio.Queue, found:set, new_found:set, priority_found:set, old_subs:set,
                 valid_file, priority_file, root, counter:Counter, wildcard_ips:Set[str], writer:FileWriter,
                 client: HTTPClient, do_http_probe: bool):
    while True:
        sub = await queue.get()
        if sub is None:
            queue.task_done()
            break
        try:
            sub = sub.lower().strip()
            if not sub or not sub.endswith(root):
                queue.task_done()
                continue
            ip = await resolve(sub)
            if ip and ip in wildcard_ips:
                queue.task_done()
                continue
            if ip:
                if sub not in found:
                    found.add(sub)
                    label = ""
                    if sub not in old_subs:
                        new_found.add(sub)
                        label = "[NEW]"
                    if any(sub.startswith(p+".") for p in HIGH_VALUE_PREFIXES):
                        label = "[PRIORITY]"
                        priority_found.add(sub)
                    count = await counter.inc()
                    probe_info = ""
                    if do_http_probe:
                        try:
                            status, title, clen = await http_probe(client, sub)
                            if status:
                                probe_info = f" | HTTP {status}"
                                if title:
                                    probe_info += f" | {title[:60]}"
                                probe_info += f" | {clen}b"
                        except Exception:
                            pass
                    console.print(f"[magenta][{count}] [green]{label} {sub} -> {ip}{probe_info}")
                    await writer.write(valid_file, f"{sub}\n")
                    if sub in priority_found:
                        await writer.write(priority_file, f"{sub}\n")
        except Exception:
            pass
        queue.task_done()

# ===== wildcard detection helper =====
async def detect_wildcard(root, attempts=3):
    ips = set()
    for _ in range(attempts):
        rand = f"random-{random.randint(100000,999999)}.{root}"
        ip = await resolve(rand)
        if ip:
            ips.add(ip)
    return ips

# ===== orchestration =====
async def recon(root, wordlist, threads, do_http_probe=False, max_candidates=200000):
    console.print(f"\n[cyan][+] Starting recon on {root}")
    found, new_found, priority_found = set(), set(), set()
    old_subs = set()
    old_file = f"{root}_old.txt"
    if os.path.isfile(old_file):
        old_subs = set(line.strip().lower() for line in open(old_file, encoding="utf-8"))
    all_file = f"{root.replace('.', '_')}_all_subdomains.txt"
    valid_file = f"{root.replace('.', '_')}_valid_subdomains.txt"
    priority_file = f"{root.replace('.', '_')}_priority_subdomains.txt"

    queue = asyncio.Queue(maxsize=max(threads * 20, 100))
    counter = Counter()
    writer = FileWriter()

    async with HTTPClient(max_connections=min(1000, threads*5)) as client:
        wildcard_ips = await detect_wildcard(root)
        if wildcard_ips:
            console.print(f"[yellow]Detected wildcard IP(s): {','.join(wildcard_ips)} — will ignore these.")

        tasks = [
            fetch_securitytrails(client, root),
            fetch_shodan(client, root),
            fetch_otx(client, root),
            fetch_virustotal(client, root),
            fetch_google(client, root),
            fetch_wayback(client, root),
            fetch_crtsh(client, root),
            fetch_certspotter(client, root),
            fetch_bufferover(client, root),
            fetch_rapiddns(client, root)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        api_subs = set()
        for res in results:
            if isinstance(res, Exception):
                continue
            if res:
                api_subs.update([s.lower() for s in res])

        # save initial passive results
        with open(all_file, "w", encoding="utf-8") as f:
            for s in sorted(api_subs):
                f.write(f"{s}\n")

        # seed queue with high value + API results
        for p in HIGH_VALUE_PREFIXES:
            await queue.put(f"{p}.{root}")
        for sub in api_subs:
            await queue.put(sub)

        # start producer(s)
        async def producer():
            count = 0
            async for sub in stream_candidates(root, wordlist, max_words=max_candidates):
                await queue.put(sub)
                # append to all_file (best-effort)
                try:
                    with open(all_file, "a", encoding="utf-8") as f:
                        f.write(f"{sub}\n")
                except Exception:
                    pass
                count += 1
                if count % 10000 == 0:
                    console.print(f"[blue]Producer generated {count} candidates so far...")
            return

        prod_tasks = [asyncio.create_task(producer()) for _ in range(1)]

        workers = [asyncio.create_task(worker(queue, found, new_found, priority_found, old_subs,
                                              valid_file, priority_file, root, counter, wildcard_ips, writer,
                                              client, do_http_probe)) for _ in range(threads)]

        # wait for producer to finish producing candidates
        await asyncio.gather(*prod_tasks)
        # wait until queue is drained
        await queue.join()
        # stop workers
        for _ in workers:
            await queue.put(None)
        await asyncio.gather(*workers)
    await writer.close()

    console.print(f"[bold green]✔ Recon finished for {root}. Total live: {len(found)}")
    console.print(f"[bold green]✔ All subdomains saved: {all_file}")
    console.print(f"[bold green]✔ Valid subdomains saved: {valid_file}")
    console.print(f"[bold green]✔ Priority subdomains saved: {priority_file}")
    console.print(f"[bold yellow]✔ New subdomains (not in old list): {len(new_found)}")

# ===== CLI =====
async def main():
    parser = argparse.ArgumentParser(description="Recon Plus: passive sources + HTTP probe + permutations")
    parser.add_argument("domains", help="Comma-separated domains")
    parser.add_argument("--wordlist", default=None, help="Path to custom wordlist")
    parser.add_argument("--threads", type=int, default=200, help="Number of concurrent workers")
    parser.add_argument("--http-probe", action="store_true", help="Enable fast HTTP probe (status + title)")
    parser.add_argument("--candidates", type=int, default=200000, help="Max generated candidates to try")
    args = parser.parse_args()

    # choose a sensible default wordlist if none provided
    wordlist = args.wordlist
    if not wordlist:
        for p in DEFAULT_WORDLISTS:
            if os.path.isfile(p):
                wordlist = p
                break

    if not wordlist:
        # suppressed: no wordlist provided - do not print informational message
        wordlist = None

    # domains can be comma separated
    domains = [d.strip().lower() for d in args.domains.split(",") if d.strip()]
    try:
        for d in domains:
            await recon(d, wordlist, threads=args.threads, do_http_probe=args.http_probe, max_candidates=args.candidates)
    except KeyboardInterrupt:
        console.print("[red]Interrupted by user, exiting...")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("[red]\nInterrupted by user.")

