# -*- coding: utf-8 -*-
"""
Build the aggregator config for this run.

- static:  subscription URLs used as-is
- github:  raw files on GitHub, used only if the file was committed within MAX_AGE_DAYS
- blogs:   daily-post sites; finds the newest post, uses it only if it is dated today
           or within MAX_AGE_DAYS (China time), and takes the subscription links from it

Usage: python subscribe/resolve_sources.py <sources.json> <base-config.json> <out.json>
"""

import datetime
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
TZ = datetime.timezone(datetime.timedelta(hours=8))
TODAY = datetime.datetime.now(TZ).date()
MAX_AGE_DAYS = int(os.environ.get("MAX_AGE_DAYS", "2"))

SUB_RE = re.compile(
    r"https?://[^\s\"'<>()\\]+?(?:\.txt|\.ya?ml|/subapi|/api/\d{6}/[A-Za-z0-9]+)(?=[^\w./-]|$)",
    re.I,
)
SKIP_RE = re.compile(r"wp-content/(themes|plugins)|robots\.txt|sitemap|llms\.txt|\.css|\.js", re.I)


def get(url: str, timeout: int = 30, headers: dict | None = None) -> str:
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        return urllib.request.urlopen(req, timeout=timeout).read().decode("utf8", "ignore")
    except Exception as e:
        print(f"  ! fetch failed {url}: {e}")
        return ""


def fresh(d: datetime.date | None) -> bool:
    return d is not None and 0 <= (TODAY - d).days <= MAX_AGE_DAYS


def date_from_text(text: str) -> datetime.date | None:
    """Find a date in a URL or title: 2026-11-12, 20261112, 2026/11/12, 2026-11-9, 11月12日, nodes1112, 261112."""
    t = text
    for pat in (r"(20\d\d)[-/_.](\d{1,2})[-/_.](\d{1,2})", r"(20\d\d)(\d\d)(\d\d)"):
        m = re.search(pat, t)
        if m:
            try:
                return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                pass
    m = re.search(r"/(2\d)(\d\d)(\d\d)/", t)
    if m:
        try:
            return datetime.date(2000 + int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    m = re.search(r"(\d{1,2})月(\d{1,2})日", t)
    if m:
        try:
            d = datetime.date(TODAY.year, int(m.group(1)), int(m.group(2)))
            if d > TODAY:
                d = d.replace(year=TODAY.year - 1)
            return d
        except ValueError:
            pass
    return None


def published(page: str) -> datetime.date | None:
    m = re.search(r"(?:article:published_time|datePublished)\"?\s*(?:content=|:)\s*\"(\d{4}-\d\d-\d\d)", page)
    if m:
        return datetime.date.fromisoformat(m.group(1))
    return None


def article_links(list_url: str, page: str, pattern: str) -> list[str]:
    out = []
    for m in re.findall(r'href=["\']([^"\'#]+)["\']', page):
        u = urllib.parse.urljoin(list_url, html.unescape(m))
        if re.search(pattern, u) and u not in out:
            out.append(u)
    return out


def resolve_blog(src: dict) -> list[str]:
    page = get(src["list"])
    links = article_links(src["list"], page, src["article"])
    if src.get("sort") == "number_desc":
        links.sort(key=lambda x: int((re.findall(r"\d+", x) or ["0"])[-1]), reverse=True)
    elif src.get("sort") == "date_desc":
        links.sort(key=lambda x: date_from_text(x) or datetime.date.min, reverse=True)
    for link in links[:4]:
        art = get(link)
        if not art:
            continue
        title = re.search(r"<title>(.*?)</title>", art, re.S)
        d = date_from_text(link) or (date_from_text(title.group(1)) if title else None) or published(art)
        if not fresh(d):
            print(f"  - skip {link} (date {d})")
            continue
        subs = []
        for u in SUB_RE.findall(art):
            u = html.unescape(u)
            if SKIP_RE.search(u) or u in subs:
                continue
            if src.get("sub_include") and not re.search(src["sub_include"], u):
                continue
            ud = date_from_text(u)
            if ud and not fresh(ud):
                continue
            subs.append(u)
        if subs:
            print(f"  + {link} (date {d}) -> {len(subs)} links")
            return subs
        print(f"  - {link} (date {d}) has no subscription links")
    return []


def github_fresh(raw_url: str) -> bool:
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(?:refs/heads/)?([^/]+)/(.+)", raw_url)
    if not m:
        return True
    owner, repo, branch, path = m.groups()
    api = f"https://api.github.com/repos/{owner}/{repo}/commits?sha={branch}&path={urllib.parse.quote(path)}&per_page=1"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = get(api, headers=headers)
    try:
        when = json.loads(data)[0]["commit"]["committer"]["date"]
        d = datetime.datetime.fromisoformat(when.replace("Z", "+00:00")).astimezone(TZ).date()
    except Exception:
        print(f"  ? cannot read commit date for {raw_url}, keep it")
        return True
    ok = fresh(d) or (TODAY - d).days <= int(os.environ.get("MAX_AGE_DAYS_GITHUB", "4"))
    print(f"  {'+' if ok else '-'} {raw_url} (updated {d})")
    return ok


def main() -> None:
    sources = json.load(open(sys.argv[1], encoding="utf8"))
    config = json.load(open(sys.argv[2], encoding="utf8"))
    out = sys.argv[3]

    picked: dict[str, list[str]] = {}
    for name, urls in sources.get("static", {}).items():
        picked[name] = urls
    for name, urls in sources.get("github", {}).items():
        print(f"[github] {name}")
        ok = [u for u in urls if github_fresh(u)]
        if ok:
            picked[name] = ok
    for src in sources.get("blogs", []):
        print(f"[blog] {src['name']}")
        try:
            urls = resolve_blog(src)
        except Exception as e:
            print(f"  ! {src['name']} failed: {e}")
            urls = []
        if urls:
            picked[src["name"]] = urls

    sites = []
    for name, urls in picked.items():
        for i, u in enumerate(urls):
            sites.append(
                {
                    "name": f"{name}{i}" if len(urls) > 1 else name,
                    "subscribe": [u],
                    "domain": "",
                    "enable": True,
                    "push_to": ["free"],
                    "check_alive": True,
                    "ignore_default_exclude": True,
                }
            )
    config["sites"] = sites
    json.dump(config, open(out, "w", encoding="utf8"), ensure_ascii=False, indent=1)
    print(f"[done] {len(picked)} sources, {len(sites)} subscription links -> {out}")


if __name__ == "__main__":
    main()
