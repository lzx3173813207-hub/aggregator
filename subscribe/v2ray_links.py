# -*- coding: utf-8 -*-
# Build the v2ray.txt (v2rayN / v2rayNG share links) straight from the checked
# Clash proxies instead of going through subconverter, which drops fields
# (gRPC serviceName, xhttp path/host) and keeps nodes Xray can no longer use.
#
# Dropped for v2rayNG (Xray core):
#   - any node that needs "skip certificate verification" (Xray removed
#     allowInsecure; fully disabled since 2026-08-01)
#   - Shadowsocks stream ciphers (rc4-md5, *-cfb, *-ctr ...), "none", plugins
#   - VMess with alterId > 0 (legacy MD5 auth, removed from Xray)
#   - protocols v2rayNG cannot import here: ssr, hysteria v1, anytls, tuic,
#     wireguard, http, socks, snell ...
#   - transports Xray no longer has (h2, http header obfs)

import base64
import json
import logging
from urllib.parse import quote, urlencode

logger = logging.getLogger(__name__)

SS_CIPHERS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
    "random", "randomized",
}
TRANSPORTS = {"tcp", "ws", "grpc", "xhttp", "httpupgrade"}


def _s(value) -> str:
    return "" if value is None else str(value).strip()


def _insecure(p: dict) -> bool:
    return bool(p.get("skip-cert-verify")) or bool(p.get("allow-insecure"))


def _alpn(p: dict) -> str:
    alpn = p.get("alpn")
    if isinstance(alpn, list):
        return ",".join(_s(a) for a in alpn if _s(a))
    return _s(alpn)


def _fp(p: dict) -> str:
    fp = _s(p.get("client-fingerprint")).lower()
    return fp if fp in FINGERPRINTS else ""


def _transport(p: dict) -> tuple[str, dict] | None:
    """Return (type, params) for vless/trojan, or None when unsupported."""
    net = _s(p.get("network")).lower() or "tcp"
    params: dict[str, str] = {}
    if net == "ws":
        opts = p.get("ws-opts") or {}
        path = _s(opts.get("path")) or "/"
        headers = opts.get("headers") or {}
        host = _s(headers.get("Host") or headers.get("host"))
        early = opts.get("max-early-data")
        if early and "ed=" not in path:
            path += ("&" if "?" in path else "?") + f"ed={int(early)}"
        if opts.get("v2ray-http-upgrade"):
            net = "httpupgrade"
        params.update({"path": path, "host": host})
        if net == "ws":
            params["headerType"] = "none"
    elif net == "grpc":
        opts = p.get("grpc-opts") or {}
        name = _s(opts.get("grpc-service-name"))
        if not name:
            return None
        params.update({"serviceName": name, "mode": "multi" if _s(opts.get("grpc-mode")) == "multi" else "gun"})
    elif net == "xhttp":
        opts = p.get("xhttp-opts") or {}
        params.update({"path": _s(opts.get("path")) or "/", "host": _s(opts.get("host"))})
        mode = _s(opts.get("mode"))
        if mode:
            params["mode"] = mode
    elif net == "tcp":
        params["headerType"] = "none"
    else:
        return None
    if net not in TRANSPORTS:
        return None
    return net, {k: v for k, v in params.items() if v != ""}


def _name(p: dict) -> str:
    return quote(_s(p.get("name")), safe="")


def _host(server: str) -> str:
    return f"[{server}]" if ":" in server and not server.startswith("[") else server


def _vless(p: dict) -> str | None:
    uuid, server, port = _s(p.get("uuid")), _s(p.get("server")), _s(p.get("port"))
    if not (uuid and server and port):
        return None
    t = _transport(p)
    if not t:
        return None
    net, tparams = t
    q: dict[str, str] = {"encryption": _s(p.get("encryption")) or "none"}
    reality = p.get("reality-opts")
    sni = _s(p.get("servername") or p.get("sni"))
    if reality:
        pbk = _s(reality.get("public-key"))
        if not pbk or not sni:
            return None
        q.update({"security": "reality", "sni": sni, "fp": _fp(p) or "chrome", "pbk": pbk})
        sid = _s(reality.get("short-id"))
        if sid:
            q["sid"] = sid
    elif p.get("tls"):
        q["security"] = "tls"
        if sni:
            q["sni"] = sni
        if _fp(p):
            q["fp"] = _fp(p)
        if _alpn(p):
            q["alpn"] = _alpn(p)
    else:
        q["security"] = "none"
    flow = _s(p.get("flow"))
    if flow:
        if net != "tcp" or q["security"] == "none":
            return None
        q["flow"] = flow
    q["type"] = net
    q.update(tparams)
    return f"vless://{uuid}@{_host(server)}:{port}?{urlencode(q, quote_via=quote)}#{_name(p)}"


def _trojan(p: dict) -> str | None:
    pwd, server, port = _s(p.get("password")), _s(p.get("server")), _s(p.get("port"))
    if not (pwd and server and port):
        return None
    t = _transport(p)
    if not t:
        return None
    net, tparams = t
    q: dict[str, str] = {"security": "tls"}
    sni = _s(p.get("sni") or p.get("servername"))
    if sni:
        q["sni"] = sni
    if _fp(p):
        q["fp"] = _fp(p)
    if _alpn(p):
        q["alpn"] = _alpn(p)
    if p.get("reality-opts"):
        return None
    q["type"] = net
    q.update(tparams)
    return f"trojan://{quote(pwd, safe='')}@{_host(server)}:{port}?{urlencode(q, quote_via=quote)}#{_name(p)}"


def _vmess(p: dict) -> str | None:
    uuid, server, port = _s(p.get("uuid")), _s(p.get("server")), _s(p.get("port"))
    if not (uuid and server and port):
        return None
    try:
        aid = int(p.get("alterId") or 0)
    except (TypeError, ValueError):
        return None
    if aid != 0:
        return None
    cipher = _s(p.get("cipher")).lower() or "auto"
    if cipher not in VMESS_CIPHERS:
        return None
    t = _transport(p)
    if not t:
        return None
    net, tparams = t
    data = {
        "v": "2",
        "ps": _s(p.get("name")),
        "add": server,
        "port": port,
        "id": uuid,
        "aid": "0",
        "scy": cipher,
        "net": net,
        "type": "none",
        "host": tparams.get("host", ""),
        "path": tparams.get("path", tparams.get("serviceName", "")),
        "tls": "tls" if p.get("tls") else "",
        "sni": _s(p.get("servername") or p.get("sni")) if p.get("tls") else "",
        "alpn": _alpn(p) if p.get("tls") else "",
        "fp": _fp(p) if p.get("tls") else "",
    }
    if net == "grpc":
        data["type"] = tparams.get("mode", "gun")
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return "vmess://" + base64.b64encode(raw.encode("utf8")).decode()


def _ss(p: dict) -> str | None:
    cipher, pwd = _s(p.get("cipher")).lower(), _s(p.get("password"))
    server, port = _s(p.get("server")), _s(p.get("port"))
    if not (cipher and pwd and server and port) or cipher not in SS_CIPHERS:
        return None
    if p.get("plugin") or p.get("plugin-opts"):
        return None
    if cipher.startswith("2022-"):
        userinfo = quote(cipher, safe="") + ":" + quote(pwd, safe="")
    else:
        userinfo = base64.urlsafe_b64encode(f"{cipher}:{pwd}".encode("utf8")).decode().rstrip("=")
    return f"ss://{userinfo}@{_host(server)}:{port}#{_name(p)}"


def _hysteria2(p: dict) -> str | None:
    pwd, server, port = _s(p.get("password") or p.get("auth")), _s(p.get("server")), _s(p.get("port"))
    if not (pwd and server and port):
        return None
    q: dict[str, str] = {}
    sni = _s(p.get("sni") or p.get("servername"))
    if sni:
        q["sni"] = sni
    if _alpn(p):
        q["alpn"] = _alpn(p)
    obfs = _s(p.get("obfs"))
    if obfs:
        if obfs != "salamander":
            return None
        q["obfs"] = "salamander"
        q["obfs-password"] = _s(p.get("obfs-password"))
    ports = _s(p.get("ports"))
    if ports:
        q["mport"] = ports
    query = urlencode(q, quote_via=quote)
    return f"hysteria2://{quote(pwd, safe='')}@{_host(server)}:{port}/?{query}#{_name(p)}"


BUILDERS = {
    "vless": _vless,
    "trojan": _trojan,
    "vmess": _vmess,
    "ss": _ss,
    "hysteria2": _hysteria2,
}


def build(proxies: list[dict]) -> tuple[str, dict]:
    """Return (base64 subscription, stats)."""
    lines, seen, stats = [], set(), {"kept": 0, "insecure": 0, "unsupported": 0}
    for p in proxies or []:
        if not isinstance(p, dict):
            continue
        kind = _s(p.get("type")).lower()
        builder = BUILDERS.get(kind)
        if not builder:
            stats["unsupported"] += 1
            continue
        if _insecure(p):
            stats["insecure"] += 1
            continue
        try:
            link = builder(p)
        except Exception as e:  # never let one odd node break the file
            logger.debug(f"v2ray link error: {e}")
            link = None
        if not link:
            stats["unsupported"] += 1
            continue
        key = link.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        lines.append(link)
    stats["kept"] = len(lines)
    content = base64.b64encode("\n".join(lines).encode("utf8")).decode() if lines else ""
    return content, stats
