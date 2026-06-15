from __future__ import annotations

import ipaddress
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import pandas as pd


FEATURE_NAMES = [
    "dots",
    "at",
    "equals",
    "slashes",
    "hyphens",
    "colons",
    "question_marks",
    "digits",
    "and",
    "underscore",
    "tilde",
    "percent",
    "lowercase",
    "uppercase",
    "upper_to_lower_ratio",
    "is_https",
    "url_length",
    "domain_length",
    "path_length",
    "path_depth",
    "query_length",
    "query_count",
    "fragment_length",
    "se_url",
    "se_domain",
    "se_path",
    "se_query",
    "se_fragment",
    "cte_domain",
    "is_domain_ip",
    "is_tld_iana_reg",
    "is_mtld",
    "subdomains",
    "special_chars",
    "digit_to_length_ratio",
    "char_to_length_ratio",
    "specialchar_to_length_ratio",
    "tld_freq",
]

DEFAULT_TLD_STATS = {"tld_freq": {}, "iana_tlds": []}
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

COMMON_MULTILEVEL_SUFFIXES = {
    "ac.id",
    "ac.in",
    "ac.jp",
    "ac.nz",
    "ac.th",
    "ac.uk",
    "ac.za",
    "co.id",
    "co.il",
    "co.in",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.th",
    "co.uk",
    "co.za",
    "com.ar",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.my",
    "com.pl",
    "com.sg",
    "com.tr",
    "com.tw",
    "com.ua",
    "com.vn",
    "edu.au",
    "edu.cn",
    "edu.hk",
    "edu.my",
    "edu.sg",
    "edu.tw",
    "go.id",
    "go.jp",
    "gov.au",
    "gov.br",
    "gov.cn",
    "gov.gr",
    "gov.hk",
    "gov.il",
    "gov.in",
    "gov.my",
    "gov.sg",
    "gov.tw",
    "gov.uk",
    "gov.za",
    "net.au",
    "net.br",
    "net.cn",
    "net.in",
    "net.nz",
    "net.uk",
    "or.id",
    "or.jp",
    "org.au",
    "org.br",
    "org.cn",
    "org.hk",
    "org.in",
    "org.nz",
    "org.sg",
    "org.uk",
    "sch.id",
    "sch.uk",
}


def load_tld_stats(stats_path: Path) -> dict:
    if not stats_path.exists():
        return DEFAULT_TLD_STATS

    with stats_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    return {
        "tld_freq": {str(k).lower(): float(v) for k, v in data.get("tld_freq", {}).items()},
        "iana_tlds": {str(t).lower() for t in data.get("iana_tlds", [])},
    }


def normalize_url(value: str) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    if SCHEME_RE.match(url):
        return url
    return f"http://{url}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 2)


def transition_entropy(value: str) -> float:
    if len(value) < 2:
        return 0.0
    pairs = [value[index : index + 2] for index in range(len(value) - 1)]
    counts = Counter(pairs)
    total = len(pairs)
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return round(entropy, 2)


def split_host_and_tld(host: str) -> tuple[list[str], str, bool]:
    if not host:
        return [], "absent", False

    labels = [label for label in host.lower().strip(".").split(".") if label]
    if not labels:
        return [], "absent", False

    tld = labels[-1]
    suffix = ".".join(labels[-2:]) if len(labels) >= 2 else tld
    is_multilevel_suffix = suffix in COMMON_MULTILEVEL_SUFFIXES
    return labels, tld, is_multilevel_suffix


def is_ip_address(host: str) -> int:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return 1
    except ValueError:
        return 0


def count_query_items(query: str) -> int:
    if not query:
        return 0
    return len([part for part in query.split("&") if part])


def extract_url_features(raw_url: str, tld_stats: dict) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    labels, tld, is_multilevel_suffix = split_host_and_tld(host)

    lowercase = sum(1 for char in url if char.islower())
    uppercase = sum(1 for char in url if char.isupper())
    digits = sum(1 for char in url if char.isdigit())

    base_counts = {
        "dots": url.count("."),
        "at": url.count("@"),
        "equals": url.count("="),
        "slashes": url.count("/"),
        "hyphens": url.count("-"),
        "colons": url.count(":"),
        "question_marks": url.count("?"),
        "digits": digits,
        "and": url.count("&"),
        "underscore": url.count("_"),
        "tilde": url.count("~"),
        "percent": url.count("%"),
        "lowercase": lowercase,
        "uppercase": uppercase,
    }

    counted_chars = sum(base_counts.values())
    url_length = len(url)
    special_chars = max(url_length - counted_chars, 0)

    registered_domain_labels = 3 if is_multilevel_suffix else 2
    subdomain_count = max(len(labels) - registered_domain_labels, 0)

    tld_freq = tld_stats.get("tld_freq", {}).get(tld, 0.0)
    iana_tlds = tld_stats.get("iana_tlds", set())

    features = {
        **base_counts,
        "upper_to_lower_ratio": round(uppercase / lowercase, 2) if lowercase else 0.0,
        "is_https": 1 if parsed.scheme.lower() == "https" else 0,
        "url_length": url_length,
        "domain_length": len(host),
        "path_length": len(parsed.path),
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "query_length": len(parsed.query),
        "query_count": count_query_items(parsed.query),
        "fragment_length": len(parsed.fragment),
        "se_url": shannon_entropy(url),
        "se_domain": shannon_entropy(host),
        "se_path": shannon_entropy(parsed.path),
        "se_query": shannon_entropy(parsed.query),
        "se_fragment": shannon_entropy(parsed.fragment),
        "cte_domain": transition_entropy(host),
        "is_domain_ip": is_ip_address(host),
        "is_tld_iana_reg": 1 if tld in iana_tlds else 0,
        "is_mtld": 1 if is_multilevel_suffix else 0,
        "subdomains": subdomain_count,
        "special_chars": special_chars,
        "digit_to_length_ratio": round(digits / url_length, 2) if url_length else 0.0,
        "char_to_length_ratio": round((lowercase + uppercase) / url_length, 2) if url_length else 0.0,
        "specialchar_to_length_ratio": round(special_chars / url_length, 2) if url_length else 0.0,
        "tld_freq": tld_freq,
    }

    return {name: float(features[name]) for name in FEATURE_NAMES}


def extract_many(urls: Iterable[str], tld_stats: dict) -> pd.DataFrame:
    rows = [extract_url_features(url, tld_stats) for url in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES).fillna(0.0)
