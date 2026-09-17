#!/usr/bin/env python3
"""Minimal read-only Cloudflare R2 (S3-compatible) client using only stdlib.

Only listing and GET are implemented: the published aggregates are derived from
the private raw archive and nothing is ever written back to the bucket.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
NAMESPACE = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Config:
    account_id: str
    access_key_id: str
    secret_access_key: str
    bucket: str
    prefix: str = "raw"
    timeout_seconds: int = 60

    @classmethod
    def from_environment(cls) -> "Config":
        return cls(
            account_id=_required("R2_ACCOUNT_ID"),
            access_key_id=_required("R2_ACCESS_KEY_ID"),
            secret_access_key=_required("R2_SECRET_ACCESS_KEY"),
            bucket=_required("R2_BUCKET"),
            prefix=os.environ.get("R2_PREFIX", "raw").strip("/"),
            timeout_seconds=int(os.environ.get("R2_TIMEOUT_SECONDS", "60")),
        )


def _signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    date_key = hmac.new(("AWS4" + secret).encode(), date.encode(), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode(), hashlib.sha256).digest()
    service_key = hmac.new(region_key, service.encode(), hashlib.sha256).digest()
    return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()


def _canonical_query(parameters: dict[str, str]) -> str:
    encoded = [
        (quote(str(name), safe="-_.~"), quote(str(value), safe="-_.~"))
        for name, value in parameters.items()
    ]
    return "&".join(f"{name}={value}" for name, value in sorted(encoded))


def _signed_headers(method, url, access_key_id, secret_access_key, payload_hash, extra=None):
    parsed = urlsplit(url)
    amz_date = _now_amz()
    short_date = amz_date[:8]
    headers = {"host": parsed.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    for name, value in (extra or {}).items():
        headers[name.lower()] = " ".join(str(value).strip().split())
    names = sorted(headers)
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in names)
    canonical_request = "\n".join(
        [method, quote(parsed.path or "/", safe="/-_.~"), parsed.query,
         canonical_headers, ";".join(names), payload_hash]
    )
    scope = f"{short_date}/auto/s3/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    signature = hmac.new(
        _signing_key(secret_access_key, short_date, "auto", "s3"), string_to_sign.encode(), hashlib.sha256
    ).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope},"
        f"SignedHeaders={';'.join(names)},Signature={signature}"
    )
    return headers


def _now_amz() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class Client:
    def __init__(self, config: Config):
        self.config = config
        self.endpoint = f"https://{config.account_id}.r2.cloudflarestorage.com"

    def _url(self, key: str) -> str:
        bucket = quote(self.config.bucket, safe="-_.~")
        return f"{self.endpoint}/{bucket}/{quote(key, safe='/-_.~')}"

    def open(self, key: str):
        """Return a streaming response for one object."""
        url = self._url(key)
        request = Request(url, method="GET", headers=_signed_headers(
            "GET", url, self.config.access_key_id, self.config.secret_access_key, EMPTY_SHA256))
        return urlopen(request, timeout=self.config.timeout_seconds)

    def list_objects(self, prefix: str | None = None):
        """Yield {key, size, etag} for every object under the prefix."""
        prefix = (prefix if prefix is not None else self.config.prefix).strip("/")
        prefix = f"{prefix}/" if prefix else ""
        continuation = ""
        while True:
            query = {"list-type": "2", "prefix": prefix}
            if continuation:
                query["continuation-token"] = continuation
            url = f"{self.endpoint}/{quote(self.config.bucket, safe='-_.~')}/?{_canonical_query(query)}"
            request = Request(url, method="GET", headers=_signed_headers(
                "GET", url, self.config.access_key_id, self.config.secret_access_key, EMPTY_SHA256))
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                root = ET.fromstring(response.read())
            for content in root.findall(f"{NAMESPACE}Contents"):
                yield {
                    "key": content.findtext(f"{NAMESPACE}Key", ""),
                    "size": int(content.findtext(f"{NAMESPACE}Size", "0")),
                    "etag": (content.findtext(f"{NAMESPACE}ETag", "") or "").strip('"'),
                }
            if root.findtext(f"{NAMESPACE}IsTruncated", "false").lower() != "true":
                return
            continuation = root.findtext(f"{NAMESPACE}NextContinuationToken", "")
            if not continuation:
                raise RuntimeError("R2 returned a truncated listing without a continuation token")
