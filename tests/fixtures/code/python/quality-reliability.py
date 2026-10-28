import json

import httpx
import requests


def fetch(url, payload):
    # ruleid: py/http-no-timeout
    r = requests.get(url)
    # ruleid: py/http-no-timeout
    requests.post(
        url,
        json=payload,
    )
    # ok: py/http-no-timeout
    requests.get(url, timeout=(3, 10))
    # ok: py/http-no-timeout
    httpx.get(url)
    return r


def parse(raw):
    try:
        return json.loads(raw)
    # ruleid: py/empty-except
    except Exception:
        pass
    try:
        return json.loads(raw)
    # ruleid: py/empty-except
    except ValueError: pass
    try:
        return json.loads(raw)
    # ok: py/empty-except
    except ValueError:
        log_bad_payload(raw)
    return None


def log_bad_payload(raw):
    return raw
