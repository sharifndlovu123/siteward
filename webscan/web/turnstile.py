import httpx

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify(token, ip, secret, post=httpx.post) -> bool:
    if not token:
        return False
    try:
        response = post(VERIFY_URL, data={"secret": secret, "response": token, "remoteip": ip}, timeout=5)
        return bool(response.json().get("success"))
    except (httpx.HTTPError, ValueError):
        return False
