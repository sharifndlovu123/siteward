CSP = ("default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
       "frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.get_host()  # Django validates Host lazily; do it for every request so a forged Host is always a 400
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", CSP)
        # NOT "no-referrer": that makes Chromium-based browsers send "Origin: null" on form POSTs, which fails CSRF.
        response.setdefault("Referrer-Policy", "same-origin")
        response.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        return response
