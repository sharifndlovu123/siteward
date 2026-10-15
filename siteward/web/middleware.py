CSP = ("default-src 'self'; script-src 'self' https://challenges.cloudflare.com; "
       "frame-src https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Content-Security-Policy", CSP)
        response.setdefault("Referrer-Policy", "no-referrer")
        response.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        return response
