from django.conf import settings

from .settings import BASE_DIR


def theme(request):
    dashlite = BASE_DIR / "static" / "theme" / "dashlite" / "css" / "dashlite.css"
    use_dashlite = settings.THEME == "dashlite" and dashlite.exists()
    return {
        "base_template": "base_dashlite.html" if use_dashlite else "base_bootstrap.html",
        "donate_url": settings.DONATE_URL,
        "public_mode": settings.PUBLIC_MODE,
    }
