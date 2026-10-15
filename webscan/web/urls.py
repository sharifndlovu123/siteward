from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("policy/", views.policy, name="policy"),
    path("scan/<str:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<str:scan_id>/status/", views.scan_status, name="scan_status"),
    path("scan/<str:scan_id>/export/", views.scan_export, name="scan_export"),
]
