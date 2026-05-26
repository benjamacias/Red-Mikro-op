from django.urls import path
from django.contrib.auth import views as auth_views

from . import views


urlpatterns = [
    path("login/", auth_views.LoginView.as_view(template_name="web_dashboard/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", views.dashboard, name="dashboard"),
    path("devices/", views.devices, name="devices"),
    path("devices/<str:ip>/", views.device_detail, name="device_detail"),
    path("traffic/", views.traffic, name="traffic"),
    path("dns/", views.dns, name="dns"),
    path("dns/summary/", views.dns_summary, name="dns_summary"),
    path("exports/", views.exports, name="exports"),
    path("exports/excel/", views.download_excel, name="download_excel"),
    path("exports/devices.csv", views.download_devices_csv, name="download_devices_csv"),
    path("exports/traffic.csv", views.download_traffic_csv, name="download_traffic_csv"),
    path("exports/dns.csv", views.download_dns_csv, name="download_dns_csv"),
]
