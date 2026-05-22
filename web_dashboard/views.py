import json

from django.core.paginator import Paginator
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.shortcuts import render

from . import services


def dashboard(request):
    data = services.dashboard_data()
    return render(
        request,
        "web_dashboard/dashboard.html",
        {
            **data,
            "device_chart_json": json.dumps(data["device_chart"]),
            "service_chart_json": json.dumps(data["service_chart"]),
        },
    )


def devices(request):
    search = request.GET.get("q", "").strip()
    sort = request.GET.get("sort", "total")
    rows = services.device_summary(search=search, sort=sort)
    return render(
        request,
        "web_dashboard/devices.html",
        {"devices": rows, "search": search, "sort": sort},
    )


def device_detail(request, ip: str):
    data = services.device_detail(ip)
    if not data["device"]["name"] and not data["recent_flows"]:
        raise Http404("Dispositivo no encontrado")
    return render(
        request,
        "web_dashboard/device_detail.html",
        {**data, "charts_json": json.dumps(data["charts"])},
    )


def traffic(request):
    filters = {
        "from_date": request.GET.get("from", "").strip(),
        "to_date": request.GET.get("to", "").strip(),
        "device": request.GET.get("device", "").strip(),
        "service": request.GET.get("service", "").strip(),
        "category": request.GET.get("category", "").strip(),
        "method": request.GET.get("method", "").strip(),
        "dst_ip": request.GET.get("dst_ip", "").strip(),
    }
    rows = services.traffic_rows(filters)
    return render(request, "web_dashboard/traffic.html", {"rows": rows, "filters": filters})


def dns(request):
    filters = {
        "q": request.GET.get("q", "").strip(),
        "device": request.GET.get("device", "").strip(),
        "device_ip": request.GET.get("device_ip", "").strip(),
        "domain": request.GET.get("domain", "").strip(),
        "clean_domain": request.GET.get("clean_domain", "").strip(),
        "category": request.GET.get("category", "").strip(),
        "service": request.GET.get("service", "").strip(),
        "date_from": request.GET.get("date_from", "").strip(),
        "date_to": request.GET.get("date_to", "").strip(),
    }
    data = services.dns_page_data(filters)
    paginator = Paginator(data["rows"], 50)
    page_obj = paginator.get_page(request.GET.get("page", "1"))
    query = request.GET.copy()
    query.pop("page", None)
    return render(
        request,
        "web_dashboard/dns.html",
        {
            **data,
            "rows": page_obj.object_list,
            "page_obj": page_obj,
            "querystring": query.urlencode(),
            "detail_json": json.dumps(data["detail"] or {}),
        },
    )


def dns_summary(request):
    filters = {
        "q": request.GET.get("q", "").strip(),
        "device": request.GET.get("device", "").strip(),
        "device_ip": request.GET.get("device_ip", "").strip(),
        "domain": request.GET.get("domain", "").strip(),
        "clean_domain": request.GET.get("clean_domain", "").strip(),
        "category": request.GET.get("category", "").strip(),
        "service": request.GET.get("service", "").strip(),
        "date_from": request.GET.get("date_from", "").strip(),
        "date_to": request.GET.get("date_to", "").strip(),
    }
    detail = services.dns_device_detail(filters)
    if not detail:
        return JsonResponse({"detail": None, "message": "No hay dispositivo seleccionado"})
    return JsonResponse(detail)


def exports(request):
    return render(
        request,
        "web_dashboard/exports.html",
        {
            "excel_exists": services.excel_path().exists(),
            "dns_available": services.table_exists("dns_queries"),
        },
    )


def download_excel(request):
    path = services.excel_path()
    if not path.exists():
        raise Http404("Excel no encontrado")
    return FileResponse(path.open("rb"), as_attachment=True, filename="reporte_trafico.xlsx")


def csv_response(filename: str, content: str) -> HttpResponse:
    response = HttpResponse(content, content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def download_devices_csv(request):
    rows = services.device_summary(sort="name")
    headers = [
        "name",
        "ip",
        "mac",
        "area",
        "sent_mb",
        "received_mb",
        "total_mb",
        "flows",
        "main_service",
        "main_domain",
        "last_activity",
    ]
    return csv_response("dispositivos.csv", services.csv_response_content(rows, headers))


def download_traffic_csv(request):
    rows = services.traffic_rows({})
    headers = ["date", "device", "src_ip", "dst_ip", "domain", "service", "category", "method", "mb", "flows"]
    return csv_response("trafico_identificado.csv", services.csv_response_content(rows, headers))


def download_dns_csv(request):
    rows, available = services.dns_rows()
    if not available:
        rows = []
    headers = ["date", "device", "ip", "domain", "clean_domain", "service", "category", "queries", "last_query"]
    return csv_response("dns_por_dispositivo.csv", services.csv_response_content(rows, headers))
