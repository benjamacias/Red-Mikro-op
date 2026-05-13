import csv
import io
import ipaddress
import os
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

import tldextract


BASE_DIR = Path(__file__).resolve().parent.parent


def resolve_path(value: str, default: str) -> Path:
    path = Path(os.getenv(value, default))
    return path if path.is_absolute() else BASE_DIR / path


def db_path() -> Path:
    return resolve_path("DATABASE_PATH", "data/netflow.db")


def excel_path() -> Path:
    return resolve_path("EXCEL_PATH", "data/reporte_trafico.xlsx")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(name: str) -> bool:
    if not db_path().exists():
        return False
    with connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
            (name,),
        ).fetchone()
    return bool(row)


def table_columns(name: str) -> set[str]:
    if not table_exists(name):
        return set()
    with connect() as conn:
        return {row["name"] for row in conn.execute(f"PRAGMA table_info({name})")}


def fetch_rows(query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    if not db_path().exists():
        return []
    with connect() as conn:
        return conn.execute(query, params).fetchall()


def fetch_one(query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    if not db_path().exists():
        return None
    with connect() as conn:
        return conn.execute(query, params).fetchone()


def parse_internal_networks() -> list[ipaddress._BaseNetwork]:
    raw_value = os.getenv("INTERNAL_NETWORKS", "192.168.1.0/24")
    networks = []
    for item in raw_value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return networks or [ipaddress.ip_network("192.168.1.0/24")]


def is_internal_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address.version == network.version and address in network for network in parse_internal_networks())


def mb(value: int | float | None) -> float:
    return round(float(value or 0) / (1024 * 1024), 2)


def gb(value: int | float | None) -> float:
    return round(float(value or 0) / (1024 * 1024 * 1024), 2)


def clean_domain(hostname: str | None) -> str:
    hostname = (hostname or "").strip(". ")
    if not hostname:
        return ""
    extracted = tldextract.extract(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return hostname


def category_for(service: str | None, domain: str | None = None) -> str:
    service = (service or "").upper()
    domain = (domain or "").lower()
    if service in {"HTTP", "HTTPS"}:
        return "Web"
    if service in {"DNS", "NTP"}:
        return "Infraestructura"
    if service in {"SMTP", "SMTP TLS", "IMAPS", "POP3S"}:
        return "Correo"
    if service in {"RDP", "SSH"}:
        return "Acceso remoto"
    if any(word in domain for word in ["google", "youtube", "facebook", "instagram", "whatsapp"]):
        return "Internet"
    return "Otro"


def load_dns_names() -> dict[str, str]:
    names: dict[str, str] = {}
    if table_exists("dns_cache"):
        for row in fetch_rows("SELECT ip, hostname FROM dns_cache WHERE hostname IS NOT NULL"):
            names[row["ip"]] = row["hostname"]
    if table_exists("dns_resolution_cache"):
        columns = table_columns("dns_resolution_cache")
        ip_col = "ip" if "ip" in columns else "address" if "address" in columns else None
        host_col = "hostname" if "hostname" in columns else "domain" if "domain" in columns else None
        if ip_col and host_col:
            for row in fetch_rows(
                f"SELECT {ip_col} AS ip, {host_col} AS hostname FROM dns_resolution_cache WHERE {host_col} IS NOT NULL"
            ):
                names.setdefault(row["ip"], row["hostname"])
    return names


def load_dns_correlations() -> dict[tuple[str, str], str]:
    if not table_exists("dns_queries"):
        return {}
    columns = table_columns("dns_queries")
    client_col = "ip" if "ip" in columns else "client_ip" if "client_ip" in columns else "src_ip" if "src_ip" in columns else None
    domain_col = "domain" if "domain" in columns else "query" if "query" in columns else "hostname" if "hostname" in columns else None
    answer_col = (
        "dst_ip"
        if "dst_ip" in columns
        else "answer_ip"
        if "answer_ip" in columns
        else "resolved_ip"
        if "resolved_ip" in columns
        else "address"
        if "address" in columns
        else None
    )
    if not client_col or not domain_col or not answer_col:
        return {}
    rows = fetch_rows(
        f"""
        SELECT {client_col} AS client_ip, {answer_col} AS answer_ip, {domain_col} AS domain
        FROM dns_queries
        WHERE {answer_col} IS NOT NULL AND {domain_col} IS NOT NULL
        """
    )
    return {
        (row["client_ip"], row["answer_ip"]): row["domain"]
        for row in rows
        if row["client_ip"] and row["answer_ip"] and row["domain"]
    }


def load_devices() -> dict[str, dict[str, str]]:
    if not table_exists("devices"):
        return {}
    rows = fetch_rows(
        """
        SELECT ip, mac, nombre, comment, active_host_name, host_name,
               source, area, last_seen, updated_at
        FROM devices
        """
    )
    return {row["ip"]: {key: row[key] or "" for key in row.keys()} for row in rows}


def device_name(ip: str, devices: dict[str, dict[str, str]], dns_names: dict[str, str] | None = None) -> str:
    if ip in devices and devices[ip].get("nombre"):
        return devices[ip]["nombre"]
    if dns_names and not is_internal_ip(ip) and dns_names.get(ip):
        return dns_names[ip]
    return ip


def flow_columns() -> set[str]:
    return table_columns("flows")


def flow_name_expr(column: str, fallback_ip: str) -> str:
    columns = flow_columns()
    return column if column in columns else fallback_ip


def summary_cards() -> dict[str, Any]:
    if not table_exists("flows"):
        return {"devices": 0, "total_mb": 0, "total_gb": 0, "flows": 0, "destinations": 0}
    row = fetch_one(
        """
        SELECT COUNT(*) AS flows,
               COALESCE(SUM(bytes), 0) AS bytes,
               COUNT(DISTINCT dst_ip) AS destinations
        FROM flows
        """
    )
    devices_count = len(device_summary())
    total_bytes = row["bytes"] if row else 0
    return {
        "devices": devices_count,
        "total_mb": mb(total_bytes),
        "total_gb": gb(total_bytes),
        "flows": row["flows"] if row else 0,
        "destinations": row["destinations"] if row else 0,
    }


def top_services(limit: int = 10, ip: str | None = None) -> list[dict[str, Any]]:
    if not table_exists("flows"):
        return []
    where = ""
    params: tuple[Any, ...] = ()
    if ip:
        where = "WHERE src_ip = ? OR dst_ip = ?"
        params = (ip, ip)
    rows = fetch_rows(
        f"""
        SELECT service, COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows
        FROM flows
        {where}
        GROUP BY service
        ORDER BY bytes DESC
        LIMIT ?
        """,
        params + (limit,),
    )
    return [{"label": row["service"] or "Otro", "bytes": row["bytes"], "mb": mb(row["bytes"]), "flows": row["flows"]} for row in rows]


def top_domains(limit: int = 10, ip: str | None = None) -> list[dict[str, Any]]:
    if not table_exists("flows"):
        return []
    dns_names = load_dns_names()
    where = ""
    params: tuple[Any, ...] = ()
    if ip:
        where = "WHERE src_ip = ? OR dst_ip = ?"
        params = (ip, ip)
    rows = fetch_rows(
        f"""
        SELECT dst_ip, COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows
        FROM flows
        {where}
        GROUP BY dst_ip
        ORDER BY bytes DESC
        LIMIT 200
        """,
        params,
    )
    grouped: dict[str, dict[str, Any]] = defaultdict(lambda: {"bytes": 0, "flows": 0, "method": "IP only"})
    for row in rows:
        hostname = dns_names.get(row["dst_ip"], "")
        domain = clean_domain(hostname) or row["dst_ip"]
        method = "reverse DNS" if hostname else "IP only"
        grouped[domain]["bytes"] += row["bytes"]
        grouped[domain]["flows"] += row["flows"]
        grouped[domain]["method"] = method
    items = [
        {"domain": domain, "bytes": data["bytes"], "mb": mb(data["bytes"]), "flows": data["flows"], "method": data["method"]}
        for domain, data in grouped.items()
    ]
    return sorted(items, key=lambda item: item["bytes"], reverse=True)[:limit]


def top_destinations(ip: str, limit: int = 10) -> list[dict[str, Any]]:
    if not table_exists("flows"):
        return []
    devices = load_devices()
    dns_names = load_dns_names()
    rows = fetch_rows(
        """
        SELECT dst_ip, COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows
        FROM flows
        WHERE src_ip = ?
        GROUP BY dst_ip
        ORDER BY bytes DESC
        LIMIT ?
        """,
        (ip, limit),
    )
    return [
        {
            "ip": row["dst_ip"],
            "name": device_name(row["dst_ip"], devices, dns_names),
            "domain": clean_domain(dns_names.get(row["dst_ip"], "")),
            "mb": mb(row["bytes"]),
            "flows": row["flows"],
        }
        for row in rows
    ]


def principal_service(ip: str) -> str:
    services = top_services(1, ip)
    return services[0]["label"] if services else ""


def principal_domain(ip: str) -> str:
    domains = top_domains(1, ip)
    return domains[0]["domain"] if domains else ""


def device_summary(search: str = "", sort: str = "total") -> list[dict[str, Any]]:
    devices = load_devices()
    dns_names = load_dns_names()
    if not table_exists("flows"):
        ips = set(devices)
    else:
        flow_ips = {
            row["ip"]
            for row in fetch_rows("SELECT src_ip AS ip FROM flows UNION SELECT dst_ip AS ip FROM flows")
            if is_internal_ip(row["ip"])
        }
        ips = set(devices) | flow_ips

    rows = []
    for ip in ips:
        sent = fetch_one(
            "SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows, MAX(received_at) AS last_seen FROM flows WHERE src_ip = ?",
            (ip,),
        )
        received = fetch_one(
            "SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows, MAX(received_at) AS last_seen FROM flows WHERE dst_ip = ?",
            (ip,),
        )
        sent_bytes = sent["bytes"] if sent else 0
        received_bytes = received["bytes"] if received else 0
        last_activity = max(
            [value for value in [sent["last_seen"] if sent else None, received["last_seen"] if received else None] if value],
            default="",
        )
        item = {
            "name": device_name(ip, devices, dns_names),
            "ip": ip,
            "mac": devices.get(ip, {}).get("mac", ""),
            "area": devices.get(ip, {}).get("area", ""),
            "sent_mb": mb(sent_bytes),
            "received_mb": mb(received_bytes),
            "total_mb": mb(sent_bytes + received_bytes),
            "flows": (sent["flows"] if sent else 0) + (received["flows"] if received else 0),
            "main_service": principal_service(ip),
            "main_domain": principal_domain(ip),
            "last_activity": last_activity,
        }
        rows.append(item)

    if search:
        needle = search.lower()
        rows = [
            row for row in rows
            if needle in " ".join([row["name"], row["ip"], row["mac"], row["area"]]).lower()
        ]

    sort_key = {
        "name": lambda row: row["name"].lower(),
        "last": lambda row: row["last_activity"] or "",
        "total": lambda row: row["total_mb"],
    }.get(sort, lambda row: row["total_mb"])
    rows.sort(key=sort_key, reverse=sort != "name")
    return rows


def dashboard_data() -> dict[str, Any]:
    devices = device_summary(sort="total")[:10]
    services = top_services(10)
    domains = top_domains(10)
    return {
        "cards": summary_cards(),
        "top_devices": devices,
        "top_services": services,
        "top_domains": domains,
        "device_chart": {
            "labels": [row["name"] for row in devices],
            "data": [row["total_mb"] for row in devices],
        },
        "service_chart": {
            "labels": [row["label"] for row in services],
            "data": [row["mb"] for row in services],
        },
    }


def device_detail(ip: str) -> dict[str, Any]:
    devices = load_devices()
    dns_names = load_dns_names()
    sent = fetch_one(
        "SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows, MAX(received_at) AS last_seen FROM flows WHERE src_ip = ?",
        (ip,),
    )
    received = fetch_one(
        "SELECT COALESCE(SUM(bytes), 0) AS bytes, COUNT(*) AS flows, MAX(received_at) AS last_seen FROM flows WHERE dst_ip = ?",
        (ip,),
    )
    sent_bytes = sent["bytes"] if sent else 0
    received_bytes = received["bytes"] if received else 0
    last_activity = max(
        [value for value in [sent["last_seen"] if sent else None, received["last_seen"] if received else None] if value],
        default="",
    )
    movement_rows = recent_flows(ip=ip, limit=50)
    hourly_rows = fetch_rows(
        """
        SELECT substr(received_at, 1, 13) || ':00' AS period,
               COALESCE(SUM(bytes), 0) AS bytes
        FROM flows
        WHERE src_ip = ? OR dst_ip = ?
        GROUP BY period
        ORDER BY period DESC
        LIMIT 24
        """,
        (ip, ip),
    )
    hourly = list(reversed([{"label": row["period"], "mb": mb(row["bytes"])} for row in hourly_rows]))
    return {
        "device": {
            "name": device_name(ip, devices, dns_names),
            "ip": ip,
            "mac": devices.get(ip, {}).get("mac", ""),
            "area": devices.get(ip, {}).get("area", ""),
            "comment": devices.get(ip, {}).get("comment", ""),
            "active_host_name": devices.get(ip, {}).get("active_host_name", ""),
            "host_name": devices.get(ip, {}).get("host_name", ""),
            "sent_mb": mb(sent_bytes),
            "received_mb": mb(received_bytes),
            "total_mb": mb(sent_bytes + received_bytes),
            "last_activity": last_activity,
        },
        "services": top_services(10, ip),
        "domains": top_domains(10, ip),
        "destinations": top_destinations(ip, 10),
        "recent_flows": movement_rows,
        "charts": {
            "services": {"labels": [row["label"] for row in top_services(10, ip)], "data": [row["mb"] for row in top_services(10, ip)]},
            "domains": {"labels": [row["domain"] for row in top_domains(10, ip)], "data": [row["mb"] for row in top_domains(10, ip)]},
            "hourly": {"labels": [row["label"] for row in hourly], "data": [row["mb"] for row in hourly]},
            "sent_received": {"labels": ["Enviado", "Recibido"], "data": [mb(sent_bytes), mb(received_bytes)]},
        },
    }


def recent_flows(ip: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if not table_exists("flows"):
        return []
    devices = load_devices()
    dns_names = load_dns_names()
    dns_correlations = load_dns_correlations()
    where = ""
    params: tuple[Any, ...] = ()
    if ip:
        where = "WHERE src_ip = ? OR dst_ip = ?"
        params = (ip, ip)
    rows = fetch_rows(
        f"""
        SELECT received_at, src_ip, dst_ip, src_device_name, dst_device_name,
               service, bytes, packets, src_port, dst_port
        FROM flows
        {where}
        ORDER BY received_at DESC, id DESC
        LIMIT ?
        """,
        params + (limit,),
    )
    return [
        identified_flow_row(row, devices, dns_names, dns_correlations)
        for row in rows
    ]


def identified_flow_row(
    row: sqlite3.Row,
    devices: dict[str, dict[str, str]],
    dns_names: dict[str, str],
    dns_correlations: dict[tuple[str, str], str],
) -> dict[str, Any]:
    correlated_domain = dns_correlations.get((row["src_ip"], row["dst_ip"]), "")
    reverse_name = dns_names.get(row["dst_ip"], "")
    if correlated_domain:
        domain = clean_domain(correlated_domain)
        method = "DNS correlation"
    elif reverse_name:
        domain = clean_domain(reverse_name)
        method = "reverse DNS"
    else:
        domain = ""
        method = "IP only"
    return {
        "date": row["received_at"],
        "device": row["src_device_name"] or device_name(row["src_ip"], devices, dns_names),
        "src_ip": row["src_ip"],
        "dst_ip": row["dst_ip"],
        "dst_name": row["dst_device_name"] or device_name(row["dst_ip"], devices, dns_names),
        "domain": domain,
        "service": row["service"] or "Otro",
        "category": category_for(row["service"], domain or reverse_name),
        "method": method,
        "mb": mb(row["bytes"]),
        "flows": 1,
    }


def traffic_rows(filters: dict[str, str]) -> list[dict[str, Any]]:
    rows = recent_flows(limit=1000)
    grouped: dict[tuple[str, ...], dict[str, Any]] = {}
    for row in rows:
        if filters.get("service") and filters["service"] != row["service"]:
            continue
        if filters.get("category") and filters["category"] != row["category"]:
            continue
        if filters.get("method") and filters["method"] != row["method"]:
            continue
        if filters.get("dst_ip") and filters["dst_ip"] not in row["dst_ip"]:
            continue
        if filters.get("device") and filters["device"].lower() not in row["device"].lower():
            continue
        if filters.get("from_date") and row["date"][:10] < filters["from_date"]:
            continue
        if filters.get("to_date") and row["date"][:10] > filters["to_date"]:
            continue

        key = (
            row["date"][:16],
            row["device"],
            row["src_ip"],
            row["dst_ip"],
            row["domain"],
            row["service"],
            row["category"],
            row["method"],
        )
        if key not in grouped:
            grouped[key] = {**row, "date": row["date"][:16], "mb": 0, "flows": 0}
        grouped[key]["mb"] = round(grouped[key]["mb"] + row["mb"], 2)
        grouped[key]["flows"] += 1

    return sorted(grouped.values(), key=lambda item: item["date"], reverse=True)


def dns_rows() -> tuple[list[dict[str, Any]], bool]:
    if not table_exists("dns_queries"):
        return [], False
    columns = table_columns("dns_queries")
    date_col = "date" if "date" in columns else "timestamp" if "timestamp" in columns else "created_at" if "created_at" in columns else None
    ip_col = "ip" if "ip" in columns else "client_ip" if "client_ip" in columns else "src_ip" if "src_ip" in columns else None
    domain_col = "domain" if "domain" in columns else "query" if "query" in columns else "hostname" if "hostname" in columns else None
    if not ip_col or not domain_col:
        return [], False
    date_expr = date_col or "''"
    rows = fetch_rows(
        f"""
        SELECT {date_expr} AS date, {ip_col} AS ip, {domain_col} AS domain,
               COUNT(*) AS queries, MAX({date_expr}) AS last_query
        FROM dns_queries
        GROUP BY ip, domain
        ORDER BY last_query DESC
        LIMIT 500
        """
    )
    devices = load_devices()
    return [
        {
            "date": row["date"],
            "device": device_name(row["ip"], devices),
            "ip": row["ip"],
            "domain": row["domain"],
            "clean_domain": clean_domain(row["domain"]),
            "service": "DNS",
            "category": category_for("DNS", row["domain"]),
            "queries": row["queries"],
            "last_query": row["last_query"],
        }
        for row in rows
    ], True


def csv_response_content(rows: list[dict[str, Any]], headers: list[str]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
