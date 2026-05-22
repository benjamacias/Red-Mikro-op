import csv
import io
import ipaddress
import os
import re
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


MAC_RE = re.compile(r"^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$", re.IGNORECASE)
NOISY_SUMMARY_DOMAINS = {
    "1e100.net",
    "net.ar",
    "com.ar",
    "cloudfront.net",
    "amazonaws.com",
    "secureserver.net",
    "akamaiedge.net",
    "akadns.net",
    "edgesuite.net",
}


def looks_like_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def has_clear_device_name(ip: str, devices: dict[str, dict[str, str]]) -> bool:
    name = (devices.get(ip, {}).get("nombre") or "").strip()
    if not name or name.lower() in {"sin identificar", "unknown"}:
        return False
    if looks_like_ip(name) or MAC_RE.match(name):
        return False
    return True


def has_clear_domain(value: str | None) -> bool:
    domain = (value or "").strip().lower().strip(".")
    if not domain or looks_like_ip(domain):
        return False
    if domain.endswith("in-addr.arpa") or domain.endswith("ip6.arpa") or domain.endswith(".arpa"):
        return False
    if domain in {"local", "lan", "router.lan"}:
        return False
    return "." in domain


def has_clear_summary_domain(value: str | None) -> bool:
    domain = (value or "").strip().lower().strip(".")
    if not has_clear_domain(domain):
        return False
    if domain in NOISY_SUMMARY_DOMAINS:
        return False
    return True


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
    if table_exists("dns_queries"):
        columns = table_columns("dns_queries")
        if "answer_ip" in columns and "domain" in columns:
            for row in fetch_rows(
                "SELECT answer_ip AS ip, domain AS hostname FROM dns_queries WHERE answer_ip IS NOT NULL AND answer_ip != '' AND domain IS NOT NULL AND domain != ''"
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
        if not has_clear_summary_domain(domain):
            continue
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
        if not has_clear_device_name(ip, devices):
            continue
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
    date_col = (
        "date"
        if "date" in columns
        else "timestamp"
        if "timestamp" in columns
        else "received_at"
        if "received_at" in columns
        else "created_at"
        if "created_at" in columns
        else None
    )
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


def dns_schema() -> dict[str, str] | None:
    if not table_exists("dns_queries"):
        return None
    columns = table_columns("dns_queries")
    date_col = (
        "date"
        if "date" in columns
        else "timestamp"
        if "timestamp" in columns
        else "received_at"
        if "received_at" in columns
        else "created_at"
        if "created_at" in columns
        else None
    )
    ip_col = "ip" if "ip" in columns else "client_ip" if "client_ip" in columns else "src_ip" if "src_ip" in columns else None
    domain_col = "domain" if "domain" in columns else "query" if "query" in columns else "hostname" if "hostname" in columns else None
    if not ip_col or not domain_col:
        return None
    return {
        "date": date_col or "created_at",
        "ip": ip_col,
        "domain": domain_col,
        "clean_domain": "clean_domain" if "clean_domain" in columns else domain_col,
        "service": "service" if "service" in columns else "'DNS'",
        "category": "category" if "category" in columns else "'Infraestructura'",
    }


def dns_device_options() -> list[dict[str, str]]:
    devices = load_devices()
    rows = fetch_rows(
        """
        SELECT DISTINCT ip
        FROM dns_queries
        WHERE ip IS NOT NULL AND ip != ''
        ORDER BY ip
        """
    ) if table_exists("dns_queries") else []
    ips = {row["ip"] for row in rows} | set(devices)
    result = []
    for ip in sorted(ips):
        if not has_clear_device_name(ip, devices):
            continue
        result.append(
            {
                "ip": ip,
                "name": device_name(ip, devices) if ip in devices else "Sin identificar",
                "mac": devices.get(ip, {}).get("mac", ""),
                "area": devices.get(ip, {}).get("area", ""),
            }
        )
    return result


def dns_filter_sql(filters: dict[str, str], schema: dict[str, str]) -> tuple[str, list[Any]]:
    clauses = []
    params: list[Any] = []
    devices = load_devices()

    selected_ip = (filters.get("device_ip") or "").strip()
    if selected_ip:
        clauses.append(f"{schema['ip']} = ?")
        params.append(selected_ip)

    device_text = (filters.get("device") or "").strip()
    if device_text and not selected_ip:
        matching_ips = [
            ip for ip, data in devices.items()
            if device_text.lower() in " ".join([ip, data.get("nombre", ""), data.get("mac", ""), data.get("area", "")]).lower()
        ]
        if matching_ips:
            placeholders = ",".join("?" for _ in matching_ips)
            clauses.append(f"{schema['ip']} IN ({placeholders})")
            params.extend(matching_ips)
        else:
            clauses.append(f"({schema['ip']} LIKE ?)")
            params.append(f"%{device_text}%")

    q = (filters.get("q") or "").strip()
    if q:
        matching_ips = [
            ip for ip, data in devices.items()
            if q.lower() in " ".join([ip, data.get("nombre", ""), data.get("mac", ""), data.get("area", "")]).lower()
        ]
        device_clause = ""
        if matching_ips:
            placeholders = ",".join("?" for _ in matching_ips)
            device_clause = f" OR {schema['ip']} IN ({placeholders})"
        clauses.append(
            f"({schema['ip']} LIKE ? OR {schema['domain']} LIKE ? OR {schema['clean_domain']} LIKE ?{device_clause})"
        )
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
        params.extend(matching_ips)

    for key, column in [
        ("domain", schema["domain"]),
        ("clean_domain", schema["clean_domain"]),
        ("category", schema["category"]),
        ("service", schema["service"]),
    ]:
        value = (filters.get(key) or "").strip()
        if not value:
            continue
        if key in {"domain", "clean_domain"}:
            clauses.append(f"{column} LIKE ?")
            params.append(f"%{value}%")
        else:
            clauses.append(f"{column} = ?")
            params.append(value)

    if filters.get("date_from"):
        clauses.append(f"substr({schema['date']}, 1, 10) >= ?")
        params.append(filters["date_from"])
    if filters.get("date_to"):
        clauses.append(f"substr({schema['date']}, 1, 10) <= ?")
        params.append(filters["date_to"])

    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params


def selected_dns_device(filters: dict[str, str]) -> dict[str, str] | None:
    devices = load_devices()
    ip = (filters.get("device_ip") or "").strip()
    if not ip and filters.get("device"):
        needle = filters["device"].lower().strip()
        matches = [
            item_ip for item_ip, data in devices.items()
            if needle in " ".join([item_ip, data.get("nombre", ""), data.get("mac", ""), data.get("area", "")]).lower()
        ]
        if len(matches) == 1:
            ip = matches[0]
        elif needle and table_exists("dns_queries"):
            row = fetch_one("SELECT DISTINCT ip FROM dns_queries WHERE ip = ? LIMIT 1", (filters["device"],))
            ip = row["ip"] if row else ""
    if not ip:
        return None
    data = devices.get(ip, {})
    if not has_clear_device_name(ip, devices):
        return None
    hostname = data.get("active_host_name") or data.get("host_name") or data.get("comment") or ""
    return {
        "id": ip,
        "name": data.get("nombre") or "Sin identificar",
        "ip": ip,
        "mac": data.get("mac", ""),
        "hostname": hostname,
        "area": data.get("area", ""),
    }


def dns_rows_filtered(filters: dict[str, str]) -> tuple[list[dict[str, Any]], bool]:
    schema = dns_schema()
    if not schema:
        return [], False
    where, params = dns_filter_sql(filters, schema)
    rows = fetch_rows(
        f"""
        SELECT {schema['date']} AS date,
               {schema['ip']} AS ip,
               {schema['domain']} AS domain,
               {schema['clean_domain']} AS clean_domain,
               {schema['service']} AS service,
               {schema['category']} AS category,
               COUNT(*) AS queries,
               MAX({schema['date']}) AS last_query
        FROM dns_queries
        {where}
        GROUP BY {schema['ip']}, {schema['domain']}, {schema['clean_domain']}, {schema['service']}, {schema['category']}
        ORDER BY last_query DESC
        LIMIT 2000
        """,
        tuple(params),
    )
    devices = load_devices()
    result = []
    for row in rows:
        row_ip = row["ip"] or ""
        row_domain = row["clean_domain"] or clean_domain(row["domain"])
        if not has_clear_device_name(row_ip, devices):
            continue
        if not has_clear_domain(row_domain):
            continue
        result.append({
            "date": row["date"],
            "device": device_name(row_ip, devices),
            "ip": row_ip,
            "domain": row["domain"] or "",
            "clean_domain": row_domain,
            "service": row["service"] or "DNS",
            "category": row["category"] or category_for("DNS", row["domain"]),
            "queries": row["queries"],
            "last_query": row["last_query"],
        })
    return result, True


def dns_filter_choices() -> dict[str, list[str]]:
    schema = dns_schema()
    if not schema:
        return {"categories": [], "services": []}
    categories = [
        row["value"] for row in fetch_rows(
            f"SELECT DISTINCT {schema['category']} AS value FROM dns_queries WHERE {schema['category']} IS NOT NULL AND {schema['category']} != '' ORDER BY value"
        )
    ]
    services = [
        row["value"] for row in fetch_rows(
            f"SELECT DISTINCT {schema['service']} AS value FROM dns_queries WHERE {schema['service']} IS NOT NULL AND {schema['service']} != '' ORDER BY value"
        )
    ]
    return {"categories": categories, "services": services}


def dns_device_detail(filters: dict[str, str]) -> dict[str, Any] | None:
    schema = dns_schema()
    device = selected_dns_device(filters)
    if not schema or not device:
        return None

    detail_filters = {**filters, "device_ip": device["ip"], "device": ""}
    where, params = dns_filter_sql(detail_filters, schema)

    summary = fetch_one(
        f"""
        SELECT COUNT(*) AS total_queries,
               COUNT(DISTINCT {schema['clean_domain']}) AS unique_domains,
               MIN({schema['date']}) AS first_seen,
               MAX({schema['date']}) AS last_seen
        FROM dns_queries
        {where}
        """,
        tuple(params),
    )
    total_queries = summary["total_queries"] if summary else 0
    if not total_queries:
        return {
            "device": device,
            "summary": {"total_queries": 0, "unique_domains": 0, "first_seen": "", "last_seen": ""},
            "top_domains": [],
            "top_categories": [],
            "top_services": [],
            "latest_queries": [],
            "timeline": [],
            "empty_message": "No hay consultas DNS registradas para este dispositivo",
        }

    top_domains = [
        {
            "domain": row["domain"] or "",
            "clean_domain": row["clean_domain"] or clean_domain(row["domain"]),
            "queries": row["queries"],
            "last_seen": row["last_seen"],
        }
        for row in fetch_rows(
            f"""
            SELECT {schema['domain']} AS domain,
                   {schema['clean_domain']} AS clean_domain,
                   COUNT(*) AS queries,
                   MAX({schema['date']}) AS last_seen
            FROM dns_queries
            {where}
            GROUP BY {schema['domain']}, {schema['clean_domain']}
            ORDER BY queries DESC, last_seen DESC
            LIMIT 10
            """,
            tuple(params),
        )
        if has_clear_domain(row["clean_domain"] or clean_domain(row["domain"]))
    ]
    top_categories = [
        {"category": row["category"] or "Sin categoría", "queries": row["queries"]}
        for row in fetch_rows(
            f"""
            SELECT {schema['category']} AS category, COUNT(*) AS queries
            FROM dns_queries
            {where}
            GROUP BY {schema['category']}
            ORDER BY queries DESC
            LIMIT 8
            """,
            tuple(params),
        )
    ]
    top_services = [
        {"service": row["service"] or "DNS", "queries": row["queries"]}
        for row in fetch_rows(
            f"""
            SELECT {schema['service']} AS service, COUNT(*) AS queries
            FROM dns_queries
            {where}
            GROUP BY {schema['service']}
            ORDER BY queries DESC
            LIMIT 8
            """,
            tuple(params),
        )
    ]
    latest_queries = [
        {
            "date": row["date"],
            "domain_queried": row["domain"] or "",
            "clean_domain": row["clean_domain"] or clean_domain(row["domain"]),
            "service": row["service"] or "DNS",
            "category": row["category"] or category_for("DNS", row["domain"]),
        }
        for row in fetch_rows(
            f"""
            SELECT {schema['date']} AS date,
                   {schema['domain']} AS domain,
                   {schema['clean_domain']} AS clean_domain,
                   {schema['service']} AS service,
                   {schema['category']} AS category
            FROM dns_queries
            {where}
            ORDER BY {schema['date']} DESC
            LIMIT 12
            """,
            tuple(params),
        )
        if has_clear_domain(row["clean_domain"] or clean_domain(row["domain"]))
    ]
    timeline = [
        {"period": row["period"], "queries": row["queries"]}
        for row in fetch_rows(
            f"""
            SELECT substr({schema['date']}, 1, 13) || ':00' AS period,
                   COUNT(*) AS queries
            FROM dns_queries
            {where}
            GROUP BY period
            ORDER BY period DESC
            LIMIT 24
            """,
            tuple(params),
        )
    ]
    timeline.reverse()

    return {
        "device": device,
        "summary": {
            "total_queries": total_queries,
            "unique_domains": summary["unique_domains"] if summary else 0,
            "first_seen": summary["first_seen"] if summary else "",
            "last_seen": summary["last_seen"] if summary else "",
        },
        "top_domains": top_domains,
        "top_categories": top_categories,
        "top_services": top_services,
        "latest_queries": latest_queries,
        "timeline": timeline,
        "empty_message": "",
    }


def dns_page_data(filters: dict[str, str]) -> dict[str, Any]:
    rows, available = dns_rows_filtered(filters)
    choices = dns_filter_choices()
    detail = dns_device_detail(filters)
    return {
        "rows": rows,
        "available": available,
        "filters": filters,
        "detail": detail,
        "devices": dns_device_options(),
        "categories": choices["categories"],
        "services": choices["services"],
    }


def csv_response_content(rows: list[dict[str, Any]], headers: list[str]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
