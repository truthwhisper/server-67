import ipaddress
import json

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver


def resolve_nameserver(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        answers = dns.resolver.resolve(value.rstrip("."), "A", lifetime=5)
        return str(answers[0])


def parse_nameserver(value):
    value = value.strip()
    port = 53
    if value.startswith("[") and "]" in value:
        host, remainder = value[1:].split("]", 1)
        if remainder:
            if not remainder.startswith(":") or not remainder[1:].isdigit():
                raise ValueError("Invalid secondary DNS port")
            port = int(remainder[1:])
    elif value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    else:
        host = value
    if not host or not 1 <= port <= 65535:
        raise ValueError("Invalid secondary DNS server")
    return resolve_nameserver(host), port


def check_secondaries(zone):
    results = []
    for server in json.loads(zone.secondary_dns or "[]"):
        try:
            address, port = parse_nameserver(server)
            query = dns.message.make_query(zone.name, dns.rdatatype.SOA)
            response = dns.query.tcp(query, address, port=port, timeout=5)
            healthy = response.rcode() == 0 and bool(response.answer)
            results.append({"server": server, "healthy": healthy, "error": ""})
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            results.append({"server": server, "healthy": False, "error": str(exc)})
    return results
