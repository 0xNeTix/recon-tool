import dns.resolver

def get_dns(domain):
    result = {}
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result[record_type] = [str(r) for r in answers]
        except Exception:
            result[record_type] = []

    return result