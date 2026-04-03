import shodan

def get_shodan(domain, api_key):
    api = shodan.Shodan(api_key)

    try:
        # Résoudre le domaine en IP d'abord
        resolved = api.dns.resolve([domain])
        ip = resolved.get(domain)

        if not ip:
            return {"error": "IP non résolue"}

        host = api.host(ip)

        return {
            "ip": ip,
            "organisation": host.get("org", "N/A"),
            "pays": host.get("country_name", "N/A"),
            "ports_ouverts": [s["port"] for s in host.get("data", [])],
        }
    except Exception as e:
        return {"error": str(e)}