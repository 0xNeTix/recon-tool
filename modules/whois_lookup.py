import whois

def get_whois(domain):
    try:
        data = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": data.creation_date,
            "expiration_date": data.expiration_date,
            "name_servers": data.name_servers,
            "emails": data.emails,
        }
    except Exception as e:
        return {"error": str(e)}