import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_subdomain(sub, domain):
    target = f"{sub}.{domain}"
    try:
        dns.resolver.resolve(target, "A")
        return target
    except Exception:
        return None

def enumerate_subdomains(domain, wordlist_path="wordlists/subdomains.txt", threads=10):
    found = []

    try:
        with open(wordlist_path, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return {"error": f"Wordlist introuvable : {wordlist_path}"}

    print(f"[*] Test de {len(subdomains)} sous-domaines ({threads} threads)...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub, domain): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"  [+] Trouvé : {result}")
                found.append(result)

    return found