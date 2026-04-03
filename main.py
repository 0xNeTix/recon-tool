from modules.whois_lookup import get_whois
from modules.dns_lookup import get_dns
from modules.subdomain_enum import enumerate_subdomains
from modules.virustotal_lookup import get_virustotal
from modules.shodan_lookup import get_shodan
from modules.reporter import (
    print_whois, print_dns, print_subdomains,
    print_virustotal, print_shodan, export_json
)
from dotenv import load_dotenv
import os

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

domain = input("Entrez un domaine : ")

whois_data = get_whois(domain)
dns_data = get_dns(domain)
sub_data = enumerate_subdomains(domain)
vt_data = get_virustotal(domain, VT_API_KEY)
shodan_data = get_shodan(domain, SHODAN_API_KEY)

print_whois(whois_data)
print_dns(dns_data)
print_subdomains(sub_data)
print_virustotal(vt_data)
print_shodan(shodan_data)

export_json(domain, whois_data, dns_data, sub_data, vt_data, shodan_data)