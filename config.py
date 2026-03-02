import os

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_KEY", "")
HIBP_KEY = os.getenv("HIBP_KEY", "")
NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")
IPINFO_KEY = os.getenv("IPINFO_KEY", "")

REQUEST_TIMEOUT = 10
CACHE_TTL_HOURS = 24
USER_AGENT = "GRAVITAS/1.0 (OSINT Research Tool)"
