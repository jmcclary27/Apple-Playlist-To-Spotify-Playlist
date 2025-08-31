import os, re
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

uri = os.environ.get("MONGODB_URI")
print("Got from env/.env:", bool(uri))
if not uri:
    raise SystemExit("MONGODB_URI not set")

# Mask the password so you can safely print the URI
masked = re.sub(r"(://[^:]+:)([^@]+)(@)", r"\1***\3", uri)
print("URI (masked):", masked)

# Extra sanity: show pieces so we can spot junk
from urllib.parse import urlsplit
parts = urlsplit(uri)
print("Scheme:", parts.scheme)
print("Netloc:", parts.netloc)
print("Path:", parts.path)
print("Query:", parts.query)
