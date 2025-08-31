# test_mongo.py (fixed)
import os
from pymongo import MongoClient
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

uri = os.environ.get("MONGODB_URI")
if not uri:
    raise SystemExit("MONGODB_URI not set")

client = MongoClient(uri)

db = client.get_default_database()
if db is None:                # <-- explicit None check instead of "or"
    db = client["am2spot"]    # fallback DB name

print("Count before:", db.health.count_documents({}))
db.health.insert_one({"ok": True})
print("Count after :", db.health.count_documents({}))
