import os, datetime
from functools import lru_cache
from pymongo import MongoClient, ASCENDING, DESCENDING

@lru_cache(maxsize=1)
def get_db():
    uri = os.environ.get("MONGODB_URI")
    if not uri:
        raise RuntimeError("MONGODB_URI not set")
    client = MongoClient(uri)
    # If your URI includes a db name, this picks it; else choose a default:
    db = client.get_default_database() or client["am2spot"]
    return db

def ensure_indexes():
    db = get_db()
    db.conversions.create_index([("created_at", DESCENDING)])
    db.unmatched.create_index([("conversion_id", ASCENDING)])
