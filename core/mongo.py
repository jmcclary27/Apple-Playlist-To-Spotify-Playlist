# core/mongo.py
import os
from pymongo import MongoClient

_client = MongoClient(os.environ["MONGO_URI"])

def get_db():
    # Prefer explicit DB name via env
    name = os.environ.get("MONGODB_NAME")
    if name:
        return _client[name]

    # Fallback: try to read default db from URI (only works if /dbname is in the URI)
    try:
        db = _client.get_default_database()
    except Exception:
        db = None

    if db is not None:
        return db

    # Final fallback: hardcoded default
    return _client["am2spot"]


def ensure_indexes():
    db = get_db()
    try:
        db.spotify_tokens.create_index("spotify_user_id", unique=True)
        db.conversions.create_index([("created_at", 1)])
        db.unmatched.create_index([("conversion_id", 1)])
    except Exception:
        # Index creation should never crash the app
        pass
