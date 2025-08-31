# core/mongo.py
import os
from pymongo import MongoClient

_client = None  # lazy singleton

def _client_instance() -> MongoClient:
    global _client
    if _client is None:
        uri = os.environ.get("MONGODB_URI")
        if not uri:
            # Raise only when someone actually needs the DB
            raise RuntimeError("MONGO_URI is not set")
        _client = MongoClient(uri)
    return _client

def get_db():
    client = _client_instance()

    name = os.environ.get("MONGO_DB_NAME")
    if name:
        return client[name]

    try:
        db = client.get_default_database()
    except Exception:
        db = None
    return db if db is not None else client["am2spot"]

def ensure_indexes():
    db = get_db()
    try:
        db.spotify_tokens.create_index("spotify_user_id", unique=True)
        db.conversions.create_index([("created_at", 1)])
        db.unmatched.create_index([("conversion_id", 1)])
    except Exception:
        # never crash on index creation
        pass
