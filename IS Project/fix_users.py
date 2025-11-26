import json
import hashlib
import os

USERS_FILE = "users.json"

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Create a fresh list with only admin
users = [
    {
        "username": "admin",
        "password": hash_password("admin123"),
        "role": "admin"
    }
]

# Save to JSON (overwrite old file)
with open(USERS_FILE, "w") as f:
    json.dump(users, f, indent=4)

print("✅ users.json overwritten with default admin (admin / admin123)")
