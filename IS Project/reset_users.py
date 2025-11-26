import json, hashlib

USERS_FILE = "users.json"

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

users = [
    {"username": "admin", "password": hash_password("admin123"), "role": "admin"},
    {"username": "guest", "password": hash_password("guest123"), "role": "user"}
]

with open(USERS_FILE, "w") as f:
    json.dump(users, f, indent=4)

print("✅ users.json reset with admin and guest")
