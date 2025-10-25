import json
import os
import hashlib

CONFIG_FILE = "config.json"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        return {
            "master_password": None,
            "theme": "dark",
            "version": "1.0",
            "vault_path": "vault.json.enc",
        }
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(config: dict) -> None:
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def set_master_password(password: str):
    config = load_config()
    config["master_password"] = hash_password(password)
    return save_config(config)
