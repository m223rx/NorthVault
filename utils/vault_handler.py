import json
import os
from .encryption import encrypt_data, decrypt_data

VAULT_FILE = "vault.json.enc"


def load_vault(key: str) -> list:
    if not os.path.exists(VAULT_FILE):
        return []

    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()
        decrypted_data = decrypt_data(encrypted, key)
        return json.loads(decrypted_data.decode())
    except Exception as e:
        print(f"Error loading vault: {e}")
        return []


def save_vault(vault: list, key: str) -> None:
    try:
        data = json.dumps(vault, indent=4).encode()
        encrypted = encrypt_data(data, key)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)
    except Exception as e:
        print(f"Error saving vault: {e}")


def add_entry(entry: dict, key: str) -> None:
    vault = load_vault(key)
    vault.append(entry)
    save_vault(vault, key)


def update_entry(entry_id: str, new_entry: dict, key: str) -> None:
    vault = load_vault(key)
    found = False
    for i, entry in enumerate(vault):
        if entry["id"] == entry_id:
            vault[i] = new_entry
            found = True
            break
    if found:
        save_vault(vault, key)
        print("Entry updated successfully.")
    else:
        print("No entry found with that ID.")


def delete_entry(entry_id: str, key: str) -> None:
    vault = load_vault(key)
    updated_vault = [entry for entry in vault if entry["id"] != entry_id]
    if len(updated_vault) == len(vault):
        print("No entry found with that ID.")
        return
    save_vault(updated_vault, key)
    print("Entry deleted successfully.")
