import os
import sys
import uuid
from getpass import getpass
from utils.vault_handler import load_vault, add_entry, delete_entry
from utils.password_gen import generate_password
from utils.config_handler import (
    load_config,
    save_config,
    hash_password,
    set_master_password,
)

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def init() -> bool:
    """Check if master password exists in config."""
    config = load_config()
    return bool(config.get("master_password"))

def create_user():
    clear()
    print("Create a new NorthVault user\n")

    username = input("Username --> ").strip()
    while not username:
        username = input("Username --> ").strip()

    email = input("Email address --> ").strip()
    while not email:
        email = input("Email address --> ").strip()

    master_password = getpass("Set master password --> ").strip()
    confirm_password = getpass("Confirm master password --> ").strip()

    if master_password != confirm_password:
        print("Passwords do not match. Try again.\n")
        return create_user()

    user_config = {
        "username": username,
        "user_email": email,
        "master_password": hash_password(master_password),
        "theme": "dark",
        "version": "1.0",
        "vault_path": "vault.json.enc",
    }

    save_config(user_config)
    print("User created successfully!\n")
    
def authenticate() -> str:
    config = load_config()
    saved_hash = config.get("master_password")

    while True:
        password = getpass("Enter master password --> ")
        if hash_password(password) == saved_hash:
            clear()
            print("Access granted.\n")
            return password
        print("Incorrect password.\n")
        
def show_saved(master_password: str):
    saved_passwords = load_vault(master_password)
    if not saved_passwords:
        print("No saved passwords yet.\n")
        return

    print("\nSaved Credentials:\n")
    for entry in saved_passwords:
        print(
            f"• {entry['service']} ({entry['Service username']}): {entry['password']}\n"
        )


def save_new_password(master_password: str):
    while True:
        try:
            length = int(input("Please enter password length --> "))
            if length < 6:
                print("Password too short. Try again.")
                continue
            break
        except ValueError:
            print("Please enter a valid number.")

    generated_password = generate_password(length=length)
    service = input("Password service name --> ").strip()
    username = input("Service username --> ").strip()

    entry = {
        "id": str(uuid.uuid4()),
        "service": service,
        "Service username": username,
        "password": generated_password,
    }

    add_entry(entry, master_password)
    clear()
    print("Password saved successfully!\n")


def update_password():
    config = load_config()
    saved_hash = config.get("master_password")
    password = getpass("Enter current master password --> ").strip()

    if hash_password(password) != saved_hash:
        print("Incorrect master password.\n")
        return

    new_password = getpass("Enter new master password --> ").strip()
    confirm_password = getpass("Confirm new master password --> ").strip()

    if new_password != confirm_password:
        print("Passwords do not match.\n")
        return

    set_master_password(new_password)
    clear()
    print("Master password updated successfully!\n")


def delete_password(master_password: str):
    saved_passwords = load_vault(master_password)
    if not saved_passwords:
        print("No saved passwords yet.\n")
        return

    print("\nSaved Credentials:\n")
    for entry in saved_passwords:
        print(
            f"• {entry['id']} {entry['service']} ({entry['Service username']}): {entry['password']}\n"
        )

    service_id = input("Service ID to delete --> ").strip()
    delete_entry(service_id, master_password)
    clear()
    print("Service deleted successfully!\n")
    
def main():
    northvault_art = r"""
      _   _            _   _ __      __         _ _       
     | \ | |          | | | |\ \    / /        | | |       
     |  \| | ___  _ __| |_| |_\ \  / /_ _ _   _| | |_
     | . ` |/ _ \| '__| __| '_ \ \/ / _` | | | | | __|
     | |\  | (_) | |  | |_| | | \  / (_| | |_| | | |_|
     |_| \_|\___/|_|   \__|_| |_|\/ \__,_|\__,_|_|\__|

                        Created by: m223rx
                GitHub: https://github.com/m223rx
    """
    clear()
    print(northvault_art)
    print("Welcome to NorthVault\n")

    master_password = authenticate()

    while True:
        print("Available options:")
        print("1. See all saved passwords")
        print("2. Save new password")
        print("3. Change master password")
        print("4. Delete saved password")
        print("5. Exit\n")

        choice = input("--> ").strip()

        match choice:
            case "1":
                clear()
                show_saved(master_password)
            case "2":
                clear()
                save_new_password(master_password)
            case "3":
                clear()
                update_password()
            case "4":
                clear()
                delete_password(master_password)
            case "5":
                clear()
                print("Goodbye!")
                break
            case _:
                print("Invalid choice. Please select 1-5.\n")


if __name__ == "__main__":
    if not init():
        create_user()
    main()
