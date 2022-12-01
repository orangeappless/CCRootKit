from cryptography.fernet import Fernet


def encrypt_data(data):
    with open("keyfile.key", "rb") as keyfile:
        key = keyfile.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    return encrypted_data


def decrypt_data(data):
    with open("keyfile.key", "rb") as keyfile:
        key = keyfile.read()
    
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(data)

    return decrypted_data
