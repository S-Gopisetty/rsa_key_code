import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key_size = int(input("Enter key size (2048 or 4096): ").strip() or "2048")

private_file = (
    input("Enter private key filename (default: private_key.pem): ").strip()
    or "private_key.pem"
)
public_file = (
    input("Enter public key filename (default: public_key.pem): ").strip()
    or "public_key.pem"
)

encrypt_choice = (
    input("Do you want to encrypt the private key with a password? (yes/no): ")
    .strip()
    .lower()
)

if encrypt_choice in ("yes", "y"):
    password = input("Enter password to encrypt the private key: ").encode()
    encryption_algo = serialization.BestAvailableEncryption(password)
else:
    encryption_algo = serialization.NoEncryption()

folder_name = os.path.splitext(private_file)[0]
os.makedirs(folder_name, exist_ok=True)

private_path = os.path.join(folder_name, private_file)
public_path = os.path.join(folder_name, public_file)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=encryption_algo,
)

public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open(private_path, "wb") as f:
    f.write(private_pem)

with open(public_path, "wb") as f:
    f.write(public_pem)

print("\nRSA key pair generated successfully!")
print(f"Folder: {folder_name}/")
print(f"Key Size: {key_size}")
print(
    f"Private Key File: {private_path} ({'Encrypted' if isinstance(encryption_algo, serialization.BestAvailableEncryption) else 'Not Encrypted'})"
)
print(f"Public Key File: {public_path}")
