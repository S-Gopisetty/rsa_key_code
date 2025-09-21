#!/usr/bin/env python3
import os, sys, binascii
from getpass import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448


def read_file(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"File not found: {path}")
        sys.exit(1)


def is_private_pem_encrypted(pem_bytes: bytes) -> bool:
    header_line = pem_bytes.splitlines()[0].decode(errors="ignore") if pem_bytes else ""
    if "BEGIN ENCRYPTED PRIVATE KEY" in header_line:
        return True
    if b"Proc-Type: 4,ENCRYPTED" in pem_bytes or b"DEK-Info:" in pem_bytes:
        return True
    return False


def load_private_key_with_prompt(pem_bytes: bytes):
    try:
        key = load_pem_private_key(pem_bytes, password=None)
        return key, False
    except TypeError:
        pass_required = True
        for _ in range(3):
            pwd = getpass("Enter password for the private key: ").encode()
            try:
                key = load_pem_private_key(pem_bytes, password=pwd)
                return key, True
            except ValueError:
                print("Incorrect password. Try again.")
        print("Failed to decrypt the private key after 3 attempts.")
        sys.exit(1)
    except ValueError as e:
        print(f"Invalid private key format: {e}")
        sys.exit(1)


def key_type_name(pubkey):
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        return f"EC ({pubkey.curve.name})"
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448"
    return "Unknown"


def public_fingerprint_sha256(pubkey) -> str:
    der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    dg = hashes.Hash(hashes.SHA256())
    dg.update(der)
    return binascii.hexlify(dg.finalize()).decode()


def rsa_keysize_bits(priv_or_pub) -> int | None:
    try:
        if isinstance(priv_or_pub, rsa.RSAPrivateKey):
            return priv_or_pub.key_size
        if isinstance(priv_or_pub, rsa.RSAPublicKey):
            return priv_or_pub.key_size
    except Exception:
        pass
    return None


def public_numbers_tuple(pubkey):
    if isinstance(pubkey, rsa.RSAPublicKey):
        nums = pubkey.public_numbers()
        return ("RSA", nums.e, nums.n)
    if isinstance(pubkey, dsa.DSAPublicKey):
        nums = pubkey.public_numbers()
        params = nums.parameter_numbers
        return ("DSA", nums.y, params.p, params.q, params.g)
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        nums = pubkey.public_numbers()
        return ("EC", pubkey.curve.name, nums.x, nums.y)
    if isinstance(pubkey, ed25519.Ed25519PublicKey):
        return (
            "Ed25519",
            pubkey.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
    if isinstance(pubkey, ed448.Ed448PublicKey):
        return (
            "Ed448",
            pubkey.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
    return ("Unknown",)


def main():
    print("=== Key Pair Validator ===")
    folder = input("Folder name: ").strip()
    if not folder:
        print("Folder name is required.")
        sys.exit(1)

    priv_name = input("Private key filename (e.g., private_key.pem): ").strip()
    pub_name = input("Public key filename  (e.g., public_key.pem): ").strip()

    private_path = os.path.join(folder, priv_name)
    public_path = os.path.join(folder, pub_name)

    priv_pem = read_file(private_path)
    pub_pem = read_file(public_path)

    # Show quick encryption hint
    encrypted_hint = is_private_pem_encrypted(priv_pem)
    print(
        f"Private key appears to be: {'Encrypted' if encrypted_hint else 'Not obviously encrypted'}"
    )

    # Load private key (will prompt for password if needed)
    private_key, used_password = load_private_key_with_prompt(priv_pem)
    derived_public = private_key.public_key()

    # Load provided public key
    try:
        given_public = load_pem_public_key(pub_pem)
    except ValueError as e:
        print(f"Invalid public key format: {e}")
        sys.exit(1)

    # Compare public parts
    match = public_numbers_tuple(derived_public) == public_numbers_tuple(given_public)

    # Report details
    key_type = key_type_name(derived_public)
    key_bits = rsa_keysize_bits(derived_public) or rsa_keysize_bits(
        private_key
    )  # RSA only
    fp = public_fingerprint_sha256(derived_public)

    print("\n=== Results ===")
    print(f"Private Key: {private_path}")
    print(
        f"    - Password required: {'Yes' if used_password or encrypted_hint else 'No'}"
    )
    print(f"Public  Key: {public_path}")
    print(f"Key Type: {key_type}")
    if key_bits:
        print(f"Key Size: {key_bits} bits")
    print(f"Pair Match: {'MATCH' if match else 'MISMATCH'}")
    print(f"SHA-256 Fingerprint: {fp}")

    if match:
        print("\nValidation successful. Keys belong to the same pair.")
        sys.exit(0)
    else:
        print("\nValidation failed. Public key does not match the private key.")
        sys.exit(1)


if __name__ == "__main__":
    main()
