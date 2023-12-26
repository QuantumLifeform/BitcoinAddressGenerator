from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from binascii import hexlify, unhexlify
import hashlib
import base58

def generate_keypair(private_key_hex):
    # Dodaj "0" na początku, jeśli długość nie jest parzysta
    if len(private_key_hex) % 2 != 0:
        private_key_hex = '0' + private_key_hex
    
    private_key_bytes = unhexlify(private_key_hex)
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    # Wersja nieskompresowanej klucza publicznego
    uncompressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).decode()

    # Wersja skompresowanej klucza publicznego
    compressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint)).decode()

    # Adres nieskompresowany
    uncompressed_address = generate_bitcoin_address(uncompressed_public_key)

    # Adres skompresowany
    compressed_address = generate_bitcoin_address(compressed_public_key)

    return {
        "private_key": private_key_hex,
        "uncompressed_public_key": uncompressed_public_key,
        "compressed_public_key": compressed_public_key,
        "uncompressed_address": uncompressed_address,
        "compressed_address": compressed_address
    }

def generate_bitcoin_address(public_key_hex):
    public_key_bytes = unhexlify(public_key_hex)
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    extended_hash = b"\x00" + ripemd160_hash  # Dodaj wersję 0x00 na początku
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    binary_address = extended_hash + checksum
    bitcoin_address = base58.b58encode(binary_address).decode("utf-8")
    return bitcoin_address

if __name__ == "__main__":
    start_range = input("Podaj początek zakresu kluczy prywatnych (szesnastkowo): ")
    end_range = input("Podaj koniec zakresu kluczy prywatnych (szesnastkowo): ")

    current_key = start_range
    while current_key <= end_range:
        keypair = generate_keypair(current_key)
        
        print("\nPrivate Key:", keypair["private_key"])
        print("Uncompressed Public Key:", keypair["uncompressed_public_key"])
        print("Compressed Public Key:", keypair["compressed_public_key"])
        print("Uncompressed Address:", keypair["uncompressed_address"])
        print("Compressed Address:", keypair["compressed_address"])

        # Inkrementuj klucz
        current_key = hex(int(current_key, 16) + 1)[2:]


