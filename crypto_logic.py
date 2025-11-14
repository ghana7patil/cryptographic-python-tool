# --- crypto_logic.py ---
# This file contains all the cryptographic functions (AES, RSA, Hashing)
# It uses the 'cryptography' library.

import base64
import os
import traceback  # For detailed error logging

# --- Cryptography Imports ---
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature, InvalidTag # For decryption errors

# --- Constants ---
AES_KEY_SIZE = 32  # 32 bytes = 256 bits
AES_BLOCK_SIZE_BYTES = algorithms.AES.block_size // 8 # 16 bytes
SALT_SIZE = 16
IV_SIZE = AES_BLOCK_SIZE_BYTES
KDF_ITERATIONS = 100_000 # Recommended minimum

# ------------------------------------------------------------------
#                   HASHING FUNCTIONS
# ------------------------------------------------------------------

def hash_sha256(text: str) -> str:
    """Hashes a string using SHA-256 and returns the hex digest."""
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(text.encode('utf-8'))
        return digest.finalize().hex()
    except Exception as e:
        return f"SHA-256 Error: {e}\n{traceback.format_exc()}"

def hash_md5(text: str) -> str:
    """
    Hashes a string using MD5. 
    NOTE: MD5 is insecure for collision resistance and should only be
    used for educational/legacy purposes (e.g., checksums).
    """
    try:
        digest = hashes.Hash(hashes.MD5(), backend=default_backend())
        digest.update(text.encode('utf-8'))
        return digest.finalize().hex()
    except Exception as e:
        return f"MD5 Error: {e}\n{traceback.format_exc()}"

# ------------------------------------------------------------------
#                   SYMMETRIC (AES) FUNCTIONS
# ------------------------------------------------------------------

def get_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte (256-bit) key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_aes(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext using AES-256-GCM.
    The password is used to derive a key.
    Returns a Base64 encoded string: [salt][iv][tag][ciphertext]
    """
    try:
        # 1. Generate a random salt for the key derivation
        salt = os.urandom(SALT_SIZE)
        
        # 2. Derive the encryption key from the password and salt
        key = get_key_from_password(password, salt)
        
        # 3. Generate a random 12-byte IV (nonce) for GCM
        iv = os.urandom(12) 
        
        # 4. Encrypt using AES-GCM (provides authenticated encryption)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv), # GCM is an authenticated mode
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        
        # 5. Get the authentication tag
        tag = encryptor.tag
        
        # 6. Combine salt, iv, tag, and ciphertext, then Base64 encode
        combined_data = salt + iv + tag + ciphertext
        return base64.b64encode(combined_data).decode('utf-8')

    except Exception as e:
        return f"AES Encryption Error: {e}\n{traceback.format_exc()}"


def decrypt_aes(ciphertext_b64: str, password: str) -> str:
    """
    Decrypts a Base64 encoded AES-256-GCM string.
    Expected format: [salt (16b)][iv (12b)][tag (16b)][ciphertext]
    """
    try:
        # 1. Decode from Base64
        data = base64.b64decode(ciphertext_b64)
        
        # 2. Extract components
        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE : SALT_SIZE + 12] # GCM IV is 12 bytes
        tag = data[SALT_SIZE + 12 : SALT_SIZE + 12 + 16] # GCM tag is 16 bytes
        ciphertext = data[SALT_SIZE + 12 + 16:]
        
        # 3. Re-derive the *same* key using the extracted salt
        key = get_key_from_password(password, salt)
        
        # 4. Decrypt and verify authentication
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag), # Pass the tag for verification
            backend=default_backend()
        ).decryptor()
        
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 5. Return the decoded string
        return plaintext_bytes.decode('utf-8')
        
    except (InvalidTag, InvalidSignature):
        return "Decryption Error: Invalid password or corrupted data (authentication tag mismatch)."
    except (ValueError, TypeError, IndexError):
        return "Decryption Error: Data is corrupted or in an invalid format."
    except Exception as e:
        return f"AES Decryption Error: {e}\n{traceback.format_exc()}"

# ------------------------------------------------------------------
#                   ASYMMETRIC (RSA) FUNCTIONS
# ------------------------------------------------------------------

def generate_rsa_keys() -> tuple[str, str]:
    """
    Generates a new 2048-bit RSA key pair.
    Returns (public_key_pem, private_key_pem) as strings.
    """
    try:
        # 1. Generate the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # 2. Serialize private key to PEM format (PKCS#8)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # Not password-protected
        ).decode('utf-8')
        
        # 3. Get the corresponding public key
        public_key = private_key.public_key()
        
        # 4. Serialize public key to PEM format (SubjectPublicKeyInfo)
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return public_key_pem, private_key_pem

    except Exception as e:
        error_msg = f"RSA Key Generation Error: {e}\n{traceback.format_exc()}"
        return error_msg, error_msg


def encrypt_rsa(plaintext: str, public_key_pem: str) -> str:
    """Encrypts plaintext using an RSA public key (PEM string)."""
    try:
        # 1. Load the public key from the PEM string
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # 2. Encrypt using OAEP padding (modern standard)
        ciphertext = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 3. Return as Base64 encoded string
        return base64.b64encode(ciphertext).decode('utf-8')
        
    except ValueError:
        return "RSA Encryption Error: Plaintext is too long for this key size."
    except Exception as e:
        return f"RSA Encryption Error: Invalid public key or other issue.\n{e}\n{traceback.format_exc()}"


def decrypt_rsa(ciphertext_b64: str, private_key_pem: str) -> str:
    """Decrypts ciphertext (Base64) using an RSA private key (PEM string)."""
    try:
        # 1. Load the private key from the PEM string
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None, # Assuming key is not password-protected
            backend=default_backend()
        )
        
        # 2. Decode the Base64 ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)
        
        # 3. Decrypt using the same OAEP padding
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 4. Return as decoded string
        return plaintext_bytes.decode('utf-8')
        
    except ValueError:
        return "RSA Decryption Error: Decryption failed. This may be due to a wrong private key or corrupted data."
    except Exception as e:
        return f"RSA Decryption Error: Invalid private key or other issue.\n{e}\n{traceback.format_exc()}"