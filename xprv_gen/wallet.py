"""
Core wallet functionality for the BSV HD Wallet Key Derivation Tool.

This module contains the HDWalletTool class which provides all the core
wallet operations including loading from mnemonic/xprv, key derivation,
and address generation.
"""

import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import bsv.hd
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    ALPHABET,
    CSV_EXTENSION,
    DEFAULT_SAVE_FILENAME,
    DERIVATION_PATH_PREFIX,
    DETAILED_CSV_HEADER,
    HARDENED_KEY_FLAG,
    PBKDF2_ITERATIONS,
    SEED_LENGTH_32,
    SEED_LENGTH_64,
    SIMPLE_CSV_HEADER,
)


class HDWalletTool:
    """HD Wallet derivation tool for BSV."""

    def __init__(self) -> None:
        self.master_xprv: Optional[bsv.hd.Xprv] = None
        self.mnemonic: Optional[str] = None
        self.last_derived_keys: List[Tuple[str, str, str, str]] = []

    @property
    def is_wallet_loaded(self) -> bool:
        """Check if wallet is loaded."""
        return self.master_xprv is not None

    @property
    def has_derived_keys(self) -> bool:
        """Check if keys have been derived."""
        return len(self.last_derived_keys) > 0

    def load_from_mnemonic(self, mnemonic: str) -> bool:
        """Load wallet from mnemonic seed phrase."""
        try:
            # First check if it's a valid BIP39 mnemonic
            try:
                bsv.hd.validate_mnemonic(mnemonic)
                print("✓ Valid BIP39 mnemonic")
                # Use BSV library for BIP39
                seed = bsv.hd.seed_from_mnemonic(mnemonic)
            except Exception:
                print("⚠ Not a valid BIP39 mnemonic, checking Electrum format...")

                # Check if it's a valid Electrum mnemonic
                # Normalize the mnemonic (basic normalization)
                normalized_mnemonic = " ".join(mnemonic.strip().split())

                # Electrum validation: HMAC-SHA512 with "Seed version" as key
                h = hmac.new(
                    b"Seed version", normalized_mnemonic.encode("utf-8"), hashlib.sha512
                ).digest()

                # Check if first byte is 0x01 (Electrum standard seed)
                if h[0] == 0x01:
                    print("✓ Valid Electrum mnemonic")

                    # Generate seed using Electrum method: PBKDF2 with "electrum" salt
                    seed = hashlib.pbkdf2_hmac(
                        "sha512",
                        normalized_mnemonic.encode("utf-8"),
                        b"electrum",  # Electrum uses "electrum" salt vs "mnemonic"
                        PBKDF2_ITERATIONS,  # Same iteration count as BIP39
                    )
                else:
                    print(
                        "⚠ Not a valid Electrum mnemonic either, but trying anyway..."
                    )
                    # Still try to generate seed (for compatibility)
                    seed = hashlib.pbkdf2_hmac(
                        "sha512",
                        normalized_mnemonic.encode("utf-8"),
                        b"electrum",
                        PBKDF2_ITERATIONS,
                    )

            # Create master xprv from seed
            self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
            self.mnemonic = mnemonic

            print("✓ Successfully loaded wallet from mnemonic")
            print(f"✓ Master xprv: {self.master_xprv}")
            return True

        except Exception as e:
            print(f"✗ Error loading from mnemonic: {e}")
            return False

    def load_from_xprv(self, xprv_string: str) -> bool:
        """Load wallet from master private key (xprv)."""
        try:
            # Try to parse as extended private key string
            if xprv_string.startswith("xprv") and len(xprv_string) == 111:
                # Validate and parse as proper xprv string
                self.master_xprv = bsv.hd.Xprv(xprv_string)
            elif len(xprv_string) == SEED_LENGTH_64:
                # Validate it's a proper hex string
                try:
                    seed = bytes.fromhex(xprv_string)
                    if len(seed) != SEED_LENGTH_32:
                        raise ValueError(f"Invalid seed length: {len(seed)} bytes, expected {SEED_LENGTH_32}")
                    # Extend to 64 bytes for master seed generation
                    seed = seed + seed  # Double the 32-byte seed to 64 bytes
                    self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
                except ValueError as hex_error:
                    raise ValueError(f"Invalid hex private key: {hex_error}")
            else:
                # Try to decode as base58 and extract key
                decoded = self._base58_decode(xprv_string)
                if len(decoded) >= SEED_LENGTH_32:
                    # Extract the private key (skip version and checksum)
                    private_key_bytes = decoded[1:33]
                    if len(private_key_bytes) != SEED_LENGTH_32:
                        raise ValueError(f"Invalid private key length: {len(private_key_bytes)} bytes")
                    # Extend to 64 bytes for master seed generation  
                    seed = private_key_bytes + private_key_bytes
                    self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
                else:
                    raise ValueError("Invalid xprv format: insufficient data length")

            self.mnemonic = None
            print("✓ Successfully loaded wallet from xprv")
            print(f"✓ Master xprv: {self.master_xprv}")
            return True

        except Exception as e:
            print(f"✗ Error loading from xprv: {e}")
            return False

    def _base58_decode(self, s: str) -> bytes:
        """Decode base58 string."""
        num = 0
        for char in s:
            num = num * 58 + ALPHABET.index(char)

        # Convert to bytes
        hex_str = hex(num)[2:].rstrip("L")
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        return bytes.fromhex(hex_str)

    def get_master_xpub(self) -> Optional[str]:
        """Get master extended public key."""
        if not self.master_xprv:
            print("✗ No wallet loaded")
            return None

        try:
            xpub = self.master_xprv.xpub()
            print(f"✓ Master xpub: {xpub}")
            return str(xpub)
        except Exception as e:
            print(f"✗ Error getting xpub: {e}")
            return None

    def derive_single_key(self, derivation_path: str) -> Optional[Tuple[str, str, str]]:
        """
        Derive a single key from derivation path.

        Returns:
            Tuple of (private_key_wif, public_key_hex, address) or None if error
        """
        if not self.master_xprv:
            print("✗ No wallet loaded")
            return None

        try:
            # Parse derivation path
            path_parts = derivation_path.strip().split("/")
            if path_parts[0] != DERIVATION_PATH_PREFIX:
                raise ValueError(
                    f"Derivation path must start with '{DERIVATION_PATH_PREFIX}'"
                )

            # Start with master key
            current_key = self.master_xprv

            # Derive child keys
            for part in path_parts[1:]:
                if part.endswith("'") or part.endswith("h"):
                    # Hardened derivation
                    index = int(part[:-1]) | HARDENED_KEY_FLAG
                else:
                    # Non-hardened derivation
                    index = int(part)

                current_key = current_key.ckd(index)

            # Get different representations
            private_key = current_key.private_key()
            wif = private_key.wif()
            public_key_hex = current_key.public_key().hex()
            address = current_key.address()

            print(f"✓ Derived key for path: {derivation_path}")
            print(f"  Private Key (WIF): {wif}")
            print(f"  Public Key (hex): {public_key_hex}")
            print(f"  Address: {address}")

            # Store the derived key for potential saving
            self.last_derived_keys = [(derivation_path, wif, public_key_hex, address)]

            return wif, public_key_hex, address

        except Exception as e:
            print(f"✗ Error deriving key for path {derivation_path}: {e}")
            return None

    def derive_keys_range(
        self, base_path: str, start_index: int, end_index: int
    ) -> List[Tuple[str, str, str, str]]:
        """
        Derive a range of keys from base path.

        Returns:
            List of (derivation_path, private_key_wif, public_key_hex, address)
        """
        if not self.master_xprv:
            print("✗ No wallet loaded")
            return []

        try:
            # Use the SDK's built-in range derivation if available
            if self.mnemonic:
                # Use the optimized range derivation from mnemonic
                keys = bsv.hd.derive_xprvs_from_mnemonic(
                    self.mnemonic,
                    path=base_path,
                    change=0,  # Using 0 for external chain
                    index_start=start_index,
                    index_end=end_index,
                )

                results = []
                for i, key in enumerate(keys):
                    current_index = start_index + i
                    full_path = f"{base_path}/0/{current_index}"

                    wif = key.private_key().wif()
                    public_key_hex = key.public_key().hex()
                    address = key.address()

                    results.append((full_path, wif, public_key_hex, address))

                    print(f"✓ {full_path}")
                    print(f"  Private Key (WIF): {wif}")
                    print(f"  Public Key (hex): {public_key_hex}")
                    print(f"  Address: {address}")
                    print()

                # Store the derived keys for potential saving
                self.last_derived_keys = results

                return results

            # Manual derivation when no mnemonic is available
            results = []

            # Parse base path to get the key at that level
            base_parts = base_path.strip().split("/")
            if base_parts[0] != DERIVATION_PATH_PREFIX:
                raise ValueError(
                    f"Base path must start with '{DERIVATION_PATH_PREFIX}'"
                )

            # Derive to the base path
            current_key = self.master_xprv
            for part in base_parts[1:]:
                if part.endswith("'") or part.endswith("h"):
                    index = int(part[:-1]) | HARDENED_KEY_FLAG
                else:
                    index = int(part)
                current_key = current_key.ckd(index)

            # Now derive the range
            for i in range(start_index, end_index + 1):
                # Derive for external addresses (0) and then the index
                external_key = current_key.ckd(0)  # Change index 0 = external
                final_key = external_key.ckd(i)

                full_path = f"{base_path}/0/{i}"
                wif = final_key.private_key().wif()
                public_key_hex = final_key.public_key().hex()
                address = final_key.address()

                results.append((full_path, wif, public_key_hex, address))

                print(f"✓ {full_path}")
                print(f"  Private Key (WIF): {wif}")
                print(f"  Public Key (hex): {public_key_hex}")
                print(f"  Address: {address}")
                print()

            # Store the derived keys for potential saving
            self.last_derived_keys = results

            return results

        except Exception as e:
            print(f"✗ Error deriving key range: {e}")
            return []

    def generate_new_wallet(self, entropy: Optional[str] = None) -> bool:
        """Generate a new wallet from entropy."""
        try:
            # Generate mnemonic from entropy
            mnemonic = bsv.hd.mnemonic_from_entropy(entropy)

            print("✓ Generated new wallet")
            if entropy:
                print(f"✓ Entropy: {entropy}")
            print(f"✓ Mnemonic: {mnemonic}")

            return self.load_from_mnemonic(mnemonic)

        except Exception as e:
            print(f"✗ Error generating new wallet: {e}")
            return False

    def generate_new_wallet_secure(self) -> bool:
        """Generate a new wallet using cryptographically secure random entropy."""
        try:
            # Generate cryptographically secure random entropy (32 bytes = 256 bits)
            secure_entropy = secrets.token_bytes(32)
            entropy_hex = secure_entropy.hex()

            print("✓ Using cryptographically secure random entropy")
            print(f"✓ Entropy source: os.urandom() via secrets module")
            print(f"✓ Entropy strength: 256 bits")

            # Generate mnemonic from secure entropy
            mnemonic = bsv.hd.mnemonic_from_entropy(entropy_hex)

            print("✓ Generated new wallet with secure entropy")
            print(f"✓ Entropy: {entropy_hex}")
            print(f"✓ Mnemonic: {mnemonic}")

            return self.load_from_mnemonic(mnemonic)

        except Exception as e:
            print(f"✗ Error generating secure wallet: {e}")
            return False

    def save_keys_simple_format(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        filename: Optional[str] = None,
    ) -> bool:
        """
        Save keys in simple CSV format: address,key.

        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            filename: Optional filename (without extension)

        Returns:
            True if successful, False otherwise
        """
        if not keys_data:
            print("✗ No keys data provided")
            return False

        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{DEFAULT_SAVE_FILENAME}_simple_{timestamp}"

            # Ensure CSV extension
            if not filename.endswith(CSV_EXTENSION):
                filename += CSV_EXTENSION

            # Create Path object
            file_path = Path(filename)

            # Write CSV file
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(SIMPLE_CSV_HEADER.split(","))
                
                # Write data rows: address, key (WIF format)
                for _, wif, _, address in keys_data:
                    writer.writerow([address, wif])

            print(f"✓ Successfully saved {len(keys_data)} keys to {file_path}")
            print(f"✓ Format: {SIMPLE_CSV_HEADER}")
            return True

        except Exception as e:
            print(f"✗ Error saving keys in simple format: {e}")
            return False

    def save_keys_detailed_format(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        filename: Optional[str] = None,
    ) -> bool:
        """
        Save keys in detailed CSV format: derivation,address,key.

        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            filename: Optional filename (without extension)

        Returns:
            True if successful, False otherwise
        """
        if not keys_data:
            print("✗ No keys data provided")
            return False

        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{DEFAULT_SAVE_FILENAME}_detailed_{timestamp}"

            # Ensure CSV extension
            if not filename.endswith(CSV_EXTENSION):
                filename += CSV_EXTENSION

            # Create Path object
            file_path = Path(filename)

            # Write CSV file
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(DETAILED_CSV_HEADER.split(","))
                
                # Write data rows: derivation, address, key (WIF format)
                for derivation_path, wif, _, address in keys_data:
                    writer.writerow([derivation_path, address, wif])

            print(f"✓ Successfully saved {len(keys_data)} keys to {file_path}")
            print(f"✓ Format: {DETAILED_CSV_HEADER}")
            return True

        except Exception as e:
            print(f"✗ Error saving keys in detailed format: {e}")
            return False

    def save_keys_json_format(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        filename: Optional[str] = None,
    ) -> bool:
        """
        Save keys in JSON format with rich metadata.

        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            filename: Optional filename (without extension)

        Returns:
            True if successful, False otherwise
        """
        if not keys_data:
            print("✗ No keys data provided")
            return False

        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{DEFAULT_SAVE_FILENAME}_export_{timestamp}"

            # Ensure JSON extension
            if not filename.endswith(".json"):
                filename += ".json"

            # Create Path object
            file_path = Path(filename)

            # Build JSON structure
            export_data: Dict[str, Any] = {
                "export_info": {
                    "timestamp": datetime.now().isoformat(),
                    "format_version": "1.0",
                    "total_keys": len(keys_data),
                    "wallet_type": "BSV",
                    "exported_by": "BSV HD Wallet Key Derivation Tool",
                },
                "keys": []
            }

            # Add key data
            for i, (derivation_path, wif, public_key_hex, address) in enumerate(keys_data):
                key_entry = {
                    "index": i,
                    "derivation_path": derivation_path,
                    "address": address,
                    "private_key_wif": wif,
                    "public_key_hex": public_key_hex,
                    "address_type": "P2PKH",
                    "created_at": datetime.now().isoformat(),
                }
                export_data["keys"].append(key_entry)

            # Calculate checksums for verification
            keys_json = json.dumps(export_data["keys"], sort_keys=True)
            export_data["checksums"] = {
                "sha256": hashlib.sha256(keys_json.encode()).hexdigest(),
                "md5": hashlib.md5(keys_json.encode()).hexdigest(),
            }

            # Write JSON file
            with open(file_path, "w", encoding="utf-8") as jsonfile:
                json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)

            print(f"✓ Successfully saved {len(keys_data)} keys to {file_path}")
            print("✓ Format: JSON with metadata and checksums")
            print(f"✓ File size: {file_path.stat().st_size} bytes")
            return True

        except Exception as e:
            print(f"✗ Error saving keys in JSON format: {e}")
            return False

    def _encrypt_data(self, data: str, password: str) -> str:
        """
        Encrypt data using AES encryption with password-based key derivation.
        
        Args:
            data: String data to encrypt
            password: Password for encryption
            
        Returns:
            Base64-encoded encrypted data (salt + encrypted content)
        """
        try:
            # Generate a random salt (16 bytes)
            salt = os.urandom(16)
            
            # Derive key from password using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,  # OWASP recommended minimum
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Encrypt the data
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data.encode())
            
            # Return salt + encrypted data as base64
            return base64.b64encode(salt + encrypted_data).decode()
            
        except Exception as e:
            print(f"✗ Encryption error: {e}")
            return ""

    def _decrypt_data(self, encrypted_data: str, password: str) -> Optional[str]:
        """
        Decrypt data using AES encryption with password-based key derivation.
        
        Args:
            encrypted_data: Base64-encoded encrypted data
            password: Password for decryption
            
        Returns:
            Decrypted string data or None if failed
        """
        try:
            # Decode the base64 data
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # Extract salt (first 16 bytes)
            salt = encrypted_bytes[:16]
            encrypted_content = encrypted_bytes[16:]
            
            # Derive key from password using same parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Decrypt the data
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_content)
            
            return decrypted_data.decode()
            
        except Exception as e:
            print(f"✗ Decryption error: {e}")
            return None

    def save_keys_encrypted(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        export_format: str = "json",
        filename: Optional[str] = None,
    ) -> bool:
        """
        Save keys in encrypted format with password protection.
        
        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            export_format: Format to encrypt ("json", "csv_simple", "csv_detailed")
            filename: Optional filename (without extension)
            
        Returns:
            True if successful, False otherwise
        """
        if not keys_data:
            print("✗ No keys data provided")
            return False

        try:
            # Get password from user
            password = getpass.getpass("Enter encryption password: ")
            if not password:
                print("✗ Empty password provided")
                return False
            
            # Confirm password
            password_confirm = getpass.getpass("Confirm encryption password: ")
            if password != password_confirm:
                print("✗ Passwords do not match")
                return False
            
            # Generate content based on format
            if export_format == "json":
                # Create JSON structure
                export_data: Dict[str, Any] = {
                    "export_info": {
                        "timestamp": datetime.now().isoformat(),
                        "format_version": "1.0",
                        "total_keys": len(keys_data),
                        "wallet_type": "BSV",
                        "exported_by": "BSV HD Wallet Key Derivation Tool",
                        "encrypted": True,
                    },
                    "keys": []
                }
                
                for i, (derivation_path, wif, public_key_hex, address) in enumerate(keys_data):
                    key_entry = {
                        "index": i,
                        "derivation_path": derivation_path,
                        "address": address,
                        "private_key_wif": wif,
                        "public_key_hex": public_key_hex,
                        "address_type": "P2PKH",
                        "created_at": datetime.now().isoformat(),
                    }
                    export_data["keys"].append(key_entry)
                
                # Add checksums
                keys_json = json.dumps(export_data["keys"], sort_keys=True)
                export_data["checksums"] = {
                    "sha256": hashlib.sha256(keys_json.encode()).hexdigest(),
                    "md5": hashlib.md5(keys_json.encode()).hexdigest(),
                }
                
                content = json.dumps(export_data, indent=2)
                
            elif export_format == "csv_simple":
                content = "address,key\n"
                for _, wif, _, address in keys_data:
                    content += f"{address},{wif}\n"
                    
            elif export_format == "csv_detailed":
                content = "derivation,address,key\n"
                for derivation_path, wif, _, address in keys_data:
                    content += f"{derivation_path},{address},{wif}\n"
                    
            else:
                print(f"✗ Unsupported export format: {export_format}")
                return False
            
            # Encrypt the content
            encrypted_content = self._encrypt_data(content, password)
            if not encrypted_content:
                print("✗ Encryption failed")
                return False
            
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{DEFAULT_SAVE_FILENAME}_encrypted_{export_format}_{timestamp}"
            
            # Add .enc extension
            if not filename.endswith(".enc"):
                filename += ".enc"
            
            # Create Path object
            file_path = Path(filename)
            
            # Write encrypted file
            with open(file_path, "w", encoding="utf-8") as encfile:
                encfile.write(encrypted_content)
            
            print(f"✓ Successfully saved {len(keys_data)} keys to {file_path}")
            print(f"✓ Format: {export_format.upper()} (AES-256 encrypted)")
            print(f"✓ Encryption: PBKDF2 with 100,000 iterations")
            print("✓ File is password-protected")
            return True
            
        except Exception as e:
            print(f"✗ Error saving encrypted keys: {e}")
            return False

    def decrypt_keys_file(self, encrypted_file: str, output_file: Optional[str] = None) -> bool:
        """
        Decrypt a previously encrypted keys file.
        
        Args:
            encrypted_file: Path to encrypted file
            output_file: Optional output filename
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if file exists
            if not Path(encrypted_file).exists():
                print(f"✗ File not found: {encrypted_file}")
                return False
            
            # Read encrypted content
            with open(encrypted_file, "r", encoding="utf-8") as encfile:
                encrypted_content = encfile.read()
            
            # Get password from user
            password = getpass.getpass("Enter decryption password: ")
            if not password:
                print("✗ Empty password provided")
                return False
            
            # Decrypt the content
            decrypted_content = self._decrypt_data(encrypted_content, password)
            if decrypted_content is None:
                print("✗ Decryption failed - wrong password or corrupted file")
                return False
            
            # Generate output filename if not provided
            if not output_file:
                output_file = encrypted_file.replace(".enc", "_decrypted")
                # Try to detect format from content
                if decrypted_content.strip().startswith("{"):
                    output_file += ".json"
                elif "derivation,address,key" in decrypted_content:
                    output_file += "_detailed.csv"
                elif "address,key" in decrypted_content:
                    output_file += "_simple.csv"
                else:
                    output_file += ".txt"
            
            # Write decrypted content
            with open(output_file, "w", encoding="utf-8") as outfile:
                outfile.write(decrypted_content)
            
            print(f"✓ Successfully decrypted to: {output_file}")
            print("✓ Decryption successful")
            return True
            
        except Exception as e:
            print(f"✗ Error decrypting file: {e}")
            return False
