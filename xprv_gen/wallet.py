"""
Core wallet functionality for the BSV HD Wallet Key Derivation Tool.

This module contains the HDWalletTool class which provides all the core
wallet operations including loading from mnemonic/xprv, key derivation,
and address generation.
"""

import base64
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
    DEFAULT_SAVE_FILENAME,
    DERIVATION_PATH_PREFIX,
    DETAILED_CSV_HEADER,
    EXPORT_FORMAT_CSV_DETAILED,
    EXPORT_FORMAT_CSV_SIMPLE,
    EXPORT_FORMAT_DETAILED_CSV,
    EXPORT_FORMAT_JSON,
    EXPORT_FORMAT_SIMPLE_CSV,
    HARDENED_KEY_FLAG,
    PBKDF2_ITERATIONS,
    SEED_LENGTH_32,
    SEED_LENGTH_64,
    SIMPLE_CSV_HEADER,
    XPRV_PREFIX,
    XPRV_STRING_LENGTH,
)
from .exceptions import (
    DecryptionError,
    DerivationPathError,
    EncryptionError,
    FileOperationError,
    InvalidEntropyError,
    InvalidIndexRangeError,
    InvalidMnemonicError,
    InvalidPasswordError,
    InvalidXprvError,
    NoKeysAvailableError,
    WalletNotLoadedError,
)


class HDWalletTool:
    """HD Wallet derivation tool for BSV."""

    def __init__(self) -> None:
        self.master_xprv: Optional[bsv.hd.Xprv] = None
        self.mnemonic: Optional[str] = None

    @property
    def is_wallet_loaded(self) -> bool:
        """Check if wallet is loaded."""
        return self.master_xprv is not None

    def _load_from_bip39_mnemonic(self, mnemonic: str) -> bytes:
        """Load seed from BIP39 mnemonic."""
        bsv.hd.validate_mnemonic(mnemonic)
        return bsv.hd.seed_from_mnemonic(mnemonic)

    def _load_from_electrum_mnemonic(self, mnemonic: str) -> bytes:
        """Load seed from Electrum mnemonic."""
        # Normalize the mnemonic (basic normalization)
        normalized_mnemonic = " ".join(mnemonic.strip().split())

        # Electrum validation: HMAC-SHA512 with "Seed version" as key
        h = hmac.new(
            b"Seed version", normalized_mnemonic.encode("utf-8"), hashlib.sha512
        ).digest()

        # Check if first byte is 0x01 (Electrum standard seed)
        if h[0] != 0x01:
            raise InvalidMnemonicError("Not a valid Electrum mnemonic")

        # Generate seed using Electrum method: PBKDF2 with "electrum" salt
        return hashlib.pbkdf2_hmac(
            "sha512",
            normalized_mnemonic.encode("utf-8"),
            b"electrum",  # Electrum uses "electrum" salt vs "mnemonic"
            PBKDF2_ITERATIONS,  # Same iteration count as BIP39
        )

    def load_from_mnemonic(self, mnemonic: str) -> str:
        """Load wallet from mnemonic seed phrase.

        Returns:
            The mnemonic type that was successfully loaded (BIP39 or Electrum)
        """
        if not mnemonic or not mnemonic.strip():
            raise InvalidMnemonicError("Empty mnemonic provided")

        try:
            # First try BIP39 mnemonic
            try:
                seed = self._load_from_bip39_mnemonic(mnemonic)
                mnemonic_type = "BIP39"
            except Exception:
                # Try Electrum mnemonic
                try:
                    seed = self._load_from_electrum_mnemonic(mnemonic)
                    mnemonic_type = "Electrum"
                except Exception:
                    # Fall back to generic seed generation for compatibility
                    normalized_mnemonic = " ".join(mnemonic.strip().split())
                    seed = hashlib.pbkdf2_hmac(
                        "sha512",
                        normalized_mnemonic.encode("utf-8"),
                        b"electrum",
                        PBKDF2_ITERATIONS,
                    )
                    mnemonic_type = "Generic"

            # Create master xprv from seed
            self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
            self.mnemonic = mnemonic

            return mnemonic_type

        except Exception as e:
            raise InvalidMnemonicError(f"Error loading from mnemonic: {e}") from e

    def _load_from_xprv_string(self, xprv_string: str) -> None:
        """Load from proper xprv string format."""
        if not (
            xprv_string.startswith(XPRV_PREFIX)
            and len(xprv_string) == XPRV_STRING_LENGTH
        ):
            raise InvalidXprvError(
                f"Invalid xprv format: must start with '{XPRV_PREFIX}' "
                f"and be {XPRV_STRING_LENGTH} characters"
            )
        self.master_xprv = bsv.hd.Xprv(xprv_string)

    def _load_from_hex_seed(self, hex_string: str) -> None:
        """Load from hex seed string."""
        if len(hex_string) != SEED_LENGTH_64:
            raise InvalidXprvError(
                f"Invalid hex seed length: {len(hex_string)} characters, "
                f"expected {SEED_LENGTH_64}"
            )

        try:
            seed = bytes.fromhex(hex_string)
            if len(seed) != SEED_LENGTH_32:
                raise InvalidXprvError(
                    f"Invalid seed length: {len(seed)} bytes, "
                    f"expected {SEED_LENGTH_32}"
                )
            # Extend to 64 bytes for master seed generation
            seed = seed + seed  # Double the 32-byte seed to 64 bytes
            self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
        except ValueError as hex_error:
            raise InvalidXprvError(
                f"Invalid hex private key: {hex_error}"
            ) from hex_error

    def _load_from_base58_key(self, base58_string: str) -> None:
        """Load from base58 encoded private key."""
        try:
            decoded = self._base58_decode(base58_string)
            if len(decoded) < SEED_LENGTH_32:
                raise InvalidXprvError("Invalid xprv format: insufficient data length")

            # Extract the private key (skip version and checksum)
            private_key_bytes = decoded[1:33]
            if len(private_key_bytes) != SEED_LENGTH_32:
                raise InvalidXprvError(
                    f"Invalid private key length: {len(private_key_bytes)} bytes"
                )

            # Extend to 64 bytes for master seed generation
            seed = private_key_bytes + private_key_bytes
            self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
        except Exception as e:
            raise InvalidXprvError(f"Error decoding base58 key: {e}") from e

    def load_from_xprv(self, xprv_string: str) -> str:
        """Load wallet from master private key (xprv).

        Returns:
            The format type that was successfully loaded
        """
        if not xprv_string or not xprv_string.strip():
            raise InvalidXprvError("Empty xprv string provided")

        xprv_string = xprv_string.strip()

        try:
            # Try to parse as extended private key string
            if (
                xprv_string.startswith(XPRV_PREFIX)
                and len(xprv_string) == XPRV_STRING_LENGTH
            ):
                self._load_from_xprv_string(xprv_string)
                format_type = "Extended Private Key"
            elif len(xprv_string) == SEED_LENGTH_64:
                self._load_from_hex_seed(xprv_string)
                format_type = "Hex Seed"
            else:
                self._load_from_base58_key(xprv_string)
                format_type = "Base58 Key"

            self.mnemonic = None
            return format_type

        except Exception as e:
            raise InvalidXprvError(f"Error loading from xprv: {e}") from e

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

    def get_master_xpub(self) -> str:
        """Get master extended public key."""
        if not self.master_xprv:
            raise WalletNotLoadedError("No wallet loaded")

        try:
            xpub = self.master_xprv.xpub()
            return str(xpub)
        except Exception as e:
            raise WalletNotLoadedError(f"Error getting xpub: {e}") from e

    def derive_single_key(self, derivation_path: str) -> Tuple[str, str, str, str]:
        """
        Derive a single key from derivation path.

        Returns:
            Tuple of (derivation_path, private_key_wif, public_key_hex, address)
        """
        if not self.master_xprv:
            raise WalletNotLoadedError("No wallet loaded")

        try:
            # Parse derivation path
            path_parts = derivation_path.strip().split("/")
            if path_parts[0] != DERIVATION_PATH_PREFIX:
                raise DerivationPathError(
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

            return derivation_path, wif, public_key_hex, address

        except ValueError as e:
            raise DerivationPathError(
                f"Invalid derivation path '{derivation_path}': {e}"
            ) from e
        except Exception as e:
            raise DerivationPathError(
                f"Error deriving key for path '{derivation_path}': {e}"
            ) from e

    def _validate_index_range(self, start_index: int, end_index: int) -> None:
        """Validate index range parameters."""
        if start_index < 0 or end_index < 0 or start_index > end_index:
            raise InvalidIndexRangeError(
                f"Invalid index range: start={start_index}, end={end_index}"
            )

    def _derive_range_from_mnemonic(
        self, base_path: str, start_index: int, end_index: int
    ) -> List[Tuple[str, str, str, str]]:
        """Derive key range using mnemonic with SDK optimization."""
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

        return results

    def _derive_range_manually(
        self, base_path: str, start_index: int, end_index: int
    ) -> List[Tuple[str, str, str, str]]:
        """Derive key range manually when no mnemonic is available."""
        # Parse base path to get the key at that level
        base_parts = base_path.strip().split("/")
        if base_parts[0] != DERIVATION_PATH_PREFIX:
            raise DerivationPathError(
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
        results = []
        for i in range(start_index, end_index + 1):
            # Derive for external addresses (0) and then the index
            external_key = current_key.ckd(0)  # Change index 0 = external
            final_key = external_key.ckd(i)

            full_path = f"{base_path}/0/{i}"
            wif = final_key.private_key().wif()
            public_key_hex = final_key.public_key().hex()
            address = final_key.address()

            results.append((full_path, wif, public_key_hex, address))

        return results

    def derive_keys_range(
        self, base_path: str, start_index: int, end_index: int
    ) -> List[Tuple[str, str, str, str]]:
        """
        Derive a range of keys from base path.

        Returns:
            List of (derivation_path, private_key_wif, public_key_hex, address)
        """
        if not self.master_xprv:
            raise WalletNotLoadedError("No wallet loaded")

        self._validate_index_range(start_index, end_index)

        try:
            # Use optimized derivation if mnemonic is available
            if self.mnemonic:
                return self._derive_range_from_mnemonic(
                    base_path, start_index, end_index
                )

            return self._derive_range_manually(base_path, start_index, end_index)

        except ValueError as e:
            raise DerivationPathError(f"Invalid base path '{base_path}': {e}") from e
        except Exception as e:
            raise DerivationPathError(f"Error deriving key range: {e}") from e

    def generate_new_wallet(self, entropy: Optional[str] = None) -> Tuple[str, str]:
        """Generate a new wallet from entropy.

        Returns:
            Tuple of (mnemonic, entropy_used)
        """
        try:
            # Generate mnemonic from entropy
            mnemonic = bsv.hd.mnemonic_from_entropy(entropy)

            # Load the wallet from the generated mnemonic
            self.load_from_mnemonic(mnemonic)

            return mnemonic, entropy or "auto-generated"

        except Exception as e:
            raise InvalidEntropyError(f"Error generating new wallet: {e}") from e

    def generate_new_wallet_secure(self) -> Tuple[str, str]:
        """Generate a new wallet using cryptographically secure random entropy.

        Returns:
            Tuple of (mnemonic, entropy_hex)
        """
        try:
            # Generate cryptographically secure random entropy (32 bytes = 256 bits)
            secure_entropy = secrets.token_bytes(32)
            entropy_hex = secure_entropy.hex()

            # Generate mnemonic from secure entropy
            mnemonic = bsv.hd.mnemonic_from_entropy(entropy_hex)

            # Load the wallet from the generated mnemonic
            self.load_from_mnemonic(mnemonic)

            return mnemonic, entropy_hex

        except Exception as e:
            raise InvalidEntropyError(f"Error generating secure wallet: {e}") from e

    def _generate_simple_csv_content(
        self, keys_data: List[Tuple[str, str, str, str]]
    ) -> str:
        """Generate simple CSV content."""
        content = f"{SIMPLE_CSV_HEADER}\n"
        for _, wif, _, address in keys_data:
            content += f"{address},{wif}\n"
        return content

    def _generate_detailed_csv_content(
        self, keys_data: List[Tuple[str, str, str, str]]
    ) -> str:
        """Generate detailed CSV content."""
        content = f"{DETAILED_CSV_HEADER}\n"
        for derivation_path, wif, _, address in keys_data:
            content += f"{derivation_path},{address},{wif}\n"
        return content

    def _generate_json_content(self, keys_data: List[Tuple[str, str, str, str]]) -> str:
        """Generate JSON content with metadata."""
        export_data: Dict[str, Any] = {
            "export_info": {
                "timestamp": datetime.now().isoformat(),
                "format_version": "1.0",
                "total_keys": len(keys_data),
                "wallet_type": "BSV",
                "exported_by": "BSV HD Wallet Key Derivation Tool",
            },
            "keys": [],
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

        return json.dumps(export_data, indent=2, ensure_ascii=False)

    def save_keys(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        export_format: str,
        filename: Optional[str] = None,
    ) -> str:
        """
        Save keys in specified format.

        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            export_format: Format to save ("simple_csv", "detailed_csv", "json")
            filename: Optional filename (without extension)

        Returns:
            Path to the saved file
        """
        if not keys_data:
            raise NoKeysAvailableError("No keys data provided")

        try:
            # Generate content based on format
            if export_format == EXPORT_FORMAT_SIMPLE_CSV:
                content = self._generate_simple_csv_content(keys_data)
                extension = ".csv"
                format_suffix = "simple"
            elif export_format == EXPORT_FORMAT_DETAILED_CSV:
                content = self._generate_detailed_csv_content(keys_data)
                extension = ".csv"
                format_suffix = "detailed"
            elif export_format == EXPORT_FORMAT_JSON:
                content = self._generate_json_content(keys_data)
                extension = ".json"
                format_suffix = "export"
            else:
                raise ValueError(f"Unsupported export format: {export_format}")

            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{DEFAULT_SAVE_FILENAME}_{format_suffix}_{timestamp}"

            # Ensure correct extension
            if not filename.endswith(extension):
                filename += extension

            # Create Path object and write file
            file_path = Path(filename)
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                f.write(content)

            return str(file_path)

        except Exception as e:
            raise FileOperationError(
                f"Error saving keys in {export_format} format: {e}"
            ) from e

    def _encrypt_data(self, data: str, password: str) -> str:
        """
        Encrypt data using AES encryption with password-based key derivation.

        Args:
            data: String data to encrypt
            password: Password for encryption

        Returns:
            Base64-encoded encrypted data (salt + encrypted content)
        """
        if not password:
            raise InvalidPasswordError("Empty password provided")

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
            raise EncryptionError(f"Encryption error: {e}") from e

    def _decrypt_data(self, encrypted_data: str, password: str) -> str:
        """
        Decrypt data using AES encryption with password-based key derivation.

        Args:
            encrypted_data: Base64-encoded encrypted data
            password: Password for decryption

        Returns:
            Decrypted string data
        """
        if not password:
            raise InvalidPasswordError("Empty password provided")

        if not encrypted_data:
            raise DecryptionError("No encrypted data provided")

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
            raise DecryptionError(f"Decryption error: {e}") from e

    def _validate_encryption_parameters(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        password: str,
        password_confirm: str,
    ) -> None:
        """Validate parameters for encryption operations."""
        if not keys_data:
            raise NoKeysAvailableError("No keys data provided")

        if not password:
            raise InvalidPasswordError("Empty password provided")

        if password != password_confirm:
            raise InvalidPasswordError("Passwords do not match")

    def _generate_encrypted_content(
        self, keys_data: List[Tuple[str, str, str, str]], export_format: str
    ) -> str:
        """Generate content for encryption based on export format."""
        if export_format == EXPORT_FORMAT_JSON:
            content = self._generate_json_content(keys_data)
            # Add encrypted flag to the JSON
            data = json.loads(content)
            data["export_info"]["encrypted"] = True
            return json.dumps(data, indent=2)
        if export_format == EXPORT_FORMAT_CSV_SIMPLE:
            return self._generate_simple_csv_content(keys_data)
        if export_format == EXPORT_FORMAT_CSV_DETAILED:
            return self._generate_detailed_csv_content(keys_data)

        raise ValueError(f"Unsupported export format: {export_format}")

    def _generate_encrypted_filename(
        self, filename: Optional[str], export_format: str
    ) -> str:
        """Generate filename for encrypted file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{DEFAULT_SAVE_FILENAME}_encrypted_{export_format}_{timestamp}"

        if not filename.endswith(".enc"):
            filename += ".enc"

        return filename

    def save_keys_encrypted(
        self,
        keys_data: List[Tuple[str, str, str, str]],
        password: str,
        password_confirm: str,
        *,
        export_format: str = "json",
        filename: Optional[str] = None,
    ) -> str:
        """
        Save keys in encrypted format with password protection.

        Args:
            keys_data: List of (derivation_path, wif, public_key_hex, address) tuples
            password: Password for encryption
            password_confirm: Confirmed password
            export_format: Format to encrypt ("json", "csv_simple", "csv_detailed")
            filename: Optional filename (without extension)

        Returns:
            Path to the saved encrypted file
        """
        try:
            self._validate_encryption_parameters(keys_data, password, password_confirm)
            content = self._generate_encrypted_content(keys_data, export_format)
            encrypted_content = self._encrypt_data(content, password)
            final_filename = self._generate_encrypted_filename(filename, export_format)

            # Write encrypted file
            file_path = Path(final_filename)
            with open(file_path, "w", encoding="utf-8") as encfile:
                encfile.write(encrypted_content)

            return str(file_path)

        except Exception as e:
            raise FileOperationError(f"Error saving encrypted keys: {e}") from e

    def decrypt_keys_file(
        self, encrypted_file: str, password: str, output_file: Optional[str] = None
    ) -> str:
        """
        Decrypt a previously encrypted keys file.

        Args:
            encrypted_file: Path to encrypted file
            password: Password for decryption
            output_file: Optional output filename

        Returns:
            Path to the decrypted file
        """
        try:
            # Check if file exists
            if not Path(encrypted_file).exists():
                raise FileOperationError(f"File not found: {encrypted_file}")

            # Read encrypted content
            with open(encrypted_file, "r", encoding="utf-8") as encfile:
                encrypted_content = encfile.read()

            # Decrypt the content
            decrypted_content = self._decrypt_data(encrypted_content, password)

            # Generate output filename if not provided
            if not output_file:
                output_file = encrypted_file.replace(".enc", "_decrypted")
                # Try to detect format from content
                if decrypted_content.strip().startswith("{"):
                    output_file += ".json"
                elif DETAILED_CSV_HEADER in decrypted_content:
                    output_file += "_detailed.csv"
                elif SIMPLE_CSV_HEADER in decrypted_content:
                    output_file += "_simple.csv"
                else:
                    output_file += ".txt"

            # Write decrypted content
            with open(output_file, "w", encoding="utf-8") as outfile:
                outfile.write(decrypted_content)

            return output_file

        except Exception as e:
            raise FileOperationError(f"Error decrypting file: {e}") from e
