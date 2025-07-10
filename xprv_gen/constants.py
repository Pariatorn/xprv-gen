"""
Constants and enumerations for the BSV HD Wallet Key Derivation Tool.

This module contains all the constants, magic numbers, and enumerations
used throughout the application.
"""

from enum import Enum
from typing import List

# Seed and key constants
SEED_LENGTH_64 = 64
SEED_LENGTH_32 = 32
HARDENED_KEY_FLAG = 0x80000000
DERIVATION_PATH_PREFIX = "m"
PBKDF2_ITERATIONS = 2048

# Key format constants
XPRV_STRING_LENGTH = 111
XPRV_PREFIX = "xprv"

# Base58 alphabet for Bitcoin
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Test mode identifier
TEST_MODE_ARG = "test"

# Save format constants
SIMPLE_CSV_HEADER = "address,key"
DETAILED_CSV_HEADER = "derivation,address,key"
DEFAULT_SAVE_FILENAME = "wallet_keys"
CSV_EXTENSION = ".csv"

# Export format strings
EXPORT_FORMAT_SIMPLE_CSV = "simple_csv"
EXPORT_FORMAT_DETAILED_CSV = "detailed_csv"
EXPORT_FORMAT_JSON = "json"
EXPORT_FORMAT_CSV_SIMPLE = "csv_simple"
EXPORT_FORMAT_CSV_DETAILED = "csv_detailed"

# Menu choice strings
MENU_CHOICE_1 = "1"
MENU_CHOICE_2 = "2"
MENU_CHOICE_3 = "3"

# User interface messages
MESSAGE_EMPTY_MNEMONIC = "Empty mnemonic provided"
MESSAGE_EMPTY_XPRV = "Empty xprv provided"
MESSAGE_EMPTY_PATH = "Empty path provided"
MESSAGE_INVALID_INPUT = "Invalid input"
MESSAGE_INVALID_INDICES = "Invalid indices provided"
MESSAGE_NO_KEYS_EXPORT = "No keys available to export"
MESSAGE_NO_KEYS_SAVE = "No keys available to save"
MESSAGE_INVALID_CHOICE = "Invalid choice or option not available in current state."
MESSAGE_GOODBYE = "Goodbye!"

# Test mode messages
TEST_MODE_RUNNING = "Running test mode..."
TEST_1_TITLE = "Test 1: Generate New Wallet"
TEST_2_TITLE = "Test 2: Master xpub"
TEST_3_TITLE = "Test 3: Derive Single Key"
TEST_4_TITLE = "Test 4: Derive Key Range"

# Menu display strings
MENU_TITLE = "BSV HD Wallet Key Derivation Tool"
MENU_LOAD_MNEMONIC = "1. Load wallet from mnemonic seed phrase"
MENU_LOAD_XPRV = "2. Load wallet from master private key (xprv)"
MENU_GENERATE_WALLET = "3. Generate new wallet"
MENU_SHOW_XPUB = "4. Show master xpub"
MENU_DERIVE_SINGLE = "5. Derive single key from path (e.g., m/0/1234)"
MENU_DERIVE_RANGE = "6. Derive key range (e.g., m/44'/0'/0' indices 0-10)"
MENU_EXPORT_KEYS = "7. Export keys"
MENU_EXIT = "9. Exit"

# Menu choice constants
MENU_CHOICE_EXIT = "9"
MENU_CHOICE_DECRYPT = "8"

# Sample test data
TEST_MNEMONIC_TYPE_BIP39 = "BIP39"
TEST_MNEMONIC_TYPE_ELECTRUM = "Electrum"
TEST_KEY_TYPE_EXTENDED = "Extended Private Key"
TEST_KEY_TYPE_HEX = "Hex Seed"
TEST_SAMPLE_XPUB = "xpub123"
TEST_SAMPLE_PATH = "m/0/1"
TEST_SAMPLE_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
TEST_SAMPLE_PUBKEY = "abcdef123456"
TEST_SAMPLE_ADDRESS = "1ABC123"


class MenuChoice(Enum):
    """Menu choice enumeration for the CLI interface."""

    # Always available options
    LOAD_FROM_MNEMONIC = "1"
    LOAD_FROM_XPRV = "2"
    GENERATE_NEW_WALLET = "3"
    DECRYPT_FILE = "8"
    EXIT = "9"

    # Available after wallet is loaded
    SHOW_MASTER_XPUB = "4"
    DERIVE_SINGLE_KEY = "5"
    DERIVE_KEY_RANGE = "6"

    # Available after keys are derived
    EXPORT_KEYS = "7"


class ExportChoice(Enum):
    """Export submenu choice enumeration."""

    EXPORT_SIMPLE_CSV = "1"
    EXPORT_DETAILED_CSV = "2"
    EXPORT_JSON = "3"
    EXPORT_ENCRYPTED = "4"
    BACK_TO_MAIN = "5"


class EncryptedExportChoice(Enum):
    """Encrypted export submenu choice enumeration."""

    ENCRYPT_SIMPLE_CSV = "1"
    ENCRYPT_DETAILED_CSV = "2"
    ENCRYPT_JSON = "3"
    BACK_TO_EXPORT = "4"


# Menu configuration
INITIAL_MENU_CHOICES: List[MenuChoice] = [
    MenuChoice.LOAD_FROM_MNEMONIC,
    MenuChoice.LOAD_FROM_XPRV,
    MenuChoice.GENERATE_NEW_WALLET,
    MenuChoice.DECRYPT_FILE,
    MenuChoice.EXIT,
]

WALLET_LOADED_CHOICES: List[MenuChoice] = [
    MenuChoice.SHOW_MASTER_XPUB,
    MenuChoice.DERIVE_SINGLE_KEY,
    MenuChoice.DERIVE_KEY_RANGE,
]

KEYS_DERIVED_CHOICES: List[MenuChoice] = [
    MenuChoice.EXPORT_KEYS,
]
