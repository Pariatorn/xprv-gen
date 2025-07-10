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

# Base58 alphabet for Bitcoin
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Test mode identifier
TEST_MODE_ARG = "test"

# Save format constants
SIMPLE_CSV_HEADER = "address,key"
DETAILED_CSV_HEADER = "derivation,address,key"
DEFAULT_SAVE_FILENAME = "wallet_keys"
CSV_EXTENSION = ".csv"


class MenuChoice(Enum):
    """Menu choice enumeration for the CLI interface."""

    # Always available options
    LOAD_FROM_MNEMONIC = "1"
    LOAD_FROM_XPRV = "2"
    GENERATE_NEW_WALLET = "3"
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
    BACK_TO_MAIN = "4"


# Menu configuration
INITIAL_MENU_CHOICES: List[MenuChoice] = [
    MenuChoice.LOAD_FROM_MNEMONIC,
    MenuChoice.LOAD_FROM_XPRV,
    MenuChoice.GENERATE_NEW_WALLET,
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
