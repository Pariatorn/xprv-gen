"""
User interface components for the BSV HD Wallet Key Derivation Tool.

This module contains the CLI menu system and all the input/output handling
functions for the interactive interface.
"""

from typing import Callable, Dict

from .constants import MenuChoice
from .wallet import HDWalletTool


def print_menu() -> None:
    """Print the main menu."""
    print("\n" + "=" * 60)
    print("BSV HD Wallet Key Derivation Tool")
    print("=" * 60)
    print("1. Load wallet from mnemonic seed phrase")
    print("2. Load wallet from master private key (xprv)")
    print("3. Generate new wallet")
    print("4. Show master xpub")
    print("5. Derive single key from path (e.g., m/0/1234)")
    print("6. Derive key range (e.g., m/44'/0'/0' indices 0-10)")
    print("7. Exit")
    print("=" * 60)


def handle_load_from_mnemonic(wallet: HDWalletTool) -> None:
    """Handle loading wallet from mnemonic."""
    print("\n--- Load from Mnemonic ---")
    mnemonic = input("Enter mnemonic seed phrase: ").strip()
    if mnemonic:
        wallet.load_from_mnemonic(mnemonic)
    else:
        print("✗ Empty mnemonic provided")


def handle_load_from_xprv(wallet: HDWalletTool) -> None:
    """Handle loading wallet from xprv."""
    print("\n--- Load from xprv ---")
    xprv = input("Enter master private key (xprv): ").strip()
    if xprv:
        wallet.load_from_xprv(xprv)
    else:
        print("✗ Empty xprv provided")


def handle_generate_new_wallet(wallet: HDWalletTool) -> None:
    """Handle generating new wallet."""
    print("\n--- Generate New Wallet ---")
    entropy_input = input("Enter entropy (hex, or press Enter for random): ").strip()
    entropy = entropy_input if entropy_input else None
    wallet.generate_new_wallet(entropy)


def handle_show_master_xpub(wallet: HDWalletTool) -> None:
    """Handle showing master xpub."""
    print("\n--- Master xpub ---")
    wallet.get_master_xpub()


def handle_derive_single_key(wallet: HDWalletTool) -> None:
    """Handle deriving single key."""
    print("\n--- Derive Single Key ---")
    path = input("Enter derivation path (e.g., m/0/1234): ").strip()
    if path:
        wallet.derive_single_key(path)
    else:
        print("✗ Empty path provided")


def handle_derive_key_range(wallet: HDWalletTool) -> None:
    """Handle deriving key range."""
    print("\n--- Derive Key Range ---")
    base_path = input("Enter base path (e.g., m/44'/0'/0'): ").strip()
    try:
        start_idx = int(input("Enter start index: ").strip())
        end_idx = int(input("Enter end index: ").strip())
        if base_path and start_idx <= end_idx:
            wallet.derive_keys_range(base_path, start_idx, end_idx)
        else:
            print("✗ Invalid input")
    except ValueError:
        print("✗ Invalid indices provided")


def get_menu_handlers() -> Dict[MenuChoice, Callable[[HDWalletTool], None]]:
    """Get the mapping of menu choices to their handler functions."""
    return {
        MenuChoice.LOAD_FROM_MNEMONIC: handle_load_from_mnemonic,
        MenuChoice.LOAD_FROM_XPRV: handle_load_from_xprv,
        MenuChoice.GENERATE_NEW_WALLET: handle_generate_new_wallet,
        MenuChoice.SHOW_MASTER_XPUB: handle_show_master_xpub,
        MenuChoice.DERIVE_SINGLE_KEY: handle_derive_single_key,
        MenuChoice.DERIVE_KEY_RANGE: handle_derive_key_range,
    }
