"""
Command line interface for the BSV HD Wallet Key Derivation Tool.

This module provides the main CLI entry point and test mode functionality
for the BSV HD wallet key derivation tool.
"""

import sys
from typing import Callable, Dict, List, Tuple

from .constants import MenuChoice
from .ui import (
    get_valid_choices,
    handle_decrypt_file,
    handle_derive_key_range,
    handle_derive_single_key,
    handle_export_keys,
    handle_generate_new_wallet,
    handle_load_from_mnemonic,
    handle_load_from_xprv,
    handle_show_master_xpub,
    print_menu,
)
from .wallet import HDWalletTool

TEST_MODE_ARG = "--test"


def _handle_key_derivation(
    handler: Callable,
    wallet: HDWalletTool,
    derived_keys: List[Tuple[str, str, str, str]],
) -> List[Tuple[str, str, str, str]]:
    """Handle key derivation operations that return new keys."""
    new_keys = handler(wallet)
    if new_keys:
        return new_keys  # Replace with new keys
    return derived_keys


def _execute_menu_choice(
    menu_choice: MenuChoice,
    wallet: HDWalletTool,
    derived_keys: List[Tuple[str, str, str, str]],
) -> List[Tuple[str, str, str, str]]:
    """Execute the appropriate handler for the given menu choice."""
    # Menu handlers that don't affect derived_keys
    simple_handlers: Dict[MenuChoice, Callable[[HDWalletTool], None]] = {
        MenuChoice.LOAD_FROM_MNEMONIC: handle_load_from_mnemonic,
        MenuChoice.LOAD_FROM_XPRV: handle_load_from_xprv,
        MenuChoice.GENERATE_NEW_WALLET: handle_generate_new_wallet,
        MenuChoice.SHOW_MASTER_XPUB: handle_show_master_xpub,
        MenuChoice.DECRYPT_FILE: handle_decrypt_file,
    }

    # Handle simple operations
    if menu_choice in simple_handlers:
        simple_handlers[menu_choice](wallet)
        return derived_keys

    # Handle key derivation operations
    if menu_choice == MenuChoice.DERIVE_SINGLE_KEY:
        return _handle_key_derivation(handle_derive_single_key, wallet, derived_keys)
    if menu_choice == MenuChoice.DERIVE_KEY_RANGE:
        return _handle_key_derivation(handle_derive_key_range, wallet, derived_keys)

    # Handle export operation
    if menu_choice == MenuChoice.EXPORT_KEYS:
        handle_export_keys(derived_keys, wallet)
        return derived_keys

    return derived_keys


def _get_user_input() -> str:
    """Get and validate user input."""
    return input("Enter your choice (1-9): ").strip()


def _process_menu_choice(choice: str) -> MenuChoice:
    """Process and validate menu choice string."""
    try:
        return MenuChoice(choice)
    except ValueError as exc:
        raise ValueError("Invalid choice. Please try again.") from exc


def main() -> None:
    """Main application loop."""
    wallet = HDWalletTool()
    derived_keys: List[Tuple[str, str, str, str]] = []

    while True:
        print_menu(wallet, derived_keys)
        choice = _get_user_input()

        # Check if choice is valid for current wallet state
        valid_choices = get_valid_choices(wallet, derived_keys)
        if choice not in valid_choices:
            print("✗ Invalid choice or option not available in current state.")
            input("\nPress Enter to continue...")
            continue

        # Process menu choice
        try:
            menu_choice = _process_menu_choice(choice)
        except ValueError as e:
            print(f"✗ {e}")
            input("\nPress Enter to continue...")
            continue

        if menu_choice == MenuChoice.EXIT:
            print("\nGoodbye!")
            break

        # Execute the appropriate handler
        derived_keys = _execute_menu_choice(menu_choice, wallet, derived_keys)
        input("\nPress Enter to continue...")


def run_test_mode() -> None:
    """Run the application in test mode."""
    print("Running test mode...")

    # Create test wallet
    wallet = HDWalletTool()

    # Test 1: Generate new wallet
    print("\n=== Test 1: Generate New Wallet ===")
    try:
        mnemonic, entropy = wallet.generate_new_wallet(
            "cd9b819d9c62f0027116c1849e7d497f"
        )
        print("✅ SUCCESS")
        print(f"Generated mnemonic: {mnemonic}")
        print(f"Used entropy: {entropy}")
        result1 = True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        result1 = False

    # Test 2: Get master xpub
    print("\n=== Test 2: Master xpub ===")
    try:
        xpub_result = wallet.get_master_xpub()
        print("✅ SUCCESS")
        print(f"Returned xpub length: {len(xpub_result)} characters")
        xpub_success = True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        xpub_result = None
        xpub_success = False

    # Test 3: Derive single key
    print("\n=== Test 3: Derive Single Key ===")
    try:
        derivation_path, wif, pubkey, address = wallet.derive_single_key("m/0/1234")
        print("✅ SUCCESS")
        print(
            f"Returned: Path({derivation_path}), WIF({len(wif)} chars), "
            f"PubKey({len(pubkey)} chars), Address({len(address)} chars)"
        )
        single_key_success = True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        single_key_success = False

    # Test 4: Derive key range
    print("\n=== Test 4: Derive Key Range ===")
    try:
        range_result = wallet.derive_keys_range("m/44'/0'/0'", 0, 2)
        print("✅ SUCCESS")
        print(f"Returned {len(range_result)} derived keys")
        range_success = True
    except Exception as e:
        print(f"❌ FAILED: {e}")
        range_success = False

    test_results = [result1, xpub_success, single_key_success, range_success]
    print(f"\n🎯 Test Summary: {sum(test_results)}/4 tests passed")


def cli_main() -> None:
    """Main CLI entry point that handles command line arguments."""
    if len(sys.argv) > 1 and sys.argv[1] == TEST_MODE_ARG:
        run_test_mode()
    else:
        main()


if __name__ == "__main__":
    cli_main()
