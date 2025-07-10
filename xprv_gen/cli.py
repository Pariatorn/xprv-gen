"""
Command Line Interface for the BSV HD Wallet Key Derivation Tool.

This module serves as the main entry point for the CLI application,
handling the interactive menu loop and test mode functionality.
"""

import sys

from .constants import TEST_MODE_ARG, MenuChoice
from .ui import get_menu_handlers, print_menu
from .wallet import HDWalletTool


def main() -> None:
    """Main application loop."""
    wallet = HDWalletTool()
    menu_handlers = get_menu_handlers()

    while True:
        print_menu(wallet)
        choice = input("Enter your choice (1-9): ").strip()

        # Convert string choice to enum
        try:
            menu_choice = MenuChoice(choice)
        except ValueError:
            print("✗ Invalid choice. Please try again.")
            input("\nPress Enter to continue...")
            continue

        if menu_choice == MenuChoice.EXIT:
            print("\nGoodbye!")
            break

        # Execute the appropriate handler
        if menu_choice in menu_handlers:
            menu_handlers[menu_choice](wallet)

        input("\nPress Enter to continue...")


def run_test_mode() -> None:
    """Run the application in test mode."""
    print("Running test mode...")

    # Create test wallet
    wallet = HDWalletTool()

    # Test 1: Generate new wallet
    print("\n=== Test 1: Generate New Wallet ===")
    result1 = wallet.generate_new_wallet("cd9b819d9c62f0027116c1849e7d497f")
    print(f"Result: {'✅ SUCCESS' if result1 else '❌ FAILED'}")

    # Test 2: Get master xpub
    print("\n=== Test 2: Master xpub ===")
    xpub_result = wallet.get_master_xpub()
    print(f"Result: {'✅ SUCCESS' if xpub_result else '❌ FAILED'}")
    if xpub_result:
        print(f"Returned xpub length: {len(xpub_result)} characters")

    # Test 3: Derive single key
    print("\n=== Test 3: Derive Single Key ===")
    single_key_result = wallet.derive_single_key("m/0/1234")
    print(f"Result: {'✅ SUCCESS' if single_key_result else '❌ FAILED'}")
    if single_key_result:
        wif, pubkey, address = single_key_result
        print(f"Returned: WIF({len(wif)} chars), PubKey({len(pubkey)} chars), Address({len(address)} chars)")

    # Test 4: Derive key range
    print("\n=== Test 4: Derive Key Range ===")
    range_result = wallet.derive_keys_range("m/44'/0'/0'", 0, 2)
    print(f"Result: {'✅ SUCCESS' if range_result else '❌ FAILED'}")
    if range_result:
        print(f"Returned {len(range_result)} derived keys")
        
    print(f"\n🎯 Test Summary: {sum([bool(result1), bool(xpub_result), bool(single_key_result), bool(range_result)])}/4 tests passed")


def cli_main() -> None:
    """Main CLI entry point that handles command line arguments."""
    if len(sys.argv) > 1 and sys.argv[1] == TEST_MODE_ARG:
        run_test_mode()
    else:
        main()


if __name__ == "__main__":
    cli_main()
