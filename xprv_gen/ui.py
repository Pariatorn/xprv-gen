"""
User interface components for the BSV HD Wallet Key Derivation Tool.

This module contains the CLI menu system and all the input/output handling
functions for the interactive interface.
"""

from typing import Callable, Dict, List

from .constants import (
    EncryptedExportChoice,
    ExportChoice,
    INITIAL_MENU_CHOICES,
    KEYS_DERIVED_CHOICES,
    MenuChoice,
    WALLET_LOADED_CHOICES,
)
from .wallet import HDWalletTool


def print_menu(wallet: HDWalletTool) -> None:
    """Print the dynamic menu based on wallet state."""
    print("\n" + "=" * 60)
    print("BSV HD Wallet Key Derivation Tool")
    print("=" * 60)
    
    # Always available options
    print("1. Load wallet from mnemonic seed phrase")
    print("2. Load wallet from master private key (xprv)")
    print("3. Generate new wallet")
    
    # Show wallet options if wallet is loaded
    if wallet.is_wallet_loaded:
        print("4. Show master xpub")
        print("5. Derive single key from path (e.g., m/0/1234)")
        print("6. Derive key range (e.g., m/44'/0'/0' indices 0-10)")
        
        # Show export option if keys are derived
        if wallet.has_derived_keys:
            print("7. Export keys")
    
    print("8. Decrypt existing file")
    print("9. Exit")
    print("=" * 60)


def print_export_menu() -> None:
    """Print the export submenu."""
    print("\n" + "=" * 50)
    print("Export Keys")
    print("=" * 50)
    print("1. Export as simple CSV (address,key)")
    print("2. Export as detailed CSV (derivation,address,key)")
    print("3. Export as JSON (structured format)")
    print("4. Export encrypted (password-protected)")
    print("5. Back to main menu")
    print("=" * 50)


def print_encrypted_export_menu() -> None:
    """Print the encrypted export submenu."""
    print("\n" + "=" * 50)
    print("Encrypted Export")
    print("=" * 50)
    print("1. Encrypt simple CSV (address,key)")
    print("2. Encrypt detailed CSV (derivation,address,key)")
    print("3. Encrypt JSON (structured format)")
    print("4. Back to export menu")
    print("=" * 50)


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
    print("1. Generate with custom entropy (advanced)")
    print("2. Generate with secure random entropy (recommended)")
    print("3. Back to main menu")
    
    choice = input("Enter your choice (1-3): ").strip()
    
    if choice == "1":
        entropy_input = input("Enter entropy (hex, or press Enter for random): ").strip()
        entropy = entropy_input if entropy_input else None
        wallet.generate_new_wallet(entropy)
    elif choice == "2":
        wallet.generate_new_wallet_secure()
    elif choice == "3":
        return
    else:
        print("✗ Invalid choice")


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


def handle_save_simple_format(wallet: HDWalletTool) -> None:
    """Handle saving keys in simple format."""
    print("\n--- Save Keys (Simple Format) ---")
    
    if not wallet.last_derived_keys:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return
    
    filename_input = input("Enter filename (optional, press Enter for auto-generated): ").strip()
    filename = filename_input if filename_input else None
    
    wallet.save_keys_simple_format(wallet.last_derived_keys, filename)


def handle_save_detailed_format(wallet: HDWalletTool) -> None:
    """Handle saving keys in detailed format."""
    print("\n--- Save Keys (Detailed Format) ---")
    
    if not wallet.last_derived_keys:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return
    
    filename_input = input("Enter filename (optional, press Enter for auto-generated): ").strip()
    filename = filename_input if filename_input else None
    
    wallet.save_keys_detailed_format(wallet.last_derived_keys, filename)


def handle_export_keys(wallet: HDWalletTool) -> None:
    """Handle the export keys submenu."""
    if not wallet.has_derived_keys:
        print("✗ No keys available to export")
        print("  Please derive keys first using options 5 or 6")
        return
    
    while True:
        print_export_menu()
        choice = input("Enter your choice (1-5): ").strip()
        
        try:
            export_choice = ExportChoice(choice)
            
            if export_choice == ExportChoice.EXPORT_SIMPLE_CSV:
                handle_save_simple_format(wallet)
            elif export_choice == ExportChoice.EXPORT_DETAILED_CSV:
                handle_save_detailed_format(wallet)
            elif export_choice == ExportChoice.EXPORT_JSON:
                handle_save_json_format(wallet)
            elif export_choice == ExportChoice.EXPORT_ENCRYPTED:
                handle_encrypted_export(wallet)
            elif export_choice == ExportChoice.BACK_TO_MAIN:
                break
            else:
                print("✗ Invalid choice")
                
        except ValueError:
            print("✗ Invalid choice")


def handle_save_json_format(wallet: HDWalletTool) -> None:
    """Handle saving keys in JSON format."""
    print("\n--- Save Keys (JSON Format) ---")
    
    if not wallet.last_derived_keys:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return
    
    filename_input = input("Enter filename (optional, press Enter for auto-generated): ").strip()
    filename = filename_input if filename_input else None
    
    wallet.save_keys_json_format(wallet.last_derived_keys, filename)


def handle_encrypted_export(wallet: HDWalletTool) -> None:
    """Handle the encrypted export submenu."""
    if not wallet.has_derived_keys:
        print("✗ No keys available to export")
        print("  Please derive keys first using options 5 or 6")
        return
    
    while True:
        print_encrypted_export_menu()
        choice = input("Enter your choice (1-4): ").strip()
        
        try:
            encrypted_choice = EncryptedExportChoice(choice)
            
            if encrypted_choice == EncryptedExportChoice.BACK_TO_EXPORT:
                break
            
            # Only ask for filename if not going back
            filename_input = input("Enter filename (optional, press Enter for auto-generated): ").strip()
            filename = filename_input if filename_input else None
            
            if encrypted_choice == EncryptedExportChoice.ENCRYPT_SIMPLE_CSV:
                wallet.save_keys_encrypted(wallet.last_derived_keys, "csv_simple", filename)
            elif encrypted_choice == EncryptedExportChoice.ENCRYPT_DETAILED_CSV:
                wallet.save_keys_encrypted(wallet.last_derived_keys, "csv_detailed", filename)
            elif encrypted_choice == EncryptedExportChoice.ENCRYPT_JSON:
                wallet.save_keys_encrypted(wallet.last_derived_keys, "json", filename)
            else:
                print("✗ Invalid choice")
                
        except ValueError:
            print("✗ Invalid choice")


def handle_decrypt_file(wallet: HDWalletTool) -> None:
    """Handle file decryption."""
    print("\n--- Decrypt Encrypted File ---")
    
    encrypted_file = input("Enter path to encrypted file (.enc): ").strip()
    if not encrypted_file:
        print("✗ No file path provided")
        return
    
    output_file_input = input("Enter output filename (optional, press Enter for auto-generated): ").strip()
    output_file = output_file_input if output_file_input else None
    
    wallet.decrypt_keys_file(encrypted_file, output_file)


def get_valid_choices(wallet: HDWalletTool) -> List[str]:
    """Get valid menu choices based on current wallet state."""
    valid_choices = []
    
    # Always available options
    valid_choices.extend([choice.value for choice in INITIAL_MENU_CHOICES])
    
    # Add wallet-dependent options
    if wallet.is_wallet_loaded:
        valid_choices.extend([choice.value for choice in WALLET_LOADED_CHOICES])
        
        # Add export option if keys are derived
        if wallet.has_derived_keys:
            valid_choices.extend([choice.value for choice in KEYS_DERIVED_CHOICES])
    
    return valid_choices


def get_menu_handlers() -> Dict[MenuChoice, Callable[[HDWalletTool], None]]:
    """Get the mapping of menu choices to their handler functions."""
    return {
        MenuChoice.LOAD_FROM_MNEMONIC: handle_load_from_mnemonic,
        MenuChoice.LOAD_FROM_XPRV: handle_load_from_xprv,
        MenuChoice.GENERATE_NEW_WALLET: handle_generate_new_wallet,
        MenuChoice.SHOW_MASTER_XPUB: handle_show_master_xpub,
        MenuChoice.DERIVE_SINGLE_KEY: handle_derive_single_key,
        MenuChoice.DERIVE_KEY_RANGE: handle_derive_key_range,
        MenuChoice.EXPORT_KEYS: handle_export_keys,
        MenuChoice.DECRYPT_FILE: handle_decrypt_file,
    }
