"""
User interface module for the BSV HD Wallet Key Derivation Tool.

This module provides all the user interface functions for interactive
wallet operations including menu display, user input handling, and
error/success message display.
"""

from typing import Dict, List, Optional, Tuple

from .constants import (
    INITIAL_MENU_CHOICES,
    KEYS_DERIVED_CHOICES,
    MENU_CHOICE_1,
    MENU_CHOICE_2,
    MENU_CHOICE_3,
    WALLET_LOADED_CHOICES,
    EncryptedExportChoice,
    ExportChoice,
    MenuChoice,
)
from .exceptions import (
    DecryptionError,
    DerivationPathError,
    FileOperationError,
    InvalidEntropyError,
    InvalidIndexRangeError,
    InvalidMnemonicError,
    InvalidPasswordError,
    InvalidXprvError,
    NoKeysAvailableError,
    WalletNotLoadedError,
)
from .wallet import HDWalletTool


def print_menu(
    wallet: HDWalletTool, derived_keys: List[Tuple[str, str, str, str]]
) -> None:
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
        if derived_keys:
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
    if not mnemonic:
        print("✗ Empty mnemonic provided")
        return

    try:
        mnemonic_type = wallet.load_from_mnemonic(mnemonic)
        print(f"✓ Valid {mnemonic_type} mnemonic")
        print("✓ Successfully loaded wallet from mnemonic")
        print(f"✓ Master xprv: {wallet.master_xprv}")
    except InvalidMnemonicError as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_load_from_xprv(wallet: HDWalletTool) -> None:
    """Handle loading wallet from xprv."""
    print("\n--- Load from xprv ---")
    xprv = input("Enter master private key (xprv): ").strip()
    if not xprv:
        print("✗ Empty xprv provided")
        return

    try:
        format_type = wallet.load_from_xprv(xprv)
        print(f"✓ Successfully loaded wallet from {format_type}")
        print(f"✓ Master xprv: {wallet.master_xprv}")
    except InvalidXprvError as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_generate_new_wallet(wallet: HDWalletTool) -> None:
    """Handle generating new wallet."""
    print("\n--- Generate New Wallet ---")
    print("1. Generate with custom entropy (advanced)")
    print("2. Generate with secure random entropy (recommended)")
    print("3. Back to main menu")

    choice = input("Enter your choice (1-3): ").strip()

    try:
        if choice == MENU_CHOICE_1:
            entropy_input = input(
                "Enter entropy (hex, or press Enter for random): "
            ).strip()
            entropy = entropy_input if entropy_input else None
            mnemonic, entropy_used = wallet.generate_new_wallet(entropy)
            print("✓ Generated new wallet")
            print(f"✓ Entropy: {entropy_used}")
            print(f"✓ Mnemonic: {mnemonic}")
            print("✓ Successfully loaded wallet from mnemonic")
            print(f"✓ Master xprv: {wallet.master_xprv}")
        elif choice == MENU_CHOICE_2:
            mnemonic, entropy_hex = wallet.generate_new_wallet_secure()
            print("✓ Using cryptographically secure random entropy")
            print("✓ Entropy source: os.urandom() via secrets module")
            print("✓ Entropy strength: 256 bits")
            print("✓ Generated new wallet with secure entropy")
            print(f"✓ Entropy: {entropy_hex}")
            print(f"✓ Mnemonic: {mnemonic}")
            print("✓ Successfully loaded wallet from mnemonic")
            print(f"✓ Master xprv: {wallet.master_xprv}")
        elif choice == MENU_CHOICE_3:
            return
        else:
            print("✗ Invalid choice")
    except InvalidEntropyError as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_show_master_xpub(wallet: HDWalletTool) -> None:
    """Handle showing master xpub."""
    print("\n--- Master xpub ---")
    try:
        xpub = wallet.get_master_xpub()
        print(f"✓ Master xpub: {xpub}")
    except WalletNotLoadedError as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_derive_single_key(wallet: HDWalletTool) -> List[Tuple[str, str, str, str]]:
    """Handle deriving single key."""
    print("\n--- Derive Single Key ---")
    path = input("Enter derivation path (e.g., m/0/1234): ").strip()
    if not path:
        print("✗ Empty path provided")
        return []

    try:
        derivation_path, wif, public_key_hex, address = wallet.derive_single_key(path)
        print(f"✓ Derived key for path: {derivation_path}")
        print(f"  Private Key (WIF): {wif}")
        print(f"  Public Key (hex): {public_key_hex}")
        print(f"  Address: {address}")
        return [(derivation_path, wif, public_key_hex, address)]
    except (WalletNotLoadedError, DerivationPathError) as e:
        print(f"✗ {e}")
        return []
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return []


def handle_derive_key_range(wallet: HDWalletTool) -> List[Tuple[str, str, str, str]]:
    """Handle deriving key range."""
    print("\n--- Derive Key Range ---")
    base_path = input("Enter base path (e.g., m/44'/0'/0'): ").strip()
    if not base_path:
        print("✗ Empty base path provided")
        return []

    try:
        start_idx = int(input("Enter start index: ").strip())
        end_idx = int(input("Enter end index: ").strip())

        if start_idx > end_idx:
            print("✗ Start index must be less than or equal to end index")
            return []

        results = wallet.derive_keys_range(base_path, start_idx, end_idx)
        for derivation_path, wif, public_key_hex, address in results:
            print(f"✓ {derivation_path}")
            print(f"  Private Key (WIF): {wif}")
            print(f"  Public Key (hex): {public_key_hex}")
            print(f"  Address: {address}")
            print()
        return results

    except ValueError:
        print("✗ Invalid indices provided")
        return []
    except (WalletNotLoadedError, DerivationPathError, InvalidIndexRangeError) as e:
        print(f"✗ {e}")
        return []
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return []


def handle_save_simple_format(
    keys_data: List[Tuple[str, str, str, str]], wallet: HDWalletTool
) -> None:
    """Handle saving keys in simple format."""
    print("\n--- Save Keys (Simple Format) ---")

    if not keys_data:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return

    filename_input = input(
        "Enter filename (optional, press Enter for auto-generated): "
    ).strip()
    filename = filename_input if filename_input else None

    try:
        saved_path = wallet.save_keys(keys_data, "simple_csv", filename)
        print(f"✓ Successfully saved {len(keys_data)} keys to {saved_path}")
        print("✓ Format: address,key")
    except (NoKeysAvailableError, FileOperationError) as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_save_detailed_format(
    keys_data: List[Tuple[str, str, str, str]], wallet: HDWalletTool
) -> None:
    """Handle saving keys in detailed format."""
    print("\n--- Save Keys (Detailed Format) ---")

    if not keys_data:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return

    filename_input = input(
        "Enter filename (optional, press Enter for auto-generated): "
    ).strip()
    filename = filename_input if filename_input else None

    try:
        saved_path = wallet.save_keys(keys_data, "detailed_csv", filename)
        print(f"✓ Successfully saved {len(keys_data)} keys to {saved_path}")
        print("✓ Format: derivation,address,key")
    except (NoKeysAvailableError, FileOperationError) as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_export_keys(
    keys_data: List[Tuple[str, str, str, str]], wallet: HDWalletTool
) -> None:
    """Handle the export keys submenu."""
    if not keys_data:
        print("✗ No keys available to export")
        print("  Please derive keys first using options 5 or 6")
        return

    while True:
        print_export_menu()
        choice = input("Enter your choice (1-5): ").strip()

        try:
            export_choice = ExportChoice(choice)

            if export_choice == ExportChoice.EXPORT_SIMPLE_CSV:
                handle_save_simple_format(keys_data, wallet)
            elif export_choice == ExportChoice.EXPORT_DETAILED_CSV:
                handle_save_detailed_format(keys_data, wallet)
            elif export_choice == ExportChoice.EXPORT_JSON:
                handle_save_json_format(keys_data, wallet)
            elif export_choice == ExportChoice.EXPORT_ENCRYPTED:
                handle_encrypted_export(keys_data, wallet)
            elif export_choice == ExportChoice.BACK_TO_MAIN:
                break
            else:
                print("✗ Invalid choice")

        except ValueError:
            print("✗ Invalid choice")


def handle_save_json_format(
    keys_data: List[Tuple[str, str, str, str]], wallet: HDWalletTool
) -> None:
    """Handle saving keys in JSON format."""
    print("\n--- Save Keys (JSON Format) ---")

    if not keys_data:
        print("✗ No keys available to save")
        print("  Please derive keys first using options 5 or 6")
        return

    filename_input = input(
        "Enter filename (optional, press Enter for auto-generated): "
    ).strip()
    filename = filename_input if filename_input else None

    try:
        saved_path = wallet.save_keys(keys_data, "json", filename)
        print(f"✓ Successfully saved {len(keys_data)} keys to {saved_path}")
        print("✓ Format: JSON with metadata and checksums")
        # Get file size for display
        from pathlib import Path

        file_size = Path(saved_path).stat().st_size
        print(f"✓ File size: {file_size} bytes")
    except (NoKeysAvailableError, FileOperationError) as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def _get_encryption_passwords() -> Tuple[str, str]:
    """Get and validate encryption passwords from user."""
    import getpass

    password = getpass.getpass("Enter encryption password: ")
    if not password:
        raise InvalidPasswordError("Empty password provided")

    password_confirm = getpass.getpass("Confirm encryption password: ")
    if password != password_confirm:
        raise InvalidPasswordError("Passwords do not match")

    return password, password_confirm


def _get_export_format_from_choice(encrypted_choice: EncryptedExportChoice) -> str:
    """Convert encrypted export choice to format string."""
    format_mapping = {
        EncryptedExportChoice.ENCRYPT_SIMPLE_CSV: "csv_simple",
        EncryptedExportChoice.ENCRYPT_DETAILED_CSV: "csv_detailed",
        EncryptedExportChoice.ENCRYPT_JSON: "json",
    }

    if encrypted_choice not in format_mapping:
        raise ValueError("Invalid choice")

    return format_mapping[encrypted_choice]


def _process_encrypted_export(
    keys_data: List[Tuple[str, str, str, str]],
    wallet: HDWalletTool,
    encrypted_choice: EncryptedExportChoice,
    filename: Optional[str],
) -> None:
    """Process the encrypted export for a specific choice."""
    if encrypted_choice == EncryptedExportChoice.BACK_TO_EXPORT:
        return

    try:
        password, password_confirm = _get_encryption_passwords()
        export_format = _get_export_format_from_choice(encrypted_choice)

        saved_path = wallet.save_keys_encrypted(
            keys_data,
            password,
            password_confirm,
            export_format=export_format,
            filename=filename,
        )

        print(f"✓ Successfully saved {len(keys_data)} keys to {saved_path}")
        print(f"✓ Format: {export_format.upper()} (AES-256 encrypted)")
        print("✓ Encryption: PBKDF2 with 100,000 iterations")
        print("✓ File is password-protected")

    except (InvalidPasswordError, NoKeysAvailableError, FileOperationError) as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def handle_encrypted_export(
    keys_data: List[Tuple[str, str, str, str]], wallet: HDWalletTool
) -> None:
    """Handle the encrypted export submenu."""
    if not keys_data:
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

            # Get filename from user
            filename_input = input(
                "Enter filename (optional, press Enter for auto-generated): "
            ).strip()
            filename = filename_input if filename_input else None

            _process_encrypted_export(keys_data, wallet, encrypted_choice, filename)

        except ValueError:
            print("✗ Invalid choice")


def handle_decrypt_file(wallet: HDWalletTool) -> None:
    """Handle file decryption."""
    print("\n--- Decrypt Encrypted File ---")

    encrypted_file = input("Enter path to encrypted file (.enc): ").strip()
    if not encrypted_file:
        print("✗ No file path provided")
        return

    output_file_input = input(
        "Enter output filename (optional, press Enter for auto-generated): "
    ).strip()
    output_file = output_file_input if output_file_input else None

    # Get password from user
    import getpass

    password = getpass.getpass("Enter decryption password: ")
    if not password:
        print("✗ Empty password provided")
        return

    try:
        decrypted_path = wallet.decrypt_keys_file(encrypted_file, password, output_file)
        print(f"✓ Successfully decrypted to: {decrypted_path}")
        print("✓ Decryption successful")
    except (InvalidPasswordError, DecryptionError, FileOperationError) as e:
        print(f"✗ {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")


def get_valid_choices(
    wallet: HDWalletTool, derived_keys: List[Tuple[str, str, str, str]]
) -> List[str]:
    """Get valid menu choices based on current wallet state."""
    valid_choices = []

    # Always available options
    valid_choices.extend([choice.value for choice in INITIAL_MENU_CHOICES])

    # Add wallet-dependent options
    if wallet.is_wallet_loaded:
        valid_choices.extend([choice.value for choice in WALLET_LOADED_CHOICES])

        # Add export option if keys are derived
        if derived_keys:
            valid_choices.extend([choice.value for choice in KEYS_DERIVED_CHOICES])

    return valid_choices


def get_menu_handlers() -> Dict[str, str]:
    """Get the mapping of menu choices to their handler function names."""
    return {
        MenuChoice.LOAD_FROM_MNEMONIC.value: "handle_load_from_mnemonic",
        MenuChoice.LOAD_FROM_XPRV.value: "handle_load_from_xprv",
        MenuChoice.GENERATE_NEW_WALLET.value: "handle_generate_new_wallet",
        MenuChoice.SHOW_MASTER_XPUB.value: "handle_show_master_xpub",
        MenuChoice.DERIVE_SINGLE_KEY.value: "handle_derive_single_key",
        MenuChoice.DERIVE_KEY_RANGE.value: "handle_derive_key_range",
        MenuChoice.EXPORT_KEYS.value: "handle_export_keys",
        MenuChoice.DECRYPT_FILE.value: "handle_decrypt_file",
    }
