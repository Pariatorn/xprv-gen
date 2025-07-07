#!/usr/bin/env python3
"""
BSV HD Wallet Key Derivation Tool
=================================

This tool allows for offline derivation of Bitcoin SV wallet keys from either:
1. Seed phrase (mnemonic)
2. Master private key (xprv)

Features:
- Derive xpub from seed phrase or xprv
- Generate child private keys and addresses for given derivation paths
- Support for standard BIP32 derivation paths
- Compatible with ElectrumSV wallet
- Completely offline operation

Requirements:
- pip install bsv-sdk

Usage:
    python hd_wallet_tool.py
"""

import sys
from typing import List, Optional, Tuple

import bsv.hd


class HDWalletTool:
    """HD Wallet derivation tool for BSV"""

    def __init__(self):
        self.master_xprv: Optional[bsv.hd.Xprv] = None
        self.mnemonic: Optional[str] = None

    def load_from_mnemonic(self, mnemonic: str) -> bool:
        """Load wallet from mnemonic seed phrase"""
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
                import hashlib
                import hmac

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
                    import hashlib

                    seed = hashlib.pbkdf2_hmac(
                        "sha512",
                        normalized_mnemonic.encode("utf-8"),
                        # Electrum uses "electrum" as salt instead of "mnemonic"
                        b"electrum",
                        2048,  # Same iteration count as BIP39
                    )
                else:
                    print(
                        "⚠ Not a valid Electrum mnemonic either, but trying anyway..."
                    )
                    # Still try to generate seed (for compatibility)
                    seed = hashlib.pbkdf2_hmac(
                        "sha512", normalized_mnemonic.encode("utf-8"), b"electrum", 2048
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
        """Load wallet from master private key (xprv)"""
        try:
            # Try to parse as extended private key string
            if xprv_string.startswith("xprv"):
                # Parse as proper xprv string
                self.master_xprv = bsv.hd.Xprv(xprv_string)
            elif len(xprv_string) == 64:
                # Assume it's a hex private key and create from that
                seed = bytes.fromhex(xprv_string)
                # Pad to proper seed length if needed
                if len(seed) < 64:
                    seed = seed + b"\x00" * (64 - len(seed))
                self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
            else:
                # Try to decode as base58 and extract key
                decoded = self._base58_decode(xprv_string)
                if len(decoded) >= 32:
                    # Extract the private key (skip version and checksum)
                    private_key_bytes = decoded[1:33]
                    # Pad to 64 bytes for seed
                    seed = private_key_bytes + b"\x00" * 32
                    self.master_xprv = bsv.hd.master_xprv_from_seed(seed)
                else:
                    raise ValueError("Invalid xprv format")

            self.mnemonic = None
            print("✓ Successfully loaded wallet from xprv")
            print(f"✓ Master xprv: {self.master_xprv}")
            return True

        except Exception as e:
            print(f"✗ Error loading from xprv: {e}")
            return False

    def _base58_decode(self, s: str) -> bytes:
        """Decode base58 string"""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for char in s:
            num = num * 58 + alphabet.index(char)

        # Convert to bytes
        hex_str = hex(num)[2:].rstrip("L")
        if len(hex_str) % 2:
            hex_str = "0" + hex_str
        return bytes.fromhex(hex_str)

    def get_master_xpub(self) -> Optional[str]:
        """Get master extended public key"""
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
        Derive a single key from derivation path
        Returns (private_key_wif, public_key_hex, address)
        """
        if not self.master_xprv:
            print("✗ No wallet loaded")
            return None

        try:
            # Parse derivation path
            path_parts = derivation_path.strip().split("/")
            if path_parts[0] != "m":
                raise ValueError("Derivation path must start with 'm'")

            # Start with master key
            current_key = self.master_xprv

            # Derive child keys
            for part in path_parts[1:]:
                if part.endswith("'") or part.endswith("h"):
                    # Hardened derivation
                    index = int(part[:-1]) | 0x80000000
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

            return wif, public_key_hex, address

        except Exception as e:
            print(f"✗ Error deriving key for path {derivation_path}: {e}")
            return None

    def derive_keys_range(
        self, base_path: str, start_index: int, end_index: int
    ) -> List[Tuple[str, str, str, str]]:
        """
        Derive a range of keys from base path
        Returns list of (derivation_path, private_key_wif, public_key_hex, address)
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

                return results
            else:
                # Manual derivation when no mnemonic is available
                results = []

                # Parse base path to get the key at that level
                base_parts = base_path.strip().split("/")
                if base_parts[0] != "m":
                    raise ValueError("Base path must start with 'm'")

                # Derive to the base path
                current_key = self.master_xprv
                for part in base_parts[1:]:
                    if part.endswith("'") or part.endswith("h"):
                        index = int(part[:-1]) | 0x80000000
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

                return results

        except Exception as e:
            print(f"✗ Error deriving key range: {e}")
            return []

    def generate_new_wallet(self, entropy: Optional[str] = None) -> bool:
        """Generate a new wallet from entropy"""
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


def print_menu():
    """Print the main menu"""
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


def main():
    """Main application loop"""
    wallet = HDWalletTool()

    while True:
        print_menu()
        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":
            print("\n--- Load from Mnemonic ---")
            mnemonic = input("Enter mnemonic seed phrase: ").strip()
            if mnemonic:
                wallet.load_from_mnemonic(mnemonic)
            else:
                print("✗ Empty mnemonic provided")

        elif choice == "2":
            print("\n--- Load from xprv ---")
            xprv = input("Enter master private key (xprv): ").strip()
            if xprv:
                wallet.load_from_xprv(xprv)
            else:
                print("✗ Empty xprv provided")

        elif choice == "3":
            print("\n--- Generate New Wallet ---")
            entropy = input("Enter entropy (hex, or press Enter for random): ").strip()
            if not entropy:
                entropy = None
            wallet.generate_new_wallet(entropy)

        elif choice == "4":
            print("\n--- Master xpub ---")
            wallet.get_master_xpub()

        elif choice == "5":
            print("\n--- Derive Single Key ---")
            path = input("Enter derivation path (e.g., m/0/1234): ").strip()
            if path:
                wallet.derive_single_key(path)
            else:
                print("✗ Empty path provided")

        elif choice == "6":
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

        elif choice == "7":
            print("\nGoodbye!")
            break

        else:
            print("✗ Invalid choice. Please try again.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    # Example usage for testing
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Running test mode...")

        # Create test wallet
        wallet = HDWalletTool()

        # Test 1: Generate new wallet
        print("\n=== Test 1: Generate New Wallet ===")
        wallet.generate_new_wallet("cd9b819d9c62f0027116c1849e7d497f")

        # Test 2: Get master xpub
        print("\n=== Test 2: Master xpub ===")
        wallet.get_master_xpub()

        # Test 3: Derive single key
        print("\n=== Test 3: Derive Single Key ===")
        wallet.derive_single_key("m/0/1234")

        # Test 4: Derive key range
        print("\n=== Test 4: Derive Key Range ===")
        wallet.derive_keys_range("m/44'/0'/0'", 0, 2)

    else:
        main()
