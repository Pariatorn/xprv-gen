# BSV HD Wallet Key Derivation Tool

A Python tool for offline derivation of Bitcoin SV (BSV) wallet keys from either seed phrases (mnemonics) or master private keys (xprv). This tool supports both BIP39 and Electrum-style mnemonic formats and is designed for secure, offline key generation and management.

## ⚠️ IMPORTANT DISCLAIMERS

**🚨 SECURITY WARNING**: 
- This tool is provided "AS IS" without any warranty
- We take **NO RESPONSIBILITY** for any loss of funds, damages, or issues arising from the use of this software
- Use at your own risk and always test with small amounts first
- Keep your seed phrases and private keys secure and never share them

**🚨 EXAMPLE FILES WARNING**:
- **NEVER USE** the example mnemonic or xprv provided in `example_mnemonic.txt` and `example_xprv.txt`
- These are PUBLIC examples and using them WILL result in loss of funds
- Always generate your own secure, random mnemonics for real use

## Features

- ✅ **Dual Format Support**: Works with both BIP39 and Electrum-style mnemonics
- ✅ **Offline Operation**: Completely offline key derivation for enhanced security
- ✅ **Multiple Input Methods**: Load from mnemonic seed phrase or master private key (xprv)
- ✅ **Flexible Key Derivation**: Support for custom BIP32 derivation paths
- ✅ **Batch Generation**: Generate multiple keys in ranges
- ✅ **ElectrumSV Compatible**: Compatible with ElectrumSV wallet format
- ✅ **Interactive CLI**: User-friendly command-line interface

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd xprv-gen
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Interactive Mode
```bash
python3 xprv-gen.py
```

### Test Mode
```bash
python3 xprv-gen.py test
```

### Menu Options

1. **Load wallet from mnemonic seed phrase**
   - Supports both BIP39 and Electrum-style mnemonics
   - Automatically detects the format

2. **Load wallet from master private key (xprv)**
   - Import from extended private key string

3. **Generate new wallet**
   - Create a new random wallet with optional entropy

4. **Show master xpub**
   - Display the master extended public key

5. **Derive single key from path**
   - Generate a specific key using BIP32 derivation path
   - Example: `m/0/1234`

6. **Derive key range**
   - Generate multiple keys in a range
   - Example: `m/44'/0'/0'` indices 0-10

## Supported Formats

### BIP39 Mnemonics
- Standard 12-24 word seed phrases
- Includes built-in checksum validation
- Compatible with most hardware wallets

### Electrum-Style Mnemonics
- Electrum's proprietary format
- Uses HMAC-SHA512 validation with "Seed version" key
- Compatible with ElectrumSV wallet

## Technical Details

### Key Derivation
- Uses BIP32 hierarchical deterministic (HD) key derivation
- Supports both hardened and non-hardened derivation
- Compatible with standard derivation paths like `m/44'/0'/0'`

### Seed Generation
- **BIP39**: Uses PBKDF2 with "mnemonic" salt
- **Electrum**: Uses PBKDF2 with "electrum" salt
- Both use 2048 iterations for key stretching

## Security Best Practices

1. **Offline Usage**: Run this tool on an air-gapped computer
2. **Secure Storage**: Store seed phrases in secure, offline locations
3. **Test First**: Always test with small amounts before trusting large sums
4. **Multiple Backups**: Keep multiple secure backups of your seed phrases
5. **Never Share**: Never share your seed phrases or private keys

## Example Output

```
Testing mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
Expected xprv: xprv9s21ZrQH143K...
✓ Valid BIP39 mnemonic
✓ Successfully loaded wallet from mnemonic
✓ Master xprv: xprv9s21ZrQH143K...
Match: True
```

## Requirements

- Python 3.6+
- bsv-sdk library
- Standard Python libraries (hashlib, hmac, etc.)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please open an issue on the GitHub repository.

---

**Remember**: This tool handles sensitive cryptographic material. Always verify the integrity of the code and use it responsibly!
