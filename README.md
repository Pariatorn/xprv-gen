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
- ✅ **Professional Package Structure**: Well-organized modular codebase
- ✅ **Comprehensive Testing**: 55+ unit tests with 86% code coverage
- ✅ **Professional Development Setup**: Complete linting, formatting, and testing workflow
- ✅ **Console Command**: Easy-to-use `xprv-gen` command after installation

## Project Structure

```
xprv-gen/
├── xprv_gen/              # Main package
│   ├── __init__.py        # Package exports
│   ├── constants.py       # Constants and enums
│   ├── wallet.py          # Core wallet functionality
│   ├── ui.py              # User interface components
│   └── cli.py             # CLI application logic
├── tests/                 # Test suite (55+ tests)
│   ├── test_constants.py  # Constants and enum tests
│   ├── test_wallet.py     # Wallet functionality tests
│   ├── test_ui.py         # UI component tests
│   └── test_cli.py        # CLI application tests
├── requirements.txt       # Runtime dependencies
├── requirements-dev.txt   # Development dependencies
├── pytest.ini            # Test configuration
├── pyproject.toml         # Tool configurations
├── Makefile               # Development automation
└── README.md              # This file
```

## Installation

### Quick Start
```bash
git clone <repository-url>
cd xprv-gen
make install
```

### Manual Installation
1. Clone the repository:
```bash
git clone <repository-url>
cd xprv-gen
```

2. Create virtual environment and install dependencies:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development
```

3. Install the package in development mode:
```bash
pip install -e .
```

## Usage

### Using Console Command (Recommended)

After installation, you can use the `xprv-gen` command directly:

```bash
# Interactive mode
xprv-gen

# Test mode with example data
xprv-gen test
```

### Using Makefile Commands

```bash
# Install dependencies and package
make install

# Run the CLI application
make run-cli

# Run comprehensive test suite
make test

# Run tests with coverage report
make coverage

# Format code (black + isort)
make format

# Run all linters (flake8, pylint, mypy)
make lint

# Clean up cache files
make clean

# View all available commands
make help
```

### Direct Python Usage

```bash
# Interactive mode
python -m xprv_gen.cli

# Test mode
python -m xprv_gen.cli test
```

### Menu Options

1. **Load wallet from mnemonic seed phrase**
   - Supports both BIP39 and Electrum-style mnemonics
   - Automatically detects the format
   - Enhanced validation with detailed error messages

2. **Load wallet from master private key (xprv)**
   - Import from extended private key string
   - Enhanced validation for proper xprv format

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

## Testing

### Test Suite Overview

The project includes a comprehensive test suite with 55+ unit tests:

- **test_constants.py**: Tests for constants and enums
- **test_wallet.py**: Core wallet functionality tests with mocking
- **test_ui.py**: User interface component tests
- **test_cli.py**: CLI application logic tests

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage report
make coverage

# Run tests with detailed output
pytest -v

# Run specific test file
pytest tests/test_wallet.py

# Run tests with coverage and HTML report
pytest --cov=xprv_gen --cov-report=html
```

### Test Quality Metrics

- **Test Coverage**: 86% (excluding test files)
- **Total Tests**: 55+ comprehensive unit tests
- **Mocking**: Extensive use of pytest mocks for external dependencies
- **Test Types**: Unit tests, validation tests, error handling tests

## Development

### Development Setup

This project includes a complete professional development environment:

**Configuration Files:**
- `pytest.ini` - Test configuration and coverage settings
- `pyproject.toml` - Black, isort, and mypy configuration
- `Makefile` - Development automation
- `requirements-dev.txt` - Development dependencies

**Code Quality Tools:**
- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Style guide enforcement
- **pylint**: Code quality analysis
- **mypy**: Static type checking
- **pytest**: Testing framework with coverage

### Development Workflow

1. **Setup**: `make install`
2. **Development**: Edit code
3. **Format**: `make format` 
4. **Lint**: `make lint`
5. **Test**: `make test`
6. **Coverage**: `make coverage`

### Code Quality Standards

- **Pylint Score**: 10.00/10 (perfect)
- **Test Coverage**: 86% minimum
- **Line Length**: ≤88 characters
- **Type Hints**: Full coverage with strict mypy
- **Documentation**: Comprehensive docstrings
- **Testing**: Comprehensive unit test coverage

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

### Package Architecture
- **Modular Design**: Separated concerns into focused modules
- **Single Responsibility**: Each module has a clear purpose
- **Type Safety**: Comprehensive type hints and mypy validation
- **Error Handling**: Robust error handling with detailed messages
- **Testing**: Extensive test coverage with mocking

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

=== Test Results ===
✓ All tests passed successfully!
```

## Requirements

### Runtime Dependencies
- Python 3.13+ (tested)
- bsv-sdk>=1.0.0
- mnemonic>=0.19

### Development Dependencies
- pytest>=7.0.0 (testing framework)
- pytest-cov>=4.0.0 (coverage reporting)
- pytest-mock>=3.10.0 (mocking support)
- black>=23.0.0 (code formatting)
- isort>=5.12.0 (import sorting)
- flake8>=6.0.0 (style checking)
- pylint>=2.17.0 (code quality)
- mypy>=1.5.0 (type checking)

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please follow the development workflow:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make format` and `make lint` 
5. Ensure all tests pass with `make test`
6. Maintain test coverage with `make coverage`
7. Submit a Pull Request

## Support

For issues and questions, please open an issue on the GitHub repository.

---

**Remember**: This tool handles sensitive cryptographic material. Always verify the integrity of the code and use it responsibly!
