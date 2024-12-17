# Cryptum-Dart

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/e51d9ddd38344efb882818c277e5f633)](https://app.codacy.com/gh/ThreatFlux/Cryptum-Dart?utm_source=github.com&utm_medium=referral&utm_content=ThreatFlux/Cryptum-Dart&utm_campaign=Badge_Grade)
[![Dart CI/CD](https://github.com/threatflux/Cryptum-Dart/actions/workflows/dart.yml/badge.svg)](https://github.com/threatflux/Cryptum-Dart/actions/workflows/dart.yml)
[![codecov](https://codecov.io/gh/threatflux/Cryptum-Dart/branch/main/graph/badge.svg)](https://codecov.io/gh/threatflux/Cryptum-Dart)
[![pub package](https://img.shields.io/pub/v/cryptum_dart.svg)](https://pub.dev/packages/cryptum_dart)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dart 2.19+](https://img.shields.io/badge/dart-2.19+-blue.svg)](https://dart.dev/get-dart)
[![Code style: lint](https://img.shields.io/badge/style-lint-4BC0F5.svg)](https://pub.dev/packages/lint)

A Dart port of the Cryptum encryption library providing hybrid RSA/AES-GCM encryption with secure session key handling and dynamic format negotiation.

## Features

- 🔐 4096-bit RSA key generation
- 🔄 Hybrid encryption (RSA + AES-GCM)
- 🔑 Secure session key handling
- ✅ Message authentication (GCM)
- 📜 PKCS8/X509 key encoding
- 🎲 Secure random number generation
- 🔀 Dynamic message format negotiation

## Prerequisites

- Dart SDK 2.19 or higher

## Installation

Add this to your `pubspec.yaml`:

```yaml
dependencies:
  cryptum_dart: ^0.0.1
```

Then run:
```bash
dart pub get
```

## Basic Usage

```dart
import 'package:cryptum_dart/cryptum_dart.dart';

void main() async {
  final cryptum = Cryptum();
  
  // Generate key pair
  final keys = await cryptum.generateKey();
  
  // Encrypt data
  final message = Uint8List.fromList(utf8.encode('Secret message'));
  final encrypted = await cryptum.encryptBlob(message, keys['public']!);
  
  // Decrypt data
  final decrypted = await cryptum.decryptBlob(encrypted, keys['private']!);
  print(utf8.decode(decrypted)); // 'Secret message'
}
```

## Advanced Usage

### Format Negotiation

Cryptum supports dynamic message format negotiation for enhanced security:

```dart
final format = MessageFormat.generateRandom();

// Encrypt with format
final encrypted = await cryptum.encryptBlob(
  message, 
  publicKey,
  format: format
);

// Decrypt with same format
final decrypted = await cryptum.decryptBlob(
  encrypted, 
  privateKey,
  format: format
);
```

## Security Features

- 🔒 AES-256 for symmetric encryption
- 🛡️ RSA-4096 for key encryption
- ✔️ GCM authentication
- 🔐 Secure session key generation
- 🛑 Tamper detection
- ⚡ Constant-time MAC comparison
- 🔀 Dynamic message formatting

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/ThreatFlux/Cryptum-Dart.git
cd Cryptum-Dart

# Get dependencies
dart pub get

# Run tests
dart test
```

### Running Tests

```bash
# Run all tests
dart test

# Run with coverage
dart test --coverage=coverage
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## CI/CD

This project uses GitHub Actions for continuous integration and deployment:

- Automated testing on each push and pull request
- Code coverage reporting via Codecov
- Automatic publishing to pub.dev when tests pass
- Code formatting and analysis checks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- **Wyatt Roersma** - *Project Lead* - [GitHub](https://github.com/wroersma)
- **Claude 3.5 Sonnet 20241022** - *Dart Port Development Support*

## Version History

See [CHANGELOG.md](CHANGELOG.md) for all changes.

---

Made with ❤️ by the ThreatFlux team
