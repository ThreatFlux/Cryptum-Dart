# Cryptum Example

This example demonstrates the core functionality of the Cryptum package for secure message encryption and decryption.

## Features Demonstrated

- Key pair generation
- Message encryption and decryption
- Message format handling
- Error handling for format mismatches
- Tamper detection

## Code Walkthrough

The example simulates a secure message exchange between two parties (Alice and Bob):

1. **Initialize Cryptum Instances**
```dart
final alice = Cryptum();
final bob = Cryptum();
```

2. **Generate Key Pairs**
```dart
final aliceKeys = await alice.generateKey();
final bobKeys = await bob.generateKey();
```

3. **Create and Format Message**
```dart
final message = 'Hello, this is a secret message!';
final messageBytes = Uint8List.fromList(utf8.encode(message));
```

4. **Generate Message Formats**
```dart
final aliceFormat = MessageFormat.generateRandom();
final bobFormat = MessageFormat.generateRandom();
```

5. **Encrypt Message**
```dart
final encrypted = await alice.encryptBlob(
  messageBytes,
  bobKeys['public']!,
  format: aliceFormat,
);
```

6. **Decrypt Message**
```dart
final decrypted = await bob.decryptBlob(
  encrypted,
  bobKeys['private']!,
  format: aliceFormat,
);
```

The example also includes error handling demonstrations for:
- Using mismatched message formats
- Attempting to decrypt messages with incorrect keys

## Running the Example

To run this example:

1. Ensure you have the Cryptum package added to your `pubspec.yaml`:
```yaml
dependencies:
  cryptum_dart: ^1.0.0
```

2. Run the example:
```bash
dart run example/cryptum_example.dart
