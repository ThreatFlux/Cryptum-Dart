import 'dart:typed_data';
import 'dart:convert';
import 'package:cryptum_dart/cryptum_dart.dart';
import 'package:cryptum_dart/src/message_format.dart';

void main() async {
  // Initialize Cryptum instances (simulating two clients)
  final alice = Cryptum();
  final bob = Cryptum();

  try {
    // Generate key pairs for both parties
    final aliceKeys = await alice.generateKey();
    final bobKeys = await bob.generateKey();

    print('Keys generated successfully');

    // Create a message
    final message = 'Hello, this is a secret message!';
    final messageBytes = Uint8List.fromList(utf8.encode(message));

    // Generate and exchange formats (in real-world this would be part of handshake)
    final aliceFormat = MessageFormat.generateRandom();
    final bobFormat = MessageFormat.generateRandom();

    print('\nOriginal message: $message');

    // Alice encrypts message for Bob using negotiated format
    final encrypted = await alice.encryptBlob(
      messageBytes,
      bobKeys['public']!,
      format: aliceFormat,
    );

    print('Message encrypted successfully');

    // Bob decrypts message using same format
    final decrypted = await bob.decryptBlob(
      encrypted,
      bobKeys['private']!,
      format: aliceFormat,
    );

    final decryptedMessage = utf8.decode(decrypted);
    print('Decrypted message: $decryptedMessage');

    // Demonstrate format mismatch handling
    try {
      await bob.decryptBlob(
        encrypted,
        bobKeys['private']!,
        format: bobFormat, // Using wrong format
      );
    } catch (e) {
      print('\nExpected error when using mismatched format: ${e.toString()}');
    }

    // Demonstrate tamper detection
    try {
      // Try to decrypt a message encrypted with Alice's public key using Bob's private key
      final tamperedMessage = await alice.encryptBlob(
        messageBytes,
        aliceKeys['public']!, // Using Alice's public key instead of Bob's
        format: aliceFormat,
      );

      await bob.decryptBlob(
        tamperedMessage,
        bobKeys['private']!, // Using Bob's private key
        format: aliceFormat,
      );
    } catch (e) {
      print('Expected error when using mismatched keys: ${e.toString()}');
    }
  } catch (e) {
    print('Error: ${e.toString()}');
  }
}
