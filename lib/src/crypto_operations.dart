import 'dart:typed_data';
import 'dart:convert';
import 'dart:math' show Random;
import 'package:pointycastle/export.dart';
import 'package:cryptum_dart/src/message_format.dart';
import 'package:cryptum_dart/src/rsa_utils.dart';

/// Utility class for cryptographic operations
class CryptoOperations {
  /// Compares two Uint8Lists in a constant-time manner
  static bool compareUint8Lists(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Prepares encryption components using a public key
  static Future<Map<String, dynamic>> prepareEncryption(String publicKeyString) async {
    try {
      // Generate 32-byte AES session key
      final sessionKey = Uint8List.fromList(
          List<int>.generate(32, (i) => Random.secure().nextInt(256)));

      // Decode the base64 public key
      final publicKeyBytes = base64Url.decode(publicKeyString);
      final publicKey = RSAUtils.decodeRSAPublicKeyX509(publicKeyBytes);

      // Setup RSA OAEP with SHA-1 and MGF1
      final rsaEngine = RSAEngine()
        ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

      final rsaEncrypter = OAEPEncoding(rsaEngine)
        ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));

      // Encrypt session key
      final encryptedSessionKey = rsaEncrypter.process(sessionKey);

      // Generate 12-byte nonce
      final nonce = Uint8List.fromList(
          List<int>.generate(12, (i) => Random.secure().nextInt(256)));

      return {
        'sessionKey': sessionKey,
        'encryptedSessionKey': encryptedSessionKey,
        'nonce': nonce,
      };
    } catch (e) {
      throw Exception('Encryption preparation failed: ${e.toString()}');
    }
  }

  /// Encrypts data using RSA-OAEP and AES-GCM
  static Future<Uint8List> encryptBlob(
      Uint8List rawData,
      String publicKeyString,
      MessageFormat messageFormat) async {
    try {
      // Prepare encryption components
      final prep = await prepareEncryption(publicKeyString);
      final sessionKey = prep['sessionKey'] as Uint8List;
      final encryptedSessionKey = prep['encryptedSessionKey'] as Uint8List;
      final nonce = prep['nonce'] as Uint8List;

      // Create GCM cipher
      final cipher = GCMBlockCipher(AESEngine());
      cipher.init(
        true,
        AEADParameters(
          KeyParameter(sessionKey),
          128,
          nonce,
          Uint8List(0),
        ),
      );

      // Encrypt data
      final cipherText = cipher.process(rawData);

      // Get tag
      final tag = cipher.mac;

      // Format message according to format
      return messageFormat.formatMessage(
        rsaBlock: encryptedSessionKey,
        nonce: nonce,
        data: cipherText,
        tag: tag,
      );
    } catch (e) {
      throw Exception('Encryption failed: ${e.toString()}');
    }
  }

  /// Decrypts data using RSA-OAEP and AES-GCM
  static Future<Uint8List> decryptBlob(
      Uint8List encryptedData,
      String privateKeyString,
      MessageFormat messageFormat) async {
    try {
      // Extract components using format
      final components = messageFormat.extractComponents(encryptedData);

      final encSessionKey = components['rsaBlock']!;
      final nonce = components['nonce']!;
      final cipherText = components['data']!;
      final tag = components['tag']!;

      // Decrypt session key
      final privateKeyBytes = base64Url.decode(privateKeyString);
      final privateKey = RSAUtils.decodeRSAPrivateKeyPKCS8(privateKeyBytes);

      // Setup RSA OAEP with SHA-1 and MGF1
      final rsaEngine = RSAEngine()
        ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

      final rsaDecrypter = OAEPEncoding(rsaEngine)
        ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

      final sessionKey = rsaDecrypter.process(encSessionKey);

      // GCM setup
      final params = AEADParameters(
        KeyParameter(sessionKey),
        128,
        nonce,
        Uint8List(0),
      );

      final cipher = GCMBlockCipher(AESEngine())..init(false, params);

      // Process data
      final plainText = cipher.process(cipherText);

      // Verify MAC - Important: Do this BEFORE returning the plaintext
      if (!compareUint8Lists(tag, cipher.mac)) {
        throw Exception('Message authentication failed - data may be tampered');
      }

      return plainText;
    } catch (e) {
      throw Exception('Decryption failed: ${e.toString()}');
    }
  }
}
