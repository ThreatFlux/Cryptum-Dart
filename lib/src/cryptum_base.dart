import 'dart:typed_data';
import 'dart:convert';
import 'dart:math' show Random;
import 'package:pointycastle/export.dart';
import 'package:cryptum_dart/src/message_format.dart';
import 'package:cryptum_dart/src/rsa_utils.dart';
import 'package:cryptum_dart/src/crypto_operations.dart';

/// Main class for the Cryptum library
class Cryptum {
  MessageFormat? _currentFormat;

  /// Generates a new RSA key pair
  Future<Map<String, String>> generateKey() async {
    final secureRandom = FortunaRandom();
    final seedSource = Random.secure();
    final seeds = List<int>.generate(32, (i) => seedSource.nextInt(256));
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    final keyParams = RSAKeyGeneratorParameters(
      BigInt.parse('65537'),
      4096,
      64,
    );

    final keyGen = RSAKeyGenerator();
    keyGen.init(ParametersWithRandom(keyParams, secureRandom));

    final pair = keyGen.generateKeyPair();
    final publicKey = pair.publicKey as RSAPublicKey;
    final privateKey = pair.privateKey as RSAPrivateKey;

    final privateKeyDer = RSAUtils.encodeRSAPrivateKeyPKCS8(privateKey);
    final publicKeyDer = RSAUtils.encodeRSAPublicKeyX509(publicKey);

    return {
      'private': base64Url.encode(privateKeyDer),
      'public': base64Url.encode(publicKeyDer),
    };
  }

  /// Gets the current message format or generates a new one
  MessageFormat getFormat() {
    _currentFormat ??= MessageFormat.generateRandom();
    return _currentFormat!;
  }

  /// Sets the message format to use for encryption/decryption
  void setFormat(MessageFormat format) {
    _currentFormat = format;
  }

  /// Encrypts data using RSA-OAEP and AES-GCM
  Future<Uint8List> encryptBlob(Uint8List rawData, String publicKeyString,
      {MessageFormat? format}) async {
    final messageFormat = format ?? getFormat();
    return CryptoOperations.encryptBlob(
        rawData, publicKeyString, messageFormat);
  }

  /// Decrypts data using RSA-OAEP and AES-GCM
  Future<Uint8List> decryptBlob(
      Uint8List encryptedData, String privateKeyString,
      {MessageFormat? format}) async {
    final messageFormat = format ?? _currentFormat;
    if (messageFormat == null) {
      throw Exception('No message format specified or set');
    }
    return CryptoOperations.decryptBlob(
        encryptedData, privateKeyString, messageFormat);
  }
}
