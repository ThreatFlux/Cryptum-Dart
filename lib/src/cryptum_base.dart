import 'dart:typed_data';
import 'dart:convert';
import 'dart:math' show Random;
import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:cryptum_dart/src/message_format.dart';

class Cryptum {
  MessageFormat? _currentFormat;

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

    final privateKeyDer = _encodeRSAPrivateKeyPKCS8(privateKey);
    final publicKeyDer = _encodeRSAPublicKeyX509(publicKey);

    return {
      'private': base64Url.encode(privateKeyDer),
      'public': base64Url.encode(publicKeyDer),
    };
  }

  MessageFormat getFormat() {
    _currentFormat ??= MessageFormat.generateRandom();
    return _currentFormat!;
  }

  void setFormat(MessageFormat format) {
    _currentFormat = format;
  }

  Future<Map<String, dynamic>> prepareEncryption(String publicKeyString) async {
    try {
      // Generate 32-byte AES session key
      final sessionKey = Uint8List.fromList(
          List<int>.generate(32, (i) => Random.secure().nextInt(256)));

      // Decode the base64 public key
      final publicKeyBytes = base64Url.decode(publicKeyString);
      final publicKey = _decodeRSAPublicKeyX509(publicKeyBytes);

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

  Future<Uint8List> encryptBlob(Uint8List rawData, String publicKeyString,
      {MessageFormat? format}) async {
    try {
      // Use provided format or current/new format
      final messageFormat = format ?? getFormat();

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

  Future<Uint8List> decryptBlob(
      Uint8List encryptedData, String privateKeyString,
      {MessageFormat? format}) async {
    try {
      final messageFormat = format ?? _currentFormat;
      if (messageFormat == null) {
        throw Exception('No message format specified or set');
      }

      // Extract components using format
      final components = messageFormat.extractComponents(encryptedData);

      final encSessionKey = components['rsaBlock']!;
      final nonce = components['nonce']!;
      final cipherText = components['data']!;
      final tag = components['tag']!;

      // Decrypt session key
      final privateKeyBytes = base64Url.decode(privateKeyString);
      final privateKey = _decodeRSAPrivateKeyPKCS8(privateKeyBytes);

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
      if (!_compareUint8Lists(tag, cipher.mac)) {
        throw Exception('Message authentication failed - data may be tampered');
      }

      return plainText;
    } catch (e) {
      throw Exception('Decryption failed: ${e.toString()}');
    }
  }

  bool _compareUint8Lists(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  Uint8List _encodeRSAPrivateKeyPKCS8(RSAPrivateKey key) {
    try {
      // Extract key components
      final n = key.n;
      final publicExponent = key.publicExponent;
      final privateExponent = key.privateExponent;
      final p = key.p;
      final q = key.q;

      // Validate all components are present
      if ([n, publicExponent, privateExponent, p, q].any((e) => e == null)) {
        throw FormatException('Invalid RSA private key: missing components');
      }

      var version = ASN1Integer(BigInt.zero);
      var algorithm = ASN1Sequence()
        ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        ..add(ASN1Null());

      var privateKeyContent = ASN1Sequence()
        ..add(ASN1Integer(BigInt.zero))
        ..add(ASN1Integer(n!))
        ..add(ASN1Integer(publicExponent!))
        ..add(ASN1Integer(privateExponent!))
        ..add(ASN1Integer(p!))
        ..add(ASN1Integer(q!))
        ..add(ASN1Integer(privateExponent % (p - BigInt.one)))
        ..add(ASN1Integer(privateExponent % (q - BigInt.one)))
        ..add(ASN1Integer(q.modInverse(p)));

      var topLevelSeq = ASN1Sequence()
        ..add(version)
        ..add(algorithm)
        ..add(ASN1OctetString(privateKeyContent.encodedBytes));

      return topLevelSeq.encodedBytes;
    } catch (e) {
      throw FormatException(
          'Failed to encode RSA private key: ${e.toString()}');
    }
  }

  Uint8List _encodeRSAPublicKeyX509(RSAPublicKey key) {
    try {
      // Extract key components
      final n = key.n;
      final publicExponent = key.publicExponent;

      // Validate all components are present
      if ([n, publicExponent].any((e) => e == null)) {
        throw FormatException('Invalid RSA public key: missing components');
      }

      var algorithm = ASN1Sequence()
        ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        ..add(ASN1Null());

      var publicKeySeq = ASN1Sequence()
        ..add(ASN1Integer(n!))
        ..add(ASN1Integer(publicExponent!));

      var topLevelSeq = ASN1Sequence()
        ..add(algorithm)
        ..add(ASN1BitString(publicKeySeq.encodedBytes));

      return topLevelSeq.encodedBytes;
    } catch (e) {
      throw FormatException('Failed to encode RSA public key: ${e.toString()}');
    }
  }

  RSAPublicKey _decodeRSAPublicKeyX509(Uint8List bytes) {
    try {
      final asn1Parser = ASN1Parser(bytes);
      final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
      final publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;
      final publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
      final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;

      final modulusElement = publicKeySeq.elements[0] as ASN1Integer;
      final exponentElement = publicKeySeq.elements[1] as ASN1Integer;

      final modulus = modulusElement.valueAsBigInteger;
      final exponent = exponentElement.valueAsBigInteger;

      if (modulus == null || exponent == null) {
        throw FormatException('Invalid RSA public key parameters');
      }

      return RSAPublicKey(modulus, exponent);
    } catch (e) {
      throw FormatException('Failed to decode RSA public key: ${e.toString()}');
    }
  }

  RSAPrivateKey _decodeRSAPrivateKeyPKCS8(Uint8List bytes) {
    try {
      final asn1Parser = ASN1Parser(bytes);
      final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
      final versionElement = topLevelSeq.elements[0] as ASN1Integer;

      final version = versionElement.valueAsBigInteger;
      if (version != BigInt.zero) {
        throw FormatException('Unsupported PKCS8 version');
      }

      final privateKeyOctetString = topLevelSeq.elements[2] as ASN1OctetString;
      final privateKeyAsn = ASN1Parser(privateKeyOctetString.contentBytes());
      final privateKeySeq = privateKeyAsn.nextObject() as ASN1Sequence;
      final keyVersionElement = privateKeySeq.elements[0] as ASN1Integer;

      final keyVersion = keyVersionElement.valueAsBigInteger;
      if (keyVersion != BigInt.zero) {
        throw FormatException('Unsupported RSA private key version');
      }

      final modulusElement = privateKeySeq.elements[1] as ASN1Integer;
      final privateExponentElement = privateKeySeq.elements[3] as ASN1Integer;
      final pElement = privateKeySeq.elements[4] as ASN1Integer;
      final qElement = privateKeySeq.elements[5] as ASN1Integer;

      final modulus = modulusElement.valueAsBigInteger;
      final privateExponent = privateExponentElement.valueAsBigInteger;
      final p = pElement.valueAsBigInteger;
      final q = qElement.valueAsBigInteger;

      // Since these values are non-nullable, we only need to validate they exist
      if ([modulus, privateExponent, p, q].any((e) => e == null)) {
        throw FormatException('Invalid RSA private key parameters');
      }

      return RSAPrivateKey(modulus!, privateExponent!, p!, q!);
    } catch (e) {
      throw FormatException(
          'Failed to decode RSA private key: ${e.toString()}');
    }
  }
}
