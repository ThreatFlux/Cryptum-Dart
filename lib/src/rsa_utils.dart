import 'dart:typed_data';
import 'package:pointycastle/export.dart';
import 'package:asn1lib/asn1lib.dart';

/// Utility class for RSA key operations
class RSAUtils {
  /// Encodes an RSA private key in PKCS8 format
  static Uint8List encodeRSAPrivateKeyPKCS8(RSAPrivateKey key) {
    try {
      // Extract key components
      final n = key.n;
      final publicExponent = key.publicExponent;
      final privateExponent = key.privateExponent;
      final p = key.p;
      final q = key.q;

      // Validate all components are present
      if (n == null ||
          publicExponent == null ||
          privateExponent == null ||
          p == null ||
          q == null) {
        throw FormatException('Invalid RSA private key: missing components');
      }

      var version = ASN1Integer(BigInt.zero);
      var algorithm = ASN1Sequence()
        ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        ..add(ASN1Null());

      var privateKeyContent = ASN1Sequence()
        ..add(ASN1Integer(BigInt.zero))
        ..add(ASN1Integer(n))
        ..add(ASN1Integer(publicExponent))
        ..add(ASN1Integer(privateExponent))
        ..add(ASN1Integer(p))
        ..add(ASN1Integer(q))
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

  /// Encodes an RSA public key in X509 format
  static Uint8List encodeRSAPublicKeyX509(RSAPublicKey key) {
    try {
      // Extract key components
      final n = key.n;
      final publicExponent = key.publicExponent;

      // Validate components
      if (n == null || publicExponent == null) {
        throw FormatException('Invalid RSA public key: missing components');
      }

      var algorithm = ASN1Sequence()
        ..add(ASN1ObjectIdentifier([1, 2, 840, 113549, 1, 1, 1]))
        ..add(ASN1Null());

      var publicKeySeq = ASN1Sequence()
        ..add(ASN1Integer(n))
        ..add(ASN1Integer(publicExponent));

      var topLevelSeq = ASN1Sequence()
        ..add(algorithm)
        ..add(ASN1BitString(publicKeySeq.encodedBytes));

      return topLevelSeq.encodedBytes;
    } catch (e) {
      throw FormatException('Failed to encode RSA public key: ${e.toString()}');
    }
  }

  /// Decodes an RSA public key from X509 format
  static RSAPublicKey decodeRSAPublicKeyX509(Uint8List bytes) {
    try {
      final asn1Parser = ASN1Parser(bytes);
      final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
      final publicKeyBitString = topLevelSeq.elements[1] as ASN1BitString;
      final publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
      final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;

      final modulusElement = publicKeySeq.elements[0] as ASN1Integer;
      final exponentElement = publicKeySeq.elements[1] as ASN1Integer;

      // Extract components - valueAsBigInteger is non-null after type assertion
      final modulus = modulusElement.valueAsBigInteger;
      final exponent = exponentElement.valueAsBigInteger;

      return RSAPublicKey(modulus, exponent);
    } catch (e) {
      throw FormatException('Failed to decode RSA public key: ${e.toString()}');
    }
  }

  /// Decodes an RSA private key from PKCS8 format
  static RSAPrivateKey decodeRSAPrivateKeyPKCS8(Uint8List bytes) {
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

      // Extract components - valueAsBigInteger is non-null after type assertion
      final modulus = modulusElement.valueAsBigInteger;
      final privateExponent = privateExponentElement.valueAsBigInteger;
      final p = pElement.valueAsBigInteger;
      final q = qElement.valueAsBigInteger;

      return RSAPrivateKey(modulus, privateExponent, p, q);
    } catch (e) {
      throw FormatException(
          'Failed to decode RSA private key: ${e.toString()}');
    }
  }
}
