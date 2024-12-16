import 'package:test/test.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptum_dart/cryptum_dart.dart';
import 'package:cryptum_dart/src/message_format.dart';

void main() {
  late Cryptum cryptum;

  setUp(() {
    cryptum = Cryptum();
  });

  group('Format Management', () {
    test('generates valid message format', () {
      final format = cryptum.getFormat();

      expect(format.version, equals(MessageFormat.CURRENT_VERSION));
      expect(format.componentOrder.length, greaterThanOrEqualTo(4));
      expect(format.componentOrder,
          containsAll(['rsaBlock', 'nonce', 'data', 'tag']));
    });

    test('format remains consistent until changed', () {
      final format1 = cryptum.getFormat();
      final format2 = cryptum.getFormat();

      expect(format1.componentOrder, equals(format2.componentOrder));
      expect(format1.paddingSizes, equals(format2.paddingSizes));
    });

    test('can set custom format', () {
      final customFormat = MessageFormat.generateRandom();
      cryptum.setFormat(customFormat);

      final format = cryptum.getFormat();
      expect(format.componentOrder, equals(customFormat.componentOrder));
      expect(format.paddingSizes, equals(customFormat.paddingSizes));
    });
  });

  group('Key Generation', () {
    test('generates valid 4096-bit RSA keypair', () async {
      final keys = await cryptum.generateKey();

      expect(keys.containsKey('private'), true);
      expect(keys.containsKey('public'), true);

      final privateBytes = base64Url.decode(keys['private']!);
      final publicBytes = base64Url.decode(keys['public']!);

      expect(privateBytes.length > 1600, true);
      expect(publicBytes.length > 500, true);
    });

    test('generates unique keys', () async {
      final keys1 = await cryptum.generateKey();
      final keys2 = await cryptum.generateKey();

      expect(keys1['private'], isNot(equals(keys2['private'])));
      expect(keys1['public'], isNot(equals(keys2['public'])));
    });
  });

  group('Encryption', () {
    test('encrypts with format', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));
      final format = MessageFormat.generateRandom();

      final encrypted =
          await cryptum.encryptBlob(testData, keys['public']!, format: format);

      final components = format.extractComponents(encrypted);

      expect(components['rsaBlock']?.length, equals(512));
      expect(components['nonce']?.length, equals(12));
      expect(components['tag']?.length, equals(16));
      expect(components['data'], isNotNull);
    });

    test('different formats produce different layouts', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));

      final format1 = MessageFormat.generateRandom();
      final format2 = MessageFormat.generateRandom();

      final encrypted1 =
          await cryptum.encryptBlob(testData, keys['public']!, format: format1);

      final encrypted2 =
          await cryptum.encryptBlob(testData, keys['public']!, format: format2);

      expect(encrypted1, isNot(equals(encrypted2)));
    });

    test('requires format', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));

      // Create a new Cryptum instance (no format set yet)
      final freshCryptum = Cryptum();

      expect(() => freshCryptum.decryptBlob(Uint8List(0), keys['private']!),
          throwsException);
    });
  });

  group('Decryption', () {
    test('decrypts with matching format', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));
      final format = MessageFormat.generateRandom();

      final encrypted =
          await cryptum.encryptBlob(testData, keys['public']!, format: format);

      final decrypted = await cryptum.decryptBlob(encrypted, keys['private']!,
          format: format);

      expect(decrypted, equals(testData));
    });

    test('fails with mismatched format', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));

      final format1 = MessageFormat.generateRandom();
      final format2 = MessageFormat.generateRandom();

      final encrypted =
          await cryptum.encryptBlob(testData, keys['public']!, format: format1);

      expect(
          () =>
              cryptum.decryptBlob(encrypted, keys['private']!, format: format2),
          throwsException);
    });

    test('handles large data correctly', () async {
      final keys = await cryptum.generateKey();
      final format = MessageFormat.generateRandom();
      final largeData =
          Uint8List.fromList(List<int>.generate(1000, (i) => i % 256));

      final encrypted =
          await cryptum.encryptBlob(largeData, keys['public']!, format: format);

      final decrypted = await cryptum.decryptBlob(encrypted, keys['private']!,
          format: format);

      expect(decrypted, equals(largeData));
    });

    test('detects tampered data', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));
      final format = MessageFormat.generateRandom();

      final encrypted =
          await cryptum.encryptBlob(testData, keys['public']!, format: format);

      // Tamper with the encrypted data
      encrypted[encrypted.length - 1] ^= 1;

      expect(
          () =>
              cryptum.decryptBlob(encrypted, keys['private']!, format: format),
          throwsException);
    });

    test('fails with invalid private key', () async {
      final keys = await cryptum.generateKey();
      final testData = Uint8List.fromList(utf8.encode('Test Message'));
      final format = MessageFormat.generateRandom();

      final encrypted =
          await cryptum.encryptBlob(testData, keys['public']!, format: format);

      expect(
          () => cryptum.decryptBlob(encrypted, 'invalid-key', format: format),
          throwsException);
    });
  });

  group('Format Serialization', () {
    test('serializes and deserializes format correctly', () {
      final originalFormat = MessageFormat.generateRandom();
      final serialized = originalFormat.serialize();
      final deserialized = MessageFormat.deserialize(serialized);

      expect(deserialized.version, equals(originalFormat.version));
      expect(
          deserialized.componentOrder, equals(originalFormat.componentOrder));
      expect(deserialized.paddingSizes, equals(originalFormat.paddingSizes));
    });

    test('different formats produce different serializations', () {
      final format1 = MessageFormat.generateRandom();
      final format2 = MessageFormat.generateRandom();

      final serialized1 = format1.serialize();
      final serialized2 = format2.serialize();

      expect(serialized1, isNot(equals(serialized2)));
    });

    test('handles invalid serialized data', () {
      final invalidData = Uint8List.fromList([1, 2, 3]); // Too short

      expect(
          () => MessageFormat.deserialize(invalidData), throwsFormatException);
    });
  });
}
