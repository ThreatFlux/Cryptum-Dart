import 'dart:typed_data';
import 'dart:math' show Random;

class MessageFormat {
  static const int CURRENT_VERSION = 1;
  static const int RSA_KEY_SIZE = 512;
  static const int NONCE_SIZE = 12;
  static const int TAG_SIZE = 16;

  static const Map<String, int> COMPONENTS = {
    'version': 4,
    'rsaBlock': 512,
    'nonce': 12,
    'data': -1,
    'tag': 16,
    'padding': -1
  };

  final List<String> componentOrder;
  final Map<String, int> paddingSizes;
  final int version;

  MessageFormat({
    required this.componentOrder,
    required this.paddingSizes,
    this.version = CURRENT_VERSION,
  }) {
    if (!componentOrder.contains('rsaBlock') ||
        !componentOrder.contains('nonce') ||
        !componentOrder.contains('data') ||
        !componentOrder.contains('tag')) {
      throw FormatException('Missing required components');
    }
  }

  static MessageFormat generateRandom() {
    final random = Random.secure();
    final required = ['rsaBlock', 'nonce', 'data', 'tag'];
    required.shuffle(random);
    final padding = Map<String, int>.fromEntries(
        required.map((c) => MapEntry(c, 8 + random.nextInt(25))));
    return MessageFormat(
        componentOrder: required,
        paddingSizes: padding,
        version: CURRENT_VERSION);
  }

  Uint8List serialize() {
    final buffer = BytesBuilder();
    buffer.addByte(version);
    buffer.addByte(componentOrder.length);
    for (final component in componentOrder) {
      buffer.addByte(COMPONENTS.keys.toList().indexOf(component));
    }
    for (final component in componentOrder) {
      buffer.addByte(paddingSizes[component] ?? 0);
    }
    return buffer.takeBytes();
  }

  static MessageFormat deserialize(Uint8List bytes) {
    if (bytes.length < 2) throw FormatException('Invalid format data');

    var position = 0;
    final version = bytes[position++];
    if (version != CURRENT_VERSION) {
      throw FormatException('Unsupported format version');
    }

    final componentCount = bytes[position++];
    if (componentCount < 4) throw FormatException('Invalid component count');

    final components = COMPONENTS.keys.toList();
    final order = <String>[];
    for (var i = 0; i < componentCount; i++) {
      if (position >= bytes.length) {
        throw FormatException('Format data truncated');
      }
      final idx = bytes[position++];
      if (idx >= components.length) {
        throw FormatException('Invalid component index');
      }
      order.add(components[idx]);
    }

    final padding = <String, int>{};
    for (var i = 0; i < componentCount; i++) {
      if (position >= bytes.length) {
        throw FormatException('Format data truncated');
      }
      padding[order[i]] = bytes[position++];
    }

    return MessageFormat(
        componentOrder: order, paddingSizes: padding, version: version);
  }

  Uint8List formatMessage({
    required Uint8List rsaBlock,
    required Uint8List nonce,
    required Uint8List data,
    required Uint8List tag,
  }) {
    if (rsaBlock.length != RSA_KEY_SIZE) {
      throw FormatException('Invalid RSA block size');
    }
    if (nonce.length != NONCE_SIZE) {
      throw FormatException('Invalid nonce size');
    }
    if (tag.length != TAG_SIZE) {
      throw FormatException('Invalid tag size');
    }

    final components = {
      'rsaBlock': rsaBlock,
      'nonce': nonce,
      'data': data,
      'tag': tag,
    };

    final buffer = BytesBuilder();
    final random = Random.secure();

    // Now build the message
    for (var i = 0; i < componentOrder.length; i++) {
      final component = componentOrder[i];
      buffer.add(components[component]!);

      // Add padding for all components
      final padSize = paddingSizes[component] ?? 0;
      if (padSize > 0) {
        buffer.add(Uint8List.fromList(
            List<int>.generate(padSize, (i) => random.nextInt(256))));
      }
    }

    return buffer.takeBytes();
  }

  Map<String, Uint8List> extractComponents(Uint8List message) {
    final components = <String, Uint8List>{};
    var position = 0;

    print('Message length: ${message.length}');
    print('Component order: $componentOrder');

    // Calculate total fixed size and data size
    var totalFixedSize = 0;
    var totalPaddingSize = 0;

    for (final component in componentOrder) {
      final size = COMPONENTS[component]!;
      if (size != -1) {
        totalFixedSize += size;
        print('Adding fixed size for $component: $size');
      }

      // Add padding size for all components
      final padding = paddingSizes[component] ?? 0;
      totalPaddingSize += padding;
      if (component != 'data') {
        print('Adding padding for $component: $padding');
      }
    }

    print('Total fixed size: $totalFixedSize');
    print('Total padding size: $totalPaddingSize');

    // Calculate data size
    final dataSize = message.length - totalFixedSize - totalPaddingSize;
    if (dataSize < 0) {
      throw FormatException('Invalid message length');
    }

    // Process components
    for (final component in componentOrder) {
      print('Processing component $component at position $position');

      // Extract component
      final size = component == 'data' ? dataSize : COMPONENTS[component]!;
      if (position + size > message.length) {
        throw FormatException(
            'Message too short for component $component (need ${position + size} bytes, have ${message.length})');
      }

      components[component] = message.sublist(position, position + size);
      position += size;
      print('Extracted component $component, new position: $position');

      // Add padding
      final padding = paddingSizes[component] ?? 0;
      if (padding > 0) {
        if (position + padding > message.length) {
          throw FormatException(
              'Message too short for padding after $component');
        }
        position += padding;
        print('Added padding $padding, new position: $position');
      }
    }

    // Final length check
    if (position != message.length) {
      throw FormatException('Message length mismatch');
    }

    return components;
  }
}
