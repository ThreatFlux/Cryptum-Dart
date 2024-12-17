import 'dart:typed_data';
import 'dart:math' show Random;

class MessageFormat {
  // Format version for compatibility checks
  static const int CURRENT_VERSION = 1;

  // Component size constants
  static const int RSA_KEY_SIZE = 512;
  static const int NONCE_SIZE = 12;
  static const int TAG_SIZE = 16;

  // Available component types
  static const Map<String, int> COMPONENTS = {
    'version': 4, // Format version number
    'rsaBlock': 512, // Encrypted session key
    'nonce': 12, // GCM nonce
    'data': -1, // Variable length encrypted data
    'tag': 16, // GCM authentication tag
    'padding': -1 // Variable length random padding
  };

  final List<String> componentOrder;
  final Map<String, int> paddingSizes;
  final int version;

  MessageFormat({
    required this.componentOrder,
    required this.paddingSizes,
    this.version = CURRENT_VERSION,
  }) {
    // Validate component order
    if (!componentOrder.contains('rsaBlock') ||
        !componentOrder.contains('nonce') ||
        !componentOrder.contains('data') ||
        !componentOrder.contains('tag')) {
      throw FormatException('Missing required components');
    }
  }

  // Generate a random valid format
  static MessageFormat generateRandom() {
    final random = Random.secure();

    // Always include required components in random order
    final required = ['rsaBlock', 'nonce', 'data', 'tag'];
    required.shuffle(random);

    // Random padding between components (8-32 bytes)
    final padding = Map<String, int>.fromEntries(
        required.map((c) => MapEntry(c, 8 + random.nextInt(25))));

    return MessageFormat(
        componentOrder: required,
        paddingSizes: padding,
        version: CURRENT_VERSION);
  }

  // Serialize format for transmission
  Uint8List serialize() {
    final buffer = BytesBuilder();

    // Write version
    buffer.addByte(version);

    // Write number of components
    buffer.addByte(componentOrder.length);

    // Write component order
    for (final component in componentOrder) {
      buffer.addByte(COMPONENTS.keys.toList().indexOf(component));
    }

    // Write padding sizes
    for (final component in componentOrder) {
      buffer.addByte(paddingSizes[component] ?? 0);
    }

    return buffer.takeBytes();
  }

  // Deserialize received format
  static MessageFormat deserialize(Uint8List bytes) {
    if (bytes.length < 2) {
      throw FormatException('Invalid format data');
    }

    var position = 0;

    // Read version
    final version = bytes[position++];
    if (version != CURRENT_VERSION) {
      throw FormatException('Unsupported format version');
    }

    // Read component count
    final componentCount = bytes[position++];
    if (componentCount < 4) {
      // Must have minimum required components
      throw FormatException('Invalid component count');
    }

    // Read component order
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

    // Read padding sizes
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

  // Format message according to current format
  Uint8List formatMessage({
    required Uint8List rsaBlock,
    required Uint8List nonce,
    required Uint8List data,
    required Uint8List tag,
  }) {
    // Verify component sizes
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

    // Add components in specified order with padding
    for (var i = 0; i < componentOrder.length; i++) {
      final component = componentOrder[i];
      buffer.add(components[component]!);

      // Add padding except after last component
      if (i < componentOrder.length - 1) {
        final padSize = paddingSizes[component] ?? 0;
        final padding = List<int>.generate(padSize, (i) => random.nextInt(256));
        buffer.add(padding);
      }
    }

    return buffer.takeBytes();
  }

  // Extract components from formatted message
  Map<String, Uint8List> extractComponents(Uint8List message) {
    var position = 0;
    final components = <String, Uint8List>{};

    // Extract each component and skip padding
    for (var i = 0; i < componentOrder.length; i++) {
      final component = componentOrder[i];
      final size = COMPONENTS[component] == -1
          ? (i < componentOrder.length - 1
                  ? _findNextComponentPosition(message, position, i)
                  : message.length) -
              position
          : COMPONENTS[component]!;

      components[component] = message.sublist(position, position + size);
      position += size;

      // Skip padding except after last component
      if (i < componentOrder.length - 1) {
        position += paddingSizes[component] ?? 0;
      }
    }

    return components;
  }

  // Helper to find next component position accounting for padding and variable sizes
  int _findNextComponentPosition(
      Uint8List message, int currentPos, int currentIdx) {
    // Find the next fixed-size component
    var nextFixedIdx = currentIdx + 1;
    var totalSize = 0;

    while (nextFixedIdx < componentOrder.length) {
      final nextComponent = componentOrder[nextFixedIdx];
      if (COMPONENTS[nextComponent] != -1) {
        // Found next fixed component
        break;
      }
      nextFixedIdx++;
    }

    if (nextFixedIdx >= componentOrder.length) {
      // No more fixed components, use remaining message length
      return message.length - currentPos;
    }

    // Calculate total size by working backwards from next fixed component
    var pos = message.length;
    for (var i = componentOrder.length - 1; i >= nextFixedIdx; i--) {
      final component = componentOrder[i];
      final size = COMPONENTS[component] ?? 0;
      pos -= size;
      if (i > 0) {
        pos -= paddingSizes[componentOrder[i - 1]] ?? 0;
      }
    }

    return pos - currentPos;
  }
}
