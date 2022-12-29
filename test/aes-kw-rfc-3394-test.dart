import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:test/test.dart';
import '../aes-kw-rfc-3394.dart';

Uint8List randomBytes(int length) {
  Uint8List buffer = new Uint8List(length);
  Random range = new Random.secure();

  for (int i = 0; i < length; i++) {
    buffer[i] = range.nextInt(256);
  }

  return buffer;
}

void main() {

  final base64MasterKey = "+Hv/rT8HPG+Qmk3zhV2NDA==";

  test('unwrap', () async {
    final encryptedKey = "8IK5l6NGSudK/b57goLjZ6ePvfHj+w29D7rle8ShLCLdl0Yy5irmtw==";
    final unwrappedKey = AesKwRfc3394.unwrap(encryptedKey, base64MasterKey);
    final expectedUnwrappedKey = base64Decode("QI3nwnUUehMVJxPbJrpEqu5lnc16zHhD0MDPlhu0/jk=");
    assert(IterableEquality().equals(unwrappedKey, expectedUnwrappedKey));
  });

  test('wrap', () async {
    final wrappingKey = base64Decode("QI3nwnUUehMVJxPbJrpEqu5lnc16zHhD0MDPlhu0/jk=");
    final wrappedKey = base64Encode(AesKwRfc3394.wrap(wrappingKey, base64MasterKey));
    final expectedWrappedKey = "8IK5l6NGSudK/b57goLjZ6ePvfHj+w29D7rle8ShLCLdl0Yy5irmtw==";

    assert(wrappedKey == expectedWrappedKey);
  });

  test('integrityMany', () async {
    for (int i = 0; i < 10000; i++) {
      final unwrappedKey = randomBytes(32);
      final wrappedKeyGcm = AesKwRfc3394.wrap(unwrappedKey, base64MasterKey);
      final unwrappedKeyGcm = AesKwRfc3394.unwrap(base64Encode(wrappedKeyGcm), base64MasterKey);

      assert(base64Encode(unwrappedKey) == base64Encode(unwrappedKeyGcm));
    }
  });

  test('wrapInvalidIv', () async {
    final unwrappedKey = base64Decode("MyWvyzi+AQ7zZ3wVJktmssvn3wARICKvZEwRE6uBDUU=");
    final wrappedKey = AesKwRfc3394.wrap(unwrappedKey, base64MasterKey);
    final wrappedKeyBase64 = base64Encode(wrappedKey);
    final expectedWrappedKey = "ABN90fG6x+Tn0xXPTX6Z9J8U4ooYgWwgqhHVW7BHNC6V7C0OqeJ/cQ==";
    assert(wrappedKeyBase64 == expectedWrappedKey);
  });


  // This was failing with: Invalid argument(s): Input buffer too short
  test('wrapBufferTooSmallIssue', () async {
    final unwrappedKey = base64Decode("ygKG1UHTho96BZYlU4+vVNiw8MljbALzmc/ItrHPTAw=");
    final wrappedKey = AesKwRfc3394.wrap(unwrappedKey, base64MasterKey);
    final wrappedKeyBase64 = base64Encode(wrappedKey);
    final expectedWrappedKey = "WjIlCIXgXbKP515KTu5etbX9gyAdT1DbdGQEESWY80cuIpafxpk6sA==";
    assert(wrappedKeyBase64 == expectedWrappedKey);
  });

  test('unwrapBufferTooSmallIssue', () async { // 15 bytes ciphertext if not padded
    final encryptedKey = "Kfm9xsiy7Tpnzp+xD6jSinUnGZaIAfqWV/Dw1tn3XuSPTEpPyxIy0Q==";
    final unwrappedKey = AesKwRfc3394.unwrap(encryptedKey, base64MasterKey);
    final expectedUnwrappedKey = base64Decode("QwocrQv7pgVm76EV3oj8ZUNIuxziPh+q2Gb3maTXBpE=");
    assert(IterableEquality().equals(unwrappedKey, expectedUnwrappedKey));
  });

  test('unwrapBufferTooSmallIssue2', () async { // 14 bytes ciphertext if not padded
    final wrappedKey = "DNKlrcKnBEYJ6R6zNEJCOoV9Weo/HYJEOozRbLYdhuzOS8HlzgUp2w==";
    final unwrappedKey = AesKwRfc3394.unwrap(wrappedKey, base64MasterKey);
    final unwrappedKeyBase64 = base64Encode(unwrappedKey);
    final expectedUnwrappedKey = "ZqusL9I4IACtnDBtH6bIg3s73u9s0BFIIBP5huaALZU=";
    assert(unwrappedKeyBase64 == expectedUnwrappedKey);
  });

  test('integrity', () {
    final encryptedKey = "8IK5l6NGSudK/b57goLjZ6ePvfHj+w29D7rle8ShLCLdl0Yy5irmtw==";
    final unwrappedKey = AesKwRfc3394.unwrap(encryptedKey, base64MasterKey);

    final wrappedKey = AesKwRfc3394.wrap(unwrappedKey, base64MasterKey);
    final wrappedKeyBase64 = base64Encode(wrappedKey);
    assert(encryptedKey == wrappedKeyBase64);
  });
}
