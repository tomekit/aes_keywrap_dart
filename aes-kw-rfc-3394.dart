import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/ecb.dart';

class AesKwRfc3394 {

  static String iv = "0xa6a6a6a6a6a6a6a6";

  static List<int> unwrap(String wrappedKeyBase64, String masterKeyBase64, {String ivHex = "0xa6a6a6a6a6a6a6a6"}) {

    final kek = base64.decode(masterKeyBase64);
    final wrapped = base64.decode(wrappedKeyBase64);

    final cipher = ECBBlockCipher(AESEngine()) as pc.BlockCipher;
    cipher.init(false, pc.KeyParameter(kek));

    final n = ((wrapped.length/8)-1).floor();

    final R = [[0]];
    for (var i = 1; i < n+1; i++) {
      R.add(wrapped.sublist(i*8, i*8+8));
    }

    final Ainput = wrapped.sublist(0, 8);
    var A = decodeBigInt(Ainput);

    for (var j = 5; j > -1; j--) {
      for (var i = n; i > 0; i--) {
        final ciphertext = encodeBigInt(A^BigInt.from(n*j+i)) + R[i];
        if (ciphertext.length < cipher.blockSize) {
          for (int x = 0; x <= cipher.blockSize-ciphertext.length; x++) {
            ciphertext.insert(0, 0); // Prepend 0 until its 16 bytes long;
          }
        }

        final B = cipher.process(Uint8List.fromList(ciphertext));
        A = decodeBigInt(B.sublist(0, 8));
        R[i] = B.sublist(8);
      }
    }

    final List<int> key = [];
    R.sublist(1).forEach((list) {
      key.addAll(list);
    });

    final keyIv = A;
    final expectedIv = BigInt.parse(ivHex);

    if (keyIv != expectedIv) {
      throw FormatException("Invalid key IV: $keyIv");
    }

    return key;
  }

  static List<int> wrap(List<int> unwrappedKey, String masterKeyBase64, {String ivHex = "0xa6a6a6a6a6a6a6a6"}) {

    final kek = base64.decode(masterKeyBase64);

    final cipher = ECBBlockCipher(AESEngine()) as pc.BlockCipher;
    cipher.init(true, pc.KeyParameter(kek));

    final n = (unwrappedKey.length/8).floor();

    final R = [[0]];
    for (var i = 0; i < n; i++) {
      R.add(unwrappedKey.sublist(i*8, i*8+8));
    }

    var A = BigInt.parse(ivHex);

    for (var j = 0; j < 6; j++) {
      for (var i = 1; i < n+1; i++) {
        final B = cipher.process(Uint8List.fromList(encodeBigInt(A, overridenSize: 8) + R[i]));  // We set overridenSize: 8 to mimic Python's QUAD.pack(). In our case e.g: 71112166732950704 was returning 7 bytes, which made buffer too small later for certain operations.
        A = decodeBigInt(B.sublist(0, 8)) ^ BigInt.from(n*j+i);
        R[i] = B.sublist(8);
      }
    }

    final List<int> key = encodeBigInt(A, overridenSize: 8).toList();
    R.sublist(1).forEach((list) {
      key.addAll(list);
    });

    return key;
  }

  static BigInt decodeBigInt(List<int> bytes) {
    BigInt result = new BigInt.from(0);
    for (int i = 0; i < bytes.length; i++) {
      result += new BigInt.from(bytes[bytes.length - i - 1]) << (8 * i);
    }
    return result;
  }

  static final _byteMask = new BigInt.from(0xff);
  // https://pub.dev/documentation/ed25519_dart_base/latest/ed25519_dart/integerToBytes.html
  static Uint8List encodeBigInt(BigInt number, {int? overridenSize}) {
    // Not handling negative numbers. Decide how you want to do that.

    int size;
    if (overridenSize == null) {
      size = (number.bitLength + 7) >> 3;
    } else {
      size = overridenSize;
    }

    final result = new Uint8List(size);
    for (int i = 0; i < size; i++) {
      result[size - i - 1] = (number & _byteMask).toInt();
      number = number >> 8;
    }
    return result;
  }
}