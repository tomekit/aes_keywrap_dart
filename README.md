# AES keywrap dart
Implementation of RFC 3394 AES key wrapping/unwrapping in Dart

http://www.ietf.org/rfc/rfc3394.txt

This is a symmetric key-encryption algorithm. It should only be used
to encrypt keys (short and globally unique strings).

In documentation, the key used for this kind of algorithm is
often called the KEK (Key-Encryption-Key), to distinguish
it from data encryption keys.

#### Thanks
Thanks to Kurt Rose which is the author of the Python's package: https://github.com/kurtbrose/aes_keywrap which I've used to implement and test my version.