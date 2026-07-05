// Package-private FFI bindings for Security.framework on macOS.
// Do NOT import this file from outside lib/crypto/.
import 'dart:ffi';
import 'dart:typed_data';

import 'native_alloc.dart' show libcAlloc;

// ── Opaque CF/Sec types ───────────────────────────────────────────────────────
final class SecKeyRefStruct extends Opaque {}

final class SecCertificateRefStruct extends Opaque {}

final class CFDictionaryRefStruct extends Opaque {}

final class CFDataRefStruct extends Opaque {}

final class CFStringRefStruct extends Opaque {}

final class CFErrorRefStruct extends Opaque {}

final class CFArrayRefStruct extends Opaque {}

typedef SecKeyRef = Pointer<SecKeyRefStruct>;
typedef SecCertificateRef = Pointer<SecCertificateRefStruct>;
typedef CFDictionaryRef = Pointer<CFDictionaryRefStruct>;
typedef CFDataRef = Pointer<CFDataRefStruct>;
typedef CFStringRef = Pointer<CFStringRefStruct>;
typedef CFErrorRef = Pointer<CFErrorRefStruct>;
typedef CFArrayRef = Pointer<CFArrayRefStruct>;

// ── Native function signatures ─────────────────────────────────────────────────

// CFRelease
typedef _CFReleaseNative = Void Function(Pointer<Void> cf);
typedef CFReleaseDart = void Function(Pointer<Void> cf);

// SecKeyCreateRandomKey(attributes, error) -> SecKeyRef?
typedef _SecKeyCreateRandomKeyNative =
    SecKeyRef Function(CFDictionaryRef attributes, Pointer<CFErrorRef> error);
typedef SecKeyCreateRandomKeyDart =
    SecKeyRef Function(CFDictionaryRef attributes, Pointer<CFErrorRef> error);

// SecKeyCopyPublicKey(key) -> SecKeyRef
typedef _SecKeyCopyPublicKeyNative = SecKeyRef Function(SecKeyRef key);
typedef SecKeyCopyPublicKeyDart = SecKeyRef Function(SecKeyRef key);

// SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, error) -> CFDataRef?
typedef _SecKeyCopyKeyExchangeResultNative =
    CFDataRef Function(
      SecKeyRef privateKey,
      Pointer<Void> algorithm, // SecKeyAlgorithm = CFStringRef
      SecKeyRef publicKey,
      CFDictionaryRef parameters,
      Pointer<CFErrorRef> error,
    );
typedef SecKeyCopyKeyExchangeResultDart =
    CFDataRef Function(
      SecKeyRef privateKey,
      Pointer<Void> algorithm,
      SecKeyRef publicKey,
      CFDictionaryRef parameters,
      Pointer<CFErrorRef> error,
    );

// SecKeyCreateSignature(key, algorithm, dataToSign, error) -> CFDataRef?
typedef _SecKeyCreateSignatureNative =
    CFDataRef Function(
      SecKeyRef key,
      Pointer<Void> algorithm, // CFStringRef
      CFDataRef dataToSign,
      Pointer<CFErrorRef> error,
    );
typedef SecKeyCreateSignatureDart =
    CFDataRef Function(
      SecKeyRef key,
      Pointer<Void> algorithm,
      CFDataRef dataToSign,
      Pointer<CFErrorRef> error,
    );

// SecKeyVerifySignature
typedef _SecKeyVerifySignatureNative =
    Bool Function(
      SecKeyRef key,
      Pointer<Void> algorithm,
      CFDataRef signedData,
      CFDataRef signature,
      Pointer<CFErrorRef> error,
    );
typedef SecKeyVerifySignatureDart =
    bool Function(
      SecKeyRef key,
      Pointer<Void> algorithm,
      CFDataRef signedData,
      CFDataRef signature,
      Pointer<CFErrorRef> error,
    );

// SecKeyCopyExternalRepresentation(key, error) -> CFDataRef?
typedef _SecKeyCopyExternalRepresentationNative =
    CFDataRef Function(SecKeyRef key, Pointer<CFErrorRef> error);
typedef SecKeyCopyExternalRepresentationDart =
    CFDataRef Function(SecKeyRef key, Pointer<CFErrorRef> error);

// SecKeyCreateWithData(keyData, attributes, error) -> SecKeyRef?
typedef _SecKeyCreateWithDataNative =
    SecKeyRef Function(
      CFDataRef keyData,
      CFDictionaryRef attributes,
      Pointer<CFErrorRef> error,
    );
typedef SecKeyCreateWithDataDart =
    SecKeyRef Function(
      CFDataRef keyData,
      CFDictionaryRef attributes,
      Pointer<CFErrorRef> error,
    );

// CFDataCreate(allocator, bytes, length) -> CFDataRef
typedef _CFDataCreateNative =
    CFDataRef Function(
      Pointer<Void> allocator, // kCFAllocatorDefault = nullptr
      Pointer<Uint8> bytes,
      Int64 length,
    );
typedef CFDataCreateDart =
    CFDataRef Function(
      Pointer<Void> allocator,
      Pointer<Uint8> bytes,
      int length,
    );

// CFDataGetBytePtr(data) -> const UInt8*
typedef _CFDataGetBytePtrNative = Pointer<Uint8> Function(CFDataRef data);
typedef CFDataGetBytePtrDart = Pointer<Uint8> Function(CFDataRef data);

// CFDataGetLength(data) -> CFIndex
typedef _CFDataGetLengthNative = Int64 Function(CFDataRef data);
typedef CFDataGetLengthDart = int Function(CFDataRef data);

// CFDictionaryCreate
typedef _CFDictionaryCreateNative =
    CFDictionaryRef Function(
      Pointer<Void> allocator,
      Pointer<Pointer<Void>> keys,
      Pointer<Pointer<Void>> values,
      Int64 numValues,
      Pointer<Void> keyCallBacks,
      Pointer<Void> valueCallBacks,
    );
typedef CFDictionaryCreateDart =
    CFDictionaryRef Function(
      Pointer<Void> allocator,
      Pointer<Pointer<Void>> keys,
      Pointer<Pointer<Void>> values,
      int numValues,
      Pointer<Void> keyCallBacks,
      Pointer<Void> valueCallBacks,
    );

// CFNumberCreate(allocator, type, valuePtr) -> CFNumberRef
typedef _CFNumberCreateNative =
    Pointer<Void> Function(
      Pointer<Void> allocator,
      Int32 type,
      Pointer<Void> valuePtr,
    );
typedef CFNumberCreateDart =
    Pointer<Void> Function(
      Pointer<Void> allocator,
      int type,
      Pointer<Void> valuePtr,
    );

// CFStringCreateWithCString
typedef _CFStringCreateWithCStringNative =
    CFStringRef Function(
      Pointer<Void> allocator,
      Pointer<Uint8> cStr,
      Uint32 encoding,
    );
typedef CFStringCreateWithCStringDart =
    CFStringRef Function(
      Pointer<Void> allocator,
      Pointer<Uint8> cStr,
      int encoding,
    );

// CFBooleanRef constants are global symbols
// kCFBooleanTrue, kCFBooleanFalse

// ── Constants ─────────────────────────────────────────────────────────────────

// CFStringEncoding
const int kCFStringEncodingUTF8 = 0x08000100;

// CFNumberType: kCFNumberSInt32Type = 3
const int kCFNumberSInt32Type = 3;

// kSecAttrKeyType values (as CFNumber from kSecAttrKeyTypeECSECPrimeRandom)
// We use the CFString constant names from Security.framework
const String kSecAttrKeyTypeECSECPrimeRandom = 'ecsecp256r1'; // symbolic

// SecKeyAlgorithm for ECDH — CFStringRef obtained via framework global symbol.

/// Singleton FFI bindings for Security.framework.
class SecurityFramework {
  SecurityFramework._();

  static final SecurityFramework instance = SecurityFramework._();

  final DynamicLibrary _lib = DynamicLibrary.open(
    '/System/Library/Frameworks/Security.framework/Security',
  );
  final DynamicLibrary _cf = DynamicLibrary.open(
    '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
  );

  late final CFReleaseDart cfRelease = _lib
      .lookupFunction<_CFReleaseNative, CFReleaseDart>('CFRelease');

  late final SecKeyCreateRandomKeyDart secKeyCreateRandomKey = _lib
      .lookupFunction<_SecKeyCreateRandomKeyNative, SecKeyCreateRandomKeyDart>(
        'SecKeyCreateRandomKey',
      );

  late final SecKeyCopyPublicKeyDart secKeyCopyPublicKey = _lib
      .lookupFunction<_SecKeyCopyPublicKeyNative, SecKeyCopyPublicKeyDart>(
        'SecKeyCopyPublicKey',
      );

  late final SecKeyCopyKeyExchangeResultDart secKeyCopyKeyExchangeResult = _lib
      .lookupFunction<
        _SecKeyCopyKeyExchangeResultNative,
        SecKeyCopyKeyExchangeResultDart
      >('SecKeyCopyKeyExchangeResult');

  late final SecKeyCreateSignatureDart secKeyCreateSignature = _lib
      .lookupFunction<_SecKeyCreateSignatureNative, SecKeyCreateSignatureDart>(
        'SecKeyCreateSignature',
      );

  late final SecKeyVerifySignatureDart secKeyVerifySignature = _lib
      .lookupFunction<_SecKeyVerifySignatureNative, SecKeyVerifySignatureDart>(
        'SecKeyVerifySignature',
      );

  late final SecKeyCopyExternalRepresentationDart
  secKeyCopyExternalRepresentation = _lib
      .lookupFunction<
        _SecKeyCopyExternalRepresentationNative,
        SecKeyCopyExternalRepresentationDart
      >('SecKeyCopyExternalRepresentation');

  late final SecKeyCreateWithDataDart secKeyCreateWithData = _lib
      .lookupFunction<_SecKeyCreateWithDataNative, SecKeyCreateWithDataDart>(
        'SecKeyCreateWithData',
      );

  late final CFDataCreateDart cfDataCreate = _cf
      .lookupFunction<_CFDataCreateNative, CFDataCreateDart>('CFDataCreate');

  late final CFDataGetBytePtrDart cfDataGetBytePtr = _cf
      .lookupFunction<_CFDataGetBytePtrNative, CFDataGetBytePtrDart>(
        'CFDataGetBytePtr',
      );

  late final CFDataGetLengthDart cfDataGetLength = _cf
      .lookupFunction<_CFDataGetLengthNative, CFDataGetLengthDart>(
        'CFDataGetLength',
      );

  late final CFDictionaryCreateDart cfDictionaryCreate = _cf
      .lookupFunction<_CFDictionaryCreateNative, CFDictionaryCreateDart>(
        'CFDictionaryCreate',
      );

  late final CFNumberCreateDart cfNumberCreate = _cf
      .lookupFunction<_CFNumberCreateNative, CFNumberCreateDart>(
        'CFNumberCreate',
      );

  late final CFStringCreateWithCStringDart cfStringCreateWithCString = _cf
      .lookupFunction<
        _CFStringCreateWithCStringNative,
        CFStringCreateWithCStringDart
      >('CFStringCreateWithCString');

  // CF callback constants (pass nullptr for default)
  Pointer<Void> get kCFAllocatorDefault => nullptr;
  Pointer<Void> get kCFTypeDictionaryKeyCallBacks =>
      _cf.lookup<Void>('kCFTypeDictionaryKeyCallBacks');
  Pointer<Void> get kCFTypeDictionaryValueCallBacks =>
      _cf.lookup<Void>('kCFTypeDictionaryValueCallBacks');

  Pointer<Void> get kCFBooleanTrue =>
      _cf.lookup<Pointer<Void>>('kCFBooleanTrue').value;
  Pointer<Void> get kCFBooleanFalse =>
      _cf.lookup<Pointer<Void>>('kCFBooleanFalse').value;

  // Security.framework CFString constants (global symbols).
  // These are CFTypeRef pointer variables; dereference to get the actual object.
  Pointer<Void> get kSecAttrKeyTypeECSECPrimeRandomRef =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeyTypeECSECPrimeRandom').value;
  Pointer<Void> get kSecAttrKeySizeInBits =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeySizeInBits').value;
  Pointer<Void> get kSecAttrKeyType =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeyType').value;
  Pointer<Void> get kSecAttrKeyClassPrivate =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeyClassPrivate').value;
  Pointer<Void> get kSecAttrKeyClassPublic =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeyClassPublic').value;
  Pointer<Void> get kSecAttrKeyClass =>
      _lib.lookup<Pointer<Void>>('kSecAttrKeyClass').value;
  Pointer<Void> get kSecKeyAlgorithmECDHKeyExchangeStandard => _lib
      .lookup<Pointer<Void>>('kSecKeyAlgorithmECDHKeyExchangeStandard')
      .value;
  Pointer<Void> get kSecKeyAlgorithmECDSASignatureDigestX962SHA256 => _lib
      .lookup<Pointer<Void>>('kSecKeyAlgorithmECDSASignatureDigestX962SHA256')
      .value;
  Pointer<Void> get kSecKeyAlgorithmECDSASignatureMessageX962SHA256 => _lib
      .lookup<Pointer<Void>>('kSecKeyAlgorithmECDSASignatureMessageX962SHA256')
      .value;

  /// Convert a [CFDataRef] to a [Uint8List] and release the CF object.
  Uint8List cfDataToBytes(CFDataRef ref) {
    try {
      final length = cfDataGetLength(ref);
      final ptr = cfDataGetBytePtr(ref);
      final out = Uint8List(length);
      for (var i = 0; i < length; i++) {
        out[i] = ptr[i];
      }
      return out;
    } finally {
      cfRelease(ref.cast());
    }
  }

  /// Create a [CFDataRef] from [bytes]. Caller must release with [cfRelease].
  CFDataRef bytesToCFData(Uint8List bytes) {
    final ptr = libcAlloc.allocate<Uint8>(bytes.length);
    try {
      for (var i = 0; i < bytes.length; i++) {
        ptr[i] = bytes[i];
      }
      final ref = cfDataCreate(nullptr, ptr, bytes.length);
      return ref;
    } finally {
      libcAlloc.free(ptr);
    }
  }
}

final sec = SecurityFramework.instance;
