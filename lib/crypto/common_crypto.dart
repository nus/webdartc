// Package-private FFI bindings for CommonCrypto on macOS.
// Do NOT import this file from outside lib/crypto/.
import 'dart:ffi';
import 'dart:typed_data';

export 'native_alloc.dart' show LibCAllocator, libcAlloc, toNative, fromNative;

// ── CCCryptor constants ──────────────────────────────────────────────────────
const int kCCSuccess = 0;
const int kCCAlgorithmAES = 0;
const int kCCEncrypt = 0;
const int kCCDecrypt = 1;

// CCMode
const int kCCModeECB = 1;
const int kCCModeCTR = 4;
const int kCCModeGCM = 11;

// CCPadding
const int ccNoPadding = 0;

// CCHmacAlgorithm
const int kCCHmacAlgSHA1 = 1;
const int kCCHmacAlgSHA256 = 2;

// CCKDFAlgorithm
const int kCCKDFHMACHash = 0; // not standard — use CCKeyDerivationHMAC directly

// CCPseudoRandomAlgorithm for CCKeyDerivationHMAC
const int kCCPRFHmacAlgSHA256 = 3;

// ── Type aliases ─────────────────────────────────────────────────────────────
typedef CCCryptorRef = Pointer<Void>;
typedef CCHmacContextNative = Array<Uint8>; // opaque — 128 bytes typically

// ── Native function signatures ────────────────────────────────────────────────
typedef _CCCryptorCreateWithModeNative = Int32 Function(
  Uint32 op,
  Uint32 mode,
  Uint32 alg,
  Uint32 padding,
  Pointer<Uint8> iv,
  Pointer<Uint8> key,
  Size keyLength,
  Pointer<Void> tweak,
  Size tweakLength,
  Int32 numRounds,
  Uint32 options,
  Pointer<CCCryptorRef> cryptorRef,
);
typedef CCCryptorCreateWithModeDart = int Function(
  int op,
  int mode,
  int alg,
  int padding,
  Pointer<Uint8> iv,
  Pointer<Uint8> key,
  int keyLength,
  Pointer<Void> tweak,
  int tweakLength,
  int numRounds,
  int options,
  Pointer<CCCryptorRef> cryptorRef,
);

typedef _CCCryptorUpdateNative = Int32 Function(
  CCCryptorRef cryptorRef,
  Pointer<Uint8> dataIn,
  Size dataInLength,
  Pointer<Uint8> dataOut,
  Size dataOutAvailable,
  Pointer<Size> dataOutMoved,
);
typedef CCCryptorUpdateDart = int Function(
  CCCryptorRef cryptorRef,
  Pointer<Uint8> dataIn,
  int dataInLength,
  Pointer<Uint8> dataOut,
  int dataOutAvailable,
  Pointer<Size> dataOutMoved,
);

typedef _CCCryptorReleaseNative = Int32 Function(CCCryptorRef cryptorRef);
typedef CCCryptorReleaseDart = int Function(CCCryptorRef cryptorRef);

// CCCryptorGCM: single-shot GCM
typedef _CCCryptorGCMNative = Int32 Function(
  Uint32 op,
  Uint32 alg,
  Pointer<Uint8> key,
  Size keyLength,
  Pointer<Uint8> iv,
  Size ivLength,
  Pointer<Uint8> aData,
  Size aDataLength,
  Pointer<Uint8> dataIn,
  Size dataLength,
  Pointer<Uint8> dataOut,
  Pointer<Uint8> tag,
  Pointer<Size> tagLength,
);
typedef CCCryptorGCMDart = int Function(
  int op,
  int alg,
  Pointer<Uint8> key,
  int keyLength,
  Pointer<Uint8> iv,
  int ivLength,
  Pointer<Uint8> aData,
  int aDataLength,
  Pointer<Uint8> dataIn,
  int dataLength,
  Pointer<Uint8> dataOut,
  Pointer<Uint8> tag,
  Pointer<Size> tagLength,
);

typedef _CCHmacNative = Void Function(
  Uint32 algorithm,
  Pointer<Uint8> key,
  Size keyLength,
  Pointer<Uint8> data,
  Size dataLength,
  Pointer<Uint8> macOut,
);
typedef CCHmacDart = void Function(
  int algorithm,
  Pointer<Uint8> key,
  int keyLength,
  Pointer<Uint8> data,
  int dataLength,
  Pointer<Uint8> macOut,
);

typedef _CCRandomGenerateBytesNative = Int32 Function(
  Pointer<Uint8> bytes,
  Size count,
);
typedef CCRandomGenerateBytesDart = int Function(
  Pointer<Uint8> bytes,
  int count,
);

typedef _CCKeyDerivationHMACNative = Int32 Function(
  Uint32 prf,
  Pointer<Uint8> salt,
  Size saltLen,
  Uint32 rounds,
  Pointer<Uint8> z,
  Size zLen,
  Pointer<Uint8> dk,
  Size dkLen,
);
typedef CCKeyDerivationHMACDart = int Function(
  int prf,
  Pointer<Uint8> salt,
  int saltLen,
  int rounds,
  Pointer<Uint8> z,
  int zLen,
  Pointer<Uint8> dk,
  int dkLen,
);

/// Singleton FFI bindings loaded from the process's own symbol table
/// (CommonCrypto is linked into the Dart VM on macOS).
class CommonCrypto {
  CommonCrypto._();

  static final CommonCrypto instance = CommonCrypto._();

  final DynamicLibrary _lib = DynamicLibrary.process();

  late final CCCryptorCreateWithModeDart ccCryptorCreateWithMode = _lib
      .lookupFunction<_CCCryptorCreateWithModeNative,
          CCCryptorCreateWithModeDart>('CCCryptorCreateWithMode');

  late final CCCryptorUpdateDart ccCryptorUpdate = _lib.lookupFunction<
      _CCCryptorUpdateNative,
      CCCryptorUpdateDart>('CCCryptorUpdate');

  late final CCCryptorReleaseDart ccCryptorRelease =
      _lib.lookupFunction<_CCCryptorReleaseNative, CCCryptorReleaseDart>(
          'CCCryptorRelease');

  late final CCCryptorGCMDart ccCryptorGCM = _lib
      .lookupFunction<_CCCryptorGCMNative, CCCryptorGCMDart>('CCCryptorGCM');

  late final CCHmacDart ccHmac =
      _lib.lookupFunction<_CCHmacNative, CCHmacDart>('CCHmac');

  late final CCRandomGenerateBytesDart ccRandomGenerateBytes =
      _lib.lookupFunction<_CCRandomGenerateBytesNative,
          CCRandomGenerateBytesDart>('CCRandomGenerateBytes');

  late final CCKeyDerivationHMACDart ccKeyDerivationHMAC =
      _lib.lookupFunction<_CCKeyDerivationHMACNative, CCKeyDerivationHMACDart>(
          'CCKeyDerivationHMAC');

  /// Copy [src] into a native [Pointer<Uint8>] allocated with [malloc].
  static Pointer<Uint8> toNative(Uint8List src, Allocator alloc) {
    final ptr = alloc<Uint8>(src.length);
    for (var i = 0; i < src.length; i++) {
      ptr[i] = src[i];
    }
    return ptr;
  }

  /// Copy [count] bytes from [ptr] into a [Uint8List].
  static Uint8List fromNative(Pointer<Uint8> ptr, int count) {
    final out = Uint8List(count);
    for (var i = 0; i < count; i++) {
      out[i] = ptr[i];
    }
    return out;
  }
}

