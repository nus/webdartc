// Thin helper over package:jni for the Android JCA crypto backends.
//
// Android has no system OpenSSL to dlopen, so the crypto primitives are
// served by the platform's Java Cryptography Architecture (java.security /
// javax.crypto, backed by Conscrypt/BoringSSL) reached through JNI. This is
// the Android analogue of macOS=Security.framework and Windows=CNG: an
// OS-maintained native crypto provider rather than a bundled library.
//
// Only imported / instantiated on Android (the factory in
// `crypto_backend.dart` guards every use with `Platform.isAndroid`). The
// class refs are JNI global references and the method IDs stay valid while
// the class is loaded, so both are resolved once and cached on [Jca.i].
import 'dart:typed_data';

import 'package:jni/jni.dart';

/// JNI constants mirrored from `javax.crypto.Cipher`.
const int _encryptMode = 1; // Cipher.ENCRYPT_MODE
const int _decryptMode = 2; // Cipher.DECRYPT_MODE

/// Lazily-resolved, process-wide cache of the JCA classes + method IDs used
/// by the Android crypto backends.
class Jca {
  Jca._();
  static final Jca i = Jca._();

  // ── Classes ──────────────────────────────────────────────────────────
  late final _cipher = JClass.forName('javax/crypto/Cipher');
  late final _secretKeySpec = JClass.forName('javax/crypto/spec/SecretKeySpec');
  late final _gcmSpec = JClass.forName('javax/crypto/spec/GCMParameterSpec');
  late final _kpg = JClass.forName('java/security/KeyPairGenerator');
  late final _ecGenSpec = JClass.forName('java/security/spec/ECGenParameterSpec');
  late final _keyPair = JClass.forName('java/security/KeyPair');
  late final _ecPublicKey = JClass.forName('java/security/interfaces/ECPublicKey');
  late final _ecPoint = JClass.forName('java/security/spec/ECPoint');
  late final _bigInteger = JClass.forName('java/math/BigInteger');
  late final _ecPublicKeySpec = JClass.forName('java/security/spec/ECPublicKeySpec');
  late final _keyFactory = JClass.forName('java/security/KeyFactory');
  late final _keyAgreement = JClass.forName('javax/crypto/KeyAgreement');
  late final _signature = JClass.forName('java/security/Signature');
  late final _algParams = JClass.forName('java/security/AlgorithmParameters');
  late final ecParameterSpecClass =
      JClass.forName('java/security/spec/ECParameterSpec');

  // ── Method IDs ───────────────────────────────────────────────────────
  late final _cipherGetInstance = _cipher.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljavax/crypto/Cipher;');
  late final _cipherInitKey =
      _cipher.instanceMethodId('init', '(ILjava/security/Key;)V');
  late final _cipherInitParams = _cipher.instanceMethodId('init',
      '(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V');
  late final _cipherUpdateAad =
      _cipher.instanceMethodId('updateAAD', '([B)V');
  late final _cipherDoFinal = _cipher.instanceMethodId('doFinal', '([B)[B');

  late final _secretKeySpecCtor =
      _secretKeySpec.constructorId('([BLjava/lang/String;)V');
  late final _gcmSpecCtor = _gcmSpec.constructorId('(I[B)V');

  late final _kpgGetInstance = _kpg.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljava/security/KeyPairGenerator;');
  late final _kpgInitialize = _kpg.instanceMethodId(
      'initialize', '(Ljava/security/spec/AlgorithmParameterSpec;)V');
  late final _kpgGenerate =
      _kpg.instanceMethodId('generateKeyPair', '()Ljava/security/KeyPair;');
  late final _ecGenSpecCtor =
      _ecGenSpec.constructorId('(Ljava/lang/String;)V');

  late final _keyPairGetPublic =
      _keyPair.instanceMethodId('getPublic', '()Ljava/security/PublicKey;');
  late final _keyPairGetPrivate =
      _keyPair.instanceMethodId('getPrivate', '()Ljava/security/PrivateKey;');

  late final _ecPubGetW =
      _ecPublicKey.instanceMethodId('getW', '()Ljava/security/spec/ECPoint;');
  late final _ecPubGetParams = _ecPublicKey.instanceMethodId(
      'getParams', '()Ljava/security/spec/ECParameterSpec;');

  late final _ecPointGetX =
      _ecPoint.instanceMethodId('getAffineX', '()Ljava/math/BigInteger;');
  late final _ecPointGetY =
      _ecPoint.instanceMethodId('getAffineY', '()Ljava/math/BigInteger;');
  late final _ecPointCtor = _ecPoint.constructorId(
      '(Ljava/math/BigInteger;Ljava/math/BigInteger;)V');

  late final _bigIntegerCtor = _bigInteger.constructorId('(I[B)V');
  late final _bigIntegerToBytes =
      _bigInteger.instanceMethodId('toByteArray', '()[B');

  late final _ecPublicKeySpecCtor = _ecPublicKeySpec.constructorId(
      '(Ljava/security/spec/ECPoint;Ljava/security/spec/ECParameterSpec;)V');

  late final _keyFactoryGetInstance = _keyFactory.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljava/security/KeyFactory;');
  late final _keyFactoryGenPublic = _keyFactory.instanceMethodId(
      'generatePublic',
      '(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;');

  late final _kaGetInstance = _keyAgreement.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljavax/crypto/KeyAgreement;');
  late final _kaInit =
      _keyAgreement.instanceMethodId('init', '(Ljava/security/Key;)V');
  late final _kaDoPhase = _keyAgreement.instanceMethodId(
      'doPhase', '(Ljava/security/Key;Z)Ljava/security/Key;');
  late final _kaGenerateSecret =
      _keyAgreement.instanceMethodId('generateSecret', '()[B');

  late final _sigGetInstance = _signature.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljava/security/Signature;');
  late final _sigInitSign = _signature.instanceMethodId(
      'initSign', '(Ljava/security/PrivateKey;)V');
  late final _sigInitVerify = _signature.instanceMethodId(
      'initVerify', '(Ljava/security/PublicKey;)V');
  late final _sigUpdate = _signature.instanceMethodId('update', '([B)V');
  late final _sigSign = _signature.instanceMethodId('sign', '()[B');
  late final _sigVerify = _signature.instanceMethodId('verify', '([B)Z');

  late final _apGetInstance = _algParams.staticMethodId(
      'getInstance', '(Ljava/lang/String;)Ljava/security/AlgorithmParameters;');
  late final _apInit = _algParams.instanceMethodId(
      'init', '(Ljava/security/spec/AlgorithmParameterSpec;)V');
  late final _apGetParameterSpec = _algParams.instanceMethodId(
      'getParameterSpec',
      '(Ljava/lang/Class;)Ljava/security/spec/AlgorithmParameterSpec;');

  /// secp256r1 (P-256) [ECParameterSpec], resolved once via
  /// AlgorithmParameters and reused for every public-key import / verify.
  late final JObject p256Params = _resolveP256Params();

  JObject _resolveP256Params() {
    final algo = 'EC'.toJString();
    final curve = 'secp256r1'.toJString();
    final ap = _apGetInstance.call(_algParams, JObject.type, [algo]);
    final genSpec = _ecGenSpecCtor.call<JObject>(_ecGenSpec, [curve]);
    _apInit.call(ap, jvoid.type, [genSpec]);
    final params =
        _apGetParameterSpec.call(ap, JObject.type, [ecParameterSpecClass]);
    algo.release();
    curve.release();
    ap.release();
    genSpec.release();
    return params; // kept alive for the process
  }

  // ── High-level operations ────────────────────────────────────────────

  /// AES single-block ECB encrypt (the keystream primitive behind AES-CM).
  Uint8List aesEcbEncryptBlock(Uint8List key, Uint8List block) {
    final cipher = _newCipher('AES/ECB/NoPadding');
    final sk = _aesKey(key);
    _cipherInitKey.call(cipher, jvoid.type, [_encryptMode, sk]);
    final result = _bytesCall(_cipherDoFinal, cipher, block);
    cipher.release();
    sk.release();
    return result;
  }

  /// AES-GCM encrypt → ciphertext || 16-byte tag (Java appends the tag).
  ({Uint8List ciphertext, Uint8List tag}) aesGcmEncrypt(
      Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    final cipher = _newCipher('AES/GCM/NoPadding');
    final sk = _aesKey(key);
    final spec = _gcmParams(nonce);
    _cipherInitParams.call(cipher, jvoid.type, [_encryptMode, sk, spec]);
    if (aad.isNotEmpty) _voidBytesCall(_cipherUpdateAad, cipher, aad);
    final out = _bytesCall(_cipherDoFinal, cipher, plaintext);
    cipher.release();
    sk.release();
    spec.release();
    final cut = out.length - 16;
    return (ciphertext: out.sublist(0, cut), tag: out.sublist(cut));
  }

  /// AES-GCM decrypt. Returns null on authentication failure.
  Uint8List? aesGcmDecrypt(Uint8List key, Uint8List nonce,
      Uint8List ciphertext, Uint8List expectedTag, Uint8List aad) {
    final cipher = _newCipher('AES/GCM/NoPadding');
    final sk = _aesKey(key);
    final spec = _gcmParams(nonce);
    try {
      _cipherInitParams.call(cipher, jvoid.type, [_decryptMode, sk, spec]);
      if (aad.isNotEmpty) _voidBytesCall(_cipherUpdateAad, cipher, aad);
      final input = Uint8List(ciphertext.length + expectedTag.length)
        ..setRange(0, ciphertext.length, ciphertext)
        ..setRange(ciphertext.length, ciphertext.length + expectedTag.length,
            expectedTag);
      return _bytesCall(_cipherDoFinal, cipher, input);
    } on JObject {
      // AEADBadTagException (and any JCA failure) → authentication failed.
      return null;
    } catch (_) {
      return null;
    } finally {
      cipher.release();
      sk.release();
      spec.release();
    }
  }

  /// Generates an EC P-256 key pair. Returns the JNI handles plus the
  /// 65-byte uncompressed public point (0x04 || X || Y). Caller owns the
  /// returned [KeyPair] handles and must release them.
  EcP256KeyPair generateEcP256KeyPair() {
    final algo = 'EC'.toJString();
    final kpg = _kpgGetInstance.call(_kpg, JObject.type, [algo]);
    final curve = 'secp256r1'.toJString();
    final genSpec = _ecGenSpecCtor.call<JObject>(_ecGenSpec, [curve]);
    _kpgInitialize.call(kpg, jvoid.type, [genSpec]);
    final pair = _kpgGenerate.call(kpg, JObject.type, []);
    final pub = _keyPairGetPublic.call(pair, JObject.type, []);
    final priv = _keyPairGetPrivate.call(pair, JObject.type, []);
    final pubBytes = ecPublicKeyToBytes(pub);

    algo.release();
    kpg.release();
    curve.release();
    genSpec.release();
    pair.release();
    return EcP256KeyPair(public: pub, private: priv, publicKeyBytes: pubBytes);
  }

  /// 65-byte uncompressed encoding (0x04 || X || Y) of an [ECPublicKey].
  Uint8List ecPublicKeyToBytes(JObject ecPublicKey) {
    final w = _ecPubGetW.call(ecPublicKey, JObject.type, []);
    final xBig = _ecPointGetX.call(w, JObject.type, []);
    final yBig = _ecPointGetY.call(w, JObject.type, []);
    final x = _bigIntegerTo32(xBig);
    final y = _bigIntegerTo32(yBig);
    w.release();
    xBig.release();
    yBig.release();
    final out = Uint8List(65)..[0] = 0x04;
    out.setRange(1, 33, x);
    out.setRange(33, 65, y);
    return out;
  }

  /// The [ECParameterSpec] of a generated [ECPublicKey] (caller releases).
  JObject ecParamsOf(JObject ecPublicKey) =>
      _ecPubGetParams.call(ecPublicKey, JObject.type, []);

  /// Imports a 65-byte uncompressed P-256 point as a JCA PublicKey under the
  /// given [ecParams]. Returns null if the encoding is invalid.
  JObject? importEcPublicKey(Uint8List uncompressed, JObject ecParams) {
    if (uncompressed.length != 65 || uncompressed[0] != 0x04) return null;
    final xBig = _bigIntegerFromMagnitude(uncompressed.sublist(1, 33));
    final yBig = _bigIntegerFromMagnitude(uncompressed.sublist(33, 65));
    final point = _ecPointCtor.call<JObject>(_ecPoint, [xBig, yBig]);
    final spec = _ecPublicKeySpecCtor.call<JObject>(
        _ecPublicKeySpec, [point, ecParams]);
    final algo = 'EC'.toJString();
    final kf = _keyFactoryGetInstance.call(_keyFactory, JObject.type, [algo]);
    final pub = _keyFactoryGenPublic.call(kf, JObject.type, [spec]);
    xBig.release();
    yBig.release();
    point.release();
    spec.release();
    algo.release();
    kf.release();
    return pub;
  }

  /// ECDH shared secret (32 bytes for P-256) between [privateKey] and an
  /// already-imported [peerPublicKey].
  Uint8List ecdhSharedSecret(JObject privateKey, JObject peerPublicKey) {
    final algo = 'ECDH'.toJString();
    final ka = _kaGetInstance.call(_keyAgreement, JObject.type, [algo]);
    _kaInit.call(ka, jvoid.type, [privateKey]);
    // doPhase(key, lastPhase: true) intentionally returns null — it yields a
    // Key only for multi-party (>2) agreements.
    _kaDoPhase.callNullable(ka, JObject.type, [peerPublicKey, true]);
    final secret = _bytesCall(_kaGenerateSecret, ka);
    algo.release();
    ka.release();
    return secret;
  }

  /// ECDSA signature over [data]. [algorithm] is e.g. "SHA256withECDSA"
  /// (hashes internally) or "NONEwithECDSA" (signs a pre-computed digest).
  Uint8List ecdsaSign(JObject privateKey, Uint8List data, String algorithm) {
    final algo = algorithm.toJString();
    final sig = _sigGetInstance.call(_signature, JObject.type, [algo]);
    _sigInitSign.call(sig, jvoid.type, [privateKey]);
    _voidBytesCall(_sigUpdate, sig, data);
    final out = _bytesCall(_sigSign, sig);
    algo.release();
    sig.release();
    return out;
  }

  /// Verifies a DER ECDSA [signature] over [message] using SHA256withECDSA.
  bool ecdsaVerifySha256(
      JObject publicKey, Uint8List message, Uint8List signature) {
    final algo = 'SHA256withECDSA'.toJString();
    final sig = _sigGetInstance.call(_signature, JObject.type, [algo]);
    _sigInitVerify.call(sig, jvoid.type, [publicKey]);
    _voidBytesCall(_sigUpdate, sig, message);
    final sigArr = JByteArray.of(signature);
    final ok = _sigVerify.call(sig, jboolean.type, [sigArr]);
    algo.release();
    sig.release();
    sigArr.release();
    return ok;
  }

  // ── Internal plumbing ────────────────────────────────────────────────

  JObject _newCipher(String transformation) {
    final t = transformation.toJString();
    final c = _cipherGetInstance.call(_cipher, JObject.type, [t]);
    t.release();
    return c;
  }

  JObject _aesKey(Uint8List key) {
    final k = JByteArray.of(key);
    final algo = 'AES'.toJString();
    final sk = _secretKeySpecCtor.call<JObject>(_secretKeySpec, [k, algo]);
    k.release();
    algo.release();
    return sk;
  }

  JObject _gcmParams(Uint8List nonce) {
    final n = JByteArray.of(nonce);
    final spec = _gcmSpecCtor.call<JObject>(_gcmSpec, [JValueInt(128), n]);
    n.release();
    return spec;
  }

  /// Calls an instance method returning `[B]` (optionally passing a single
  /// `[B]` argument) and returns the result as a [Uint8List]. `asDart()` is a
  /// per-element view, so `Uint8List.fromList` is the actual bulk copy out.
  /// Releases the temporary Java arrays.
  Uint8List _bytesCall(JInstanceMethodId method, JObject target,
      [Uint8List? arg]) {
    final inArr = arg == null ? null : JByteArray.of(arg);
    final outArr =
        method.call(target, JByteArray.type, [if (inArr != null) inArr]);
    final out = Uint8List.fromList(outArr.asDart());
    inArr?.release();
    outArr.release();
    return out;
  }

  /// Calls a `([B])V` instance method with a single byte-array argument.
  void _voidBytesCall(JInstanceMethodId method, JObject target, Uint8List arg) {
    final a = JByteArray.of(arg);
    method.call(target, jvoid.type, [a]);
    a.release();
  }

  /// `new BigInteger(1, magnitude)` — a positive integer from big-endian
  /// unsigned bytes.
  JObject _bigIntegerFromMagnitude(Uint8List magnitude) {
    final m = JByteArray.of(magnitude);
    final bi = _bigIntegerCtor.call<JObject>(_bigInteger, [JValueInt(1), m]);
    m.release();
    return bi;
  }

  /// BigInteger → 32-byte big-endian, stripping the two's-complement sign
  /// byte or left-padding short values.
  Uint8List _bigIntegerTo32(JObject bigInteger) {
    final arr = _bigIntegerToBytes.call(bigInteger, JByteArray.type, []);
    final raw = Uint8List.fromList(arr.asDart());
    arr.release();
    if (raw.length == 32) return raw;
    final out = Uint8List(32);
    if (raw.length > 32) {
      out.setRange(0, 32, raw.sublist(raw.length - 32));
    } else {
      out.setRange(32 - raw.length, 32, raw);
    }
    return out;
  }
}

/// JNI handles for a generated EC P-256 key pair.
class EcP256KeyPair {
  final JObject public;
  final JObject private;
  final Uint8List publicKeyBytes;

  EcP256KeyPair({
    required this.public,
    required this.private,
    required this.publicKeyBytes,
  });

  void release() {
    public.release();
    private.release();
  }
}
