// Platform-neutral libc malloc/free allocator for FFI.
// Works on both macOS and Linux via DynamicLibrary.process().
import 'dart:ffi';
import 'dart:typed_data';

/// A minimal allocator using libc malloc/free from the process symbol table.
final class LibCAllocator implements Allocator {
  static final LibCAllocator instance = LibCAllocator._();
  LibCAllocator._();

  static final _malloc = DynamicLibrary.process()
      .lookupFunction<Pointer<Void> Function(Size), Pointer<Void> Function(int)>(
          'malloc');
  static final _free = DynamicLibrary.process()
      .lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
          'free');

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    final result = _malloc(byteCount);
    if (result == nullptr) throw OutOfMemoryError();
    return result.cast();
  }

  @override
  void free(Pointer<NativeType> pointer) => _free(pointer.cast());
}

final libcAlloc = LibCAllocator.instance;

/// Copy [src] into a native [Pointer<Uint8>] allocated with [alloc].
Pointer<Uint8> toNative(Uint8List src, Allocator alloc) {
  final ptr = alloc<Uint8>(src.length);
  for (var i = 0; i < src.length; i++) {
    ptr[i] = src[i];
  }
  return ptr;
}

/// Copy [count] bytes from [ptr] into a [Uint8List].
Uint8List fromNative(Pointer<Uint8> ptr, int count) {
  final out = Uint8List(count);
  for (var i = 0; i < count; i++) {
    out[i] = ptr[i];
  }
  return out;
}
