import Cocoa
import FlutterMacOS
import CoreVideo

/// Entry point for the macOS plugin. Registers a method channel
/// (`webdartc_flutter/render`) and wires video textures into the Flutter
/// engine via `FlutterPluginRegistrar.textures`.
public class WebdartcFlutterPlugin: NSObject, FlutterPlugin {
  private let textureRegistry: FlutterTextureRegistry
  private var textures: [Int64: VideoTexture] = [:]
  private let lock = NSLock()

  init(textureRegistry: FlutterTextureRegistry) {
    self.textureRegistry = textureRegistry
    super.init()
  }

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "webdartc_flutter/render",
      binaryMessenger: registrar.messenger)
    let instance = WebdartcFlutterPlugin(textureRegistry: registrar.textures)
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "create":
      let tex = VideoTexture()
      let id = textureRegistry.register(tex)
      tex.textureId = id
      tex.registry = textureRegistry
      lock.lock(); textures[id] = tex; lock.unlock()
      result(id)

    case "render":
      guard let args = call.arguments as? [String: Any],
            let id = args["textureId"] as? Int64,
            let width = args["width"] as? Int,
            let height = args["height"] as? Int,
            let data = args["data"] as? FlutterStandardTypedData else {
        result(FlutterError(code: "BAD_ARGS",
                            message: "render requires {textureId,width,height,data}",
                            details: nil))
        return
      }
      lock.lock(); let tex = textures[id]; lock.unlock()
      guard let tex = tex else {
        result(FlutterError(code: "NO_TEXTURE",
                            message: "Unknown textureId \(id)",
                            details: nil))
        return
      }
      tex.update(i420: data.data, width: width, height: height)
      result(nil)

    case "dispose":
      guard let args = call.arguments as? [String: Any],
            let id = args["textureId"] as? Int64 else {
        result(FlutterError(code: "BAD_ARGS", message: nil, details: nil))
        return
      }
      textureRegistry.unregisterTexture(id)
      lock.lock(); textures.removeValue(forKey: id); lock.unlock()
      result(nil)

    default:
      result(FlutterMethodNotImplemented)
    }
  }
}

/// One video track's worth of texture state. Holds the latest decoded frame
/// as an NV12 `CVPixelBuffer`; Flutter's Metal compositor performs the
/// YUV→RGB conversion when sampling it.
private final class VideoTexture: NSObject, FlutterTexture {
  var textureId: Int64 = 0
  weak var registry: FlutterTextureRegistry?

  private let bufLock = NSLock()
  private var latest: CVPixelBuffer?
  // Reused when width/height are stable to avoid per-frame CVPixelBuffer
  // allocation.
  private var scratch: CVPixelBuffer?
  private var scratchWidth = 0
  private var scratchHeight = 0

  func copyPixelBuffer() -> Unmanaged<CVPixelBuffer>? {
    bufLock.lock(); defer { bufLock.unlock() }
    guard let buf = latest else { return nil }
    return Unmanaged.passRetained(buf)
  }

  func update(i420: Data, width: Int, height: Int) {
    guard width > 0, height > 0,
          i420.count >= width * height * 3 / 2 else { return }

    let pb = ensureScratch(width: width, height: height)
    guard let pb = pb else { return }

    CVPixelBufferLockBaseAddress(pb, [])
    defer { CVPixelBufferUnlockBaseAddress(pb, []) }

    let yPlane = CVPixelBufferGetBaseAddressOfPlane(pb, 0)!
      .assumingMemoryBound(to: UInt8.self)
    let yDstStride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0)
    let uvPlane = CVPixelBufferGetBaseAddressOfPlane(pb, 1)!
      .assumingMemoryBound(to: UInt8.self)
    let uvDstStride = CVPixelBufferGetBytesPerRowOfPlane(pb, 1)

    i420.withUnsafeBytes { raw in
      let yStart = raw.baseAddress!.assumingMemoryBound(to: UInt8.self)
      let uStart = yStart.advanced(by: width * height)
      let vStart = uStart.advanced(by: (width / 2) * (height / 2))

      for r in 0..<height {
        memcpy(yPlane.advanced(by: r * yDstStride),
               yStart.advanced(by: r * width),
               width)
      }

      let uvw = width / 2
      let uvh = height / 2
      for r in 0..<uvh {
        let dstRow = uvPlane.advanced(by: r * uvDstStride)
        let uRow = uStart.advanced(by: r * uvw)
        let vRow = vStart.advanced(by: r * uvw)
        for c in 0..<uvw {
          dstRow[c * 2] = uRow[c]
          dstRow[c * 2 + 1] = vRow[c]
        }
      }
    }

    bufLock.lock()
    latest = pb
    bufLock.unlock()

    registry?.textureFrameAvailable(textureId)
  }

  private func ensureScratch(width: Int, height: Int) -> CVPixelBuffer? {
    if let pb = scratch,
       scratchWidth == width,
       scratchHeight == height {
      return pb
    }
    var pb: CVPixelBuffer?
    let attrs: [CFString: Any] = [
      kCVPixelBufferMetalCompatibilityKey: true,
      kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
    ]
    let status = CVPixelBufferCreate(
      kCFAllocatorDefault, width, height,
      kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
      attrs as CFDictionary,
      &pb)
    guard status == kCVReturnSuccess, let buf = pb else { return nil }
    scratch = buf
    scratchWidth = width
    scratchHeight = height
    return buf
  }
}
