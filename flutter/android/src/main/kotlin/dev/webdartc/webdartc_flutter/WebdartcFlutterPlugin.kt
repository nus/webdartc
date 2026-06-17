package dev.webdartc.webdartc_flutter

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Rect
import android.view.Surface
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.view.TextureRegistry
import java.util.concurrent.ConcurrentHashMap

/// Android renderer for webdartc decoded video. Mirrors the macOS / Windows
/// plugins behind the shared `webdartc_flutter/render` MethodChannel:
///
///   create()                              -> Int textureId
///   render({textureId,width,height,data}) -> void   (data = I420 bytes)
///   dispose({textureId})                  -> void
///
/// Each texture is a Flutter SurfaceTexture; decoded I420 frames are converted
/// to ARGB on the CPU (BT.601 full-range, same coefficients as the macOS /
/// Windows backends) and posted to the texture's Surface. GLES/Impeller
/// external-texture upload is a later optimisation.
class WebdartcFlutterPlugin :
    FlutterPlugin,
    MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var textureRegistry: TextureRegistry
    private val textures = ConcurrentHashMap<Long, VideoTexture>()

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        textureRegistry = binding.textureRegistry
        channel = MethodChannel(binding.binaryMessenger, "webdartc_flutter/render")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "create" -> {
                val entry = textureRegistry.createSurfaceTexture()
                textures[entry.id()] = VideoTexture(entry)
                result.success(entry.id())
            }

            "render" -> {
                val id = (call.argument<Number>("textureId"))?.toLong()
                val width = call.argument<Int>("width")
                val height = call.argument<Int>("height")
                val data = call.argument<ByteArray>("data")
                if (id == null || width == null || height == null || data == null) {
                    result.error("BAD_ARGS", "render requires {textureId,width,height,data}", null)
                    return
                }
                val tex = textures[id]
                if (tex == null) {
                    result.error("NO_TEXTURE", "Unknown textureId $id", null)
                    return
                }
                tex.update(data, width, height)
                result.success(null)
            }

            "dispose" -> {
                val id = (call.argument<Number>("textureId"))?.toLong()
                if (id == null) {
                    result.error("BAD_ARGS", "dispose requires {textureId}", null)
                    return
                }
                textures.remove(id)?.release()
                result.success(null)
            }

            else -> result.notImplemented()
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        for (tex in textures.values) tex.release()
        textures.clear()
    }
}

/// One video track's texture: a [Surface] over Flutter's SurfaceTexture plus a
/// reusable ARGB [Bitmap] sized to the current frame.
private class VideoTexture(private val entry: TextureRegistry.SurfaceTextureEntry) {
    private val surface = Surface(entry.surfaceTexture())
    private val dstRect = Rect()
    private var bitmap: Bitmap? = null
    private var pixels: IntArray = IntArray(0)
    private var width = 0
    private var height = 0

    fun update(i420: ByteArray, w: Int, h: Int) {
        if (w <= 0 || h <= 0 || i420.size < w * h * 3 / 2) return

        if (w != width || h != height) {
            width = w
            height = h
            bitmap?.recycle()
            bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            pixels = IntArray(w * h)
            entry.surfaceTexture().setDefaultBufferSize(w, h)
        }
        val bmp = bitmap ?: return

        convertI420ToArgb(i420, w, h, pixels)
        bmp.setPixels(pixels, 0, w, 0, 0, w, h)

        val canvas = surface.lockCanvas(null) ?: return
        try {
            dstRect.set(0, 0, canvas.width, canvas.height)
            canvas.drawBitmap(bmp, null, dstRect, null)
        } finally {
            surface.unlockCanvasAndPost(canvas)
        }
    }

    fun release() {
        surface.release()
        bitmap?.recycle()
        bitmap = null
        entry.release()
    }

    /// BT.601 full-range I420 -> ARGB8888, 8.8 fixed-point integer math.
    /// Same coefficients as the Windows `ConvertI420ToBgra8` template.
    private fun convertI420ToArgb(i420: ByteArray, w: Int, h: Int, out: IntArray) {
        val ySize = w * h
        val uvStride = w / 2
        val uOffset = ySize
        val vOffset = ySize + uvStride * (h / 2)
        var dst = 0
        for (row in 0 until h) {
            val yRow = row * w
            val uvRow = (row / 2) * uvStride
            for (col in 0 until w) {
                val y = i420[yRow + col].toInt() and 0xff
                val u = (i420[uOffset + uvRow + (col shr 1)].toInt() and 0xff) - 128
                val v = (i420[vOffset + uvRow + (col shr 1)].toInt() and 0xff) - 128
                val r = clamp(y + ((359 * v) shr 8))
                val g = clamp(y - ((88 * u + 183 * v) shr 8))
                val b = clamp(y + ((454 * u) shr 8))
                out[dst++] = (0xff shl 24) or (r shl 16) or (g shl 8) or b
            }
        }
    }

    private fun clamp(v: Int): Int = if (v < 0) 0 else if (v > 255) 255 else v
}
