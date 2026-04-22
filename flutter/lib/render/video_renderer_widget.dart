/// Flutter widget that displays a [VideoRenderer] once its platform
/// texture is ready.
library;

import 'package:flutter/widgets.dart';

import 'video_renderer.dart';

final class VideoRendererWidget extends StatelessWidget {
  final VideoRenderer renderer;
  final Widget? placeholder;

  const VideoRendererWidget({
    super.key,
    required this.renderer,
    this.placeholder,
  });

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<int>(
      future: renderer.textureId,
      builder: (context, snap) {
        if (snap.hasData) return Texture(textureId: snap.data!);
        if (snap.hasError) return ErrorWidget(snap.error!);
        return placeholder ?? const SizedBox.shrink();
      },
    );
  }
}
