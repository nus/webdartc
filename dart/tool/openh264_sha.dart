// One-shot helper: download an OpenH264 prebuilt from ciscobinary.openh264.org,
// decompress in-memory and print the SHA-256 of the payload.
//
//   dart run tool/openh264_sha.dart https://ciscobinary.openh264.org/openh264-2.5.1-win-arm64.dll.bz2
//
// Used when adding a new Cisco-prebuilt target to dart/hook/build.dart on a
// host that can't otherwise execute the cross-arch payload (e.g. computing
// the win-arm64 SHA from an x64 host).
import 'dart:io';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';

Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln('usage: dart run tool/openh264_sha.dart <bz2-url>');
    exit(64);
  }
  final url = Uri.parse(args[0]);
  final client = HttpClient();
  try {
    final req = await client.getUrl(url);
    final resp = await req.close();
    if (resp.statusCode != 200) {
      stderr.writeln('GET $url -> HTTP ${resp.statusCode}');
      exit(1);
    }
    final compressed = <int>[];
    await for (final chunk in resp) {
      compressed.addAll(chunk);
    }
    final decoded = BZip2Decoder().decodeBytes(compressed);
    print('payload bytes: ${decoded.length}');
    print('sha256:        ${sha256.convert(decoded)}');
  } finally {
    client.close(force: true);
  }
}
