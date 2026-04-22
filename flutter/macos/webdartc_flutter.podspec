Pod::Spec.new do |s|
  s.name             = 'webdartc_flutter'
  s.version          = '0.1.0'
  s.summary          = 'Flutter integration for webdartc (macOS renderer).'
  s.description      = <<-DESC
Platform-specific rendering and capture for webdartc on macOS. Provides a
FlutterTexture-backed video renderer that accepts I420 bytes and presents
them as an NV12 CVPixelBuffer to Flutter's Metal compositor.
                       DESC
  s.homepage         = 'https://github.com/nus/webdartc'
  s.license          = { :type => 'BSD', :text => 'See project root LICENSE.' }
  s.author           = { 'webdartc authors' => 'noreply@invalid' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'FlutterMacOS'
  s.platform         = :osx, '10.14'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version    = '5.0'
end
