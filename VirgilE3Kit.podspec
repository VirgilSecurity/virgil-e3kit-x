Pod::Spec.new do |s|
  s.name                       	= "VirgilE3Kit"
  s.version                   	= "4.0.0-dev.1"
  s.swift_version               = "5."
  s.license      		= { :type => "BSD", :file => "LICENSE" }
  s.summary      		= "Vigil E3Kit for Apple devices and languages"
  s.homepage     		= "https://github.com/VirgilSecurity/virgil-e3kit-x/"
  s.author       		= { "Virgil Security" => "https://virgilsecurity.com/" }
  s.ios.deployment_target       = "9.0"
  s.osx.deployment_target       = "10.11"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source       		= { :git => "https://github.com/VirgilSecurity/virgil-e3kit-x.git", :tag => s.version }
  s.source_files  		= 'Source/**/*.{swift}'
  s.dependency "VirgilSDKRatchet", '= 0.10.0'
end
