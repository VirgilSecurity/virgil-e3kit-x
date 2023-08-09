Pod::Spec.new do |s|
  s.name                       	= "VirgilE3Kit"
  s.version                   	= "4.0.0"
  s.swift_version               = "5.0"
  s.license      		= { :type => "BSD", :file => "LICENSE" }
  s.summary      		= "Vigil E3Kit for Apple devices and languages"
  s.homepage     		= "https://github.com/VirgilSecurity/virgil-e3kit-x/"
  s.author       		= { "Virgil Security" => "https://virgilsecurity.com/" }
  s.ios.deployment_target       = "11.0"
  s.osx.deployment_target       = "10.13"
  s.tvos.deployment_target      = "11.0"
  s.watchos.deployment_target   = "4.0"
  s.source       		= { :git => "https://github.com/VirgilSecurity/virgil-e3kit-x.git", :tag => s.version }
  s.source_files  		= 'Source/**/*.{swift}'
  s.dependency "VirgilSDKRatchet", '= 0.10.0'
end
