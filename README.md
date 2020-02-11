# Virgil E3Kit Objective-C/Swift

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-e3kit-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-x)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilE3Kit.svg)](https://cocoapods.org/pods/VirgilE3Kit)
[![Platform](https://img.shields.io/cocoapods/p/VirgilE3Kit.svg?style=flat)](https://cocoapods.org/pods/VirgilE3Kit)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![API Reference](https://img.shields.io/badge/API%20reference-e3kit--x-green)](https://virgilsecurity.github.io/virgil-e3kit-x/)

[Introduction](#introduction) | [Benefits](#benefits) | [Features](#features) | [Installation](#installation) | [Resources](#resources) | [Samples](#samples) | [License](#license) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="100px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/e3kit/E3Kit.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the [E3Kit](https://developer.virgilsecurity.com/docs/e3kit/) - an open-source client-side framework that allows developers to add end-to-end encryption to their messaging applications, file sharing programs, and other digital communication products in just a few simple steps to become HIPAA and GDPR compliant and more.

## Benefits

- Easy to setup and integrate into new or existing projects
- Compatible with any CPaaS provider, including Nexmo, Firebase, Twilio, PubNub and etc.
- Strong secret keys storage, integration with Keychain
- Provides GDPR and HIPAA compliance
- Immune to quantum computers attacks

## Features

- Strong one-to-one and group encryption
- Files and stream end-to-end encryption
- Data signature and verification as part of the encrypt and decrypt functions
- Recoverable private encryption keys
- Access to encrypted data from multiple user devices
- Perfect forward secrecy with the Double Ratchet algorithm
- Encryption for unregistered users
- Post-quantum algorithms support: [Round5](https://round5.org/) (encryption), [Falcon](https://falcon-sign.info/) (signature)


## Installation

Virgil E3Kit is provided as a set of frameworks. These frameworks are distributed via Carthage and Cocoapods.

All frameworks are available for:
- iOS 9.0+
- macOS 10.11+
- tvOS 9.0+
- watchOS 2.0+

### COCOAPODS

[CocoaPods](http://cocoapods.org) is a dependency manager for Cocoa projects. You can install it with the following command:

```bash
$ gem install cocoapods
```

To integrate Virgil E3Kit into your Xcode project using CocoaPods, specify it in your *Podfile*:

```bash
target '<Your Target Name>' do
    use_frameworks!

    pod 'VirgilE3Kit', '~> 0.8.0'
end
```

Then, run the following command:

```bash
$ pod install
```

### Carthage

[Carthage](https://github.com/Carthage/Carthage) is a decentralized dependency manager that builds your dependencies and provides you with binary frameworks.

You can install Carthage with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install carthage
```

To integrate VirgilE3Kit into your Xcode project using Carthage, create an empty file with name *Cartfile* in your project's root folder and add following lines to your *Cartfile*

```
github "VirgilSecurity/virgil-e3kit-x" ~> 0.8.0
```

#### Linking against prebuilt binaries

To link prebuilt frameworks to your app, run following command:

```bash
$ carthage update
```

This will build each dependency or download a pre-compiled framework from github Releases.

##### Building for iOS/tvOS/watchOS

On your application targets’ “General” settings tab, in the “Linked Frameworks and Libraries” section, add following frameworks from the *Carthage/Build* folder inside your project's folder:
 - VirgilE3Kit
 - VirgilPythiaSDK
 - VirgilSDK
 - VirgilCrypto
 - VirgilCryptoFoundation
 - VirgilCryptoPythia
 - VSCCommon
 - VSCFoundation
 - VSCPythia

On your application targets’ “Build Phases” settings tab, click the “+” icon and choose “New Run Script Phase.” Create a Run Script in which you specify your shell (ex: */bin/sh*), add the following contents to the script area below the shell:

```bash
/usr/local/bin/carthage copy-frameworks
```

and add the paths to the frameworks you want to use under “Input Files”, e.g.:

```
$(SRCROOT)/Carthage/Build/iOS/VirgilE3Kit.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilPythiaSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilSDK.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCrypto.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoFoundation.framework
$(SRCROOT)/Carthage/Build/iOS/VirgilCryptoPythia.framework
$(SRCROOT)/Carthage/Build/iOS/VSCCommon.framework
$(SRCROOT)/Carthage/Build/iOS/VSCFoundation.framework
$(SRCROOT)/Carthage/Build/iOS/VSCPythia.framework
```

##### Building for macOS

On your application target's “General” settings tab, in the “Embedded Binaries” section, drag and drop following frameworks from the Carthage/Build folder on disk:
 - VirgilE3Kit
 - VirgilPythiaSDK
 - VirgilSDK
 - VirgilCrypto
 - VirgilCryptoFoundation
 - VirgilCryptoPythia
 - VSCCommon
 - VSCFoundation
 - VSCPythia

Additionally, you'll need to copy debug symbols for debugging and crash reporting on macOS.

On your application target’s “Build Phases” settings tab, click the “+” icon and choose “New Copy Files Phase”.
Click the “Destination” drop-down menu and select “Products Directory”. For each framework, drag and drop corresponding dSYM file.

## Resources

- [Developer Documentation](https://developer.virgilsecurity.com/docs/e3kit/) - start integrating E3Kit into your project with our detailed guides.
- [Quickstart Demo](https://developer.virgilsecurity.com/docs/e3kit/get-started/quickstart/) - will help you to get started with the Virgil E3Kit quickly, and to learn some common ways to build end-to-end encryption between two fictional characters Alice and Bob.
- [E3Kit Kotlin API Reference](https://virgilsecurity.github.io/virgil-e3kit-kotlin/) - E3Kit API reference for the language of your choice.


## Samples

You can find the code samples for Objective-C/Swift here:

| Sample type | 
|----------| 
| [`iOS Demo`](https://github.com/VirgilSecurity/demo-e3kit-ios) | 

You can run the samples to see how to initialize the SDK, register users and encrypt messages using E3Kit.

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support

Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
