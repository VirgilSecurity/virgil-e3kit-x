# Virgil E3Kit Objective-C/Swift SDK

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-e3kit-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-x)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilE3Kit.svg)](https://cocoapods.org/pods/VirgilE3Kit)
[![Platform](https://img.shields.io/cocoapods/p/VirgilE3Kit.svg?style=flat)](https://cocoapods.org/pods/VirgilE3Kit)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides an SDK which simplifies work with Virgil services and presents easy to use API for adding security to any application. In a few simple steps you can setup user encryption with multidevice support.

## SDK Features
- multidevice support
- manage users' Public Keys

## Installation

Virgil E3Kit is provided as a set of frameworks. These frameworks are distributed via Carthage.  Also in this guide, you find one more package called VirgilCrypto (Virgil Crypto Library) that is used by the E3Kit to perform cryptographic operations.

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

pod 'VirgilE3Kit', '~> 0.7.0-beta'
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
github "VirgilSecurity/virgil-e3kit-x" ~> 0.7.0-beta
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

## Register User
Use the following lines of code to authenticate user.

```swift
import VirgilE3Kit

// initialize E3Kit
EThree.initialize(tokenCallback) { eThree, error in 
    guard let eThree = eThree, error == nil else {
      // error handling here
    }
    eThree.register { error in 
        // done
    }
}
```

## Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Public Keys to sign, then encrypt text.

```swift
import VirgilE3Kit

// prepare a message
let messageToEncrypt = "Hello, Bob!"

// initialize E3Kit
EThree.initialize(tokenCallback) { eThree, error in 
    // Authenticate user 
    eThree!.register { error in
        // Search user's cards to encrypt for
        eThree!.lookUpCards(of: ["Alice", "Den"]) { lookupResult, error in 
            // encrypt text
            let encryptedMessage = try! eThree.encrypt(messageToEncrypt, for: lookupResult!)
        }
    }
}
```

## Enable Group Chat
In this section, you'll find out how to build a group chat using the Virgil E3Kit.

We assume that your users have installed and initialized the E3Kit, and used snippet above to register.


### Create Group Chat
Let's imagine Alice wants to start a group chat with Bob and Carol. First, Alice creates a new group ticket by running the `createGroup` feature and the E3Kit stores the ticket on the Virgil Cloud. This ticket holds a shared root key for future group encryption.

Alice has to specify a unique `identifier` of group with length > 10 and `lookup` of participants. We recommend tying this identifier to your unique transport channel id.
```swift 
ethree.createGroup(id: groupId, with: lookupResult) { error in 
    guard error == nil else {
        // Error handling
    }
    // Group created and saved locally!
}
```

### Start Group Chat Session

Now, other participants, Bob and Carol, want to join the Alice's group and have to start the group session by loading the group ticket using the `loadGroup` method. This function requires specifying the group `identifier` and group initiator's Card.
```swift
ethree.loadGroup(id: groupId, initiator: lookupResult["Alice"]!) { group, error in 
    guard let group = group, error == nil else 
        // Error handling
    }
    // Group loaded and saved locally! 
}
```

Use the loadGroup method to load and save group locally. Then, you can use the getGroup method to retrieve group instance from local storage.
```swift
let group = try! ethree.getGroup(id: groupId)
```

### Encrypt and Decrypt Messages
To encrypt and decrypt messages, use the `encrypt` and `decrypt` E3Kit functions, which allows you to work with data and strings.

Use the following code-snippets to encrypt messages:
```swift
// prepare a message
let messageToEncrypt = "Hello, Bob and Carol!"

let encrypted = try! group.encrypt(text: messageToEncrypt)
```

Use the following code-snippets to decrypt messages:
```swift
let decrypted = try! group.decrypt(text: encrypted, from: lookupResult["Alice"]!)
```
At the decrypt step, you also use `lookupCards` method to verify that the message hasn't been tempered with.

### Manage Group Chat
E3Kit also allows you to perform other operations, like participants management, while you work with group chat. In this version of E3Kit only group initiator can change participants or delete group.

#### Add New Participant
To add a new chat member, the chat owner has to use the `add` method and specify the new member's Card. New member will be able to decrypt all previous messages history.
```swift
group.add(participant: lookupResult["Den"]!) { error in 
    guard error == nil else {
        // Error handling
    }
    
    // Den was added!
}
```

#### Remove Participant
To remove participant, group owner has to use the `remove` method and specify the member's Card. Removed participants won't be able to load or update this group.
```swift
group.remove(participant: lookupResult["Den"]!) { error in 
    guard error == nil else {
        // Error handling
    }
    
    // Den was removed!
}
```

#### Update Group Chat
In the event of changes in your group, i.e. adding a new participant, or deleting an existing one, each group chat participant has to update the encryption key by calling the `update` E3Kit method or reloading Group by `loadGroup`.
```swift
group.update { error in 
    guard error == nil else {
        // Error handling
    }

    // Group updated!
}
```

#### Delete Group Chat
To delete a group, the owner has to use the `deleteGroup` method and specify the group `identifier`.
```swift

ethree.deleteGroup(id: groupId) { error in
    guard error == nil else {
        // Error handling
    }
    
    // Group was deleted!
}
```

## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).

[_virgil_crypto]: https://github.com/VirgilSecurity/virgil-crypto-x
[_cards_service]: https://developer.virgilsecurity.com/docs/api-reference/card-service/v5
[_use_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/use-card-for-crypto-operation
[_get_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/get-card
[_search_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/search-card
[_create_card]: https://developer.virgilsecurity.com/docs/swift/how-to/public-key-management/v5/create-card
[_own_crypto]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-own-crypto-library
[_key_storage]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-key-storage
[_card_verifier]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-verifier
[_card_manager]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-card-manager
[_setup_authentication]: https://developer.virgilsecurity.com/docs/swift/how-to/setup/v5/setup-authentication
[_reference_api]: https://developer.virgilsecurity.com/docs/api-reference
[_configure_sdk]: https://developer.virgilsecurity.com/docs/how-to#sdk-configuration
[_more_examples]: https://developer.virgilsecurity.com/docs/how-to#public-key-management
