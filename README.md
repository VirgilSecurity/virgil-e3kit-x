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

pod 'VirgilE3Kit', '~> 0.6'
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
github "VirgilSecurity/virgil-e3kit-x" ~> 0.6
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
        // Search user's publicKeys to encrypt for
        eThree!.lookUpPublicKeys(of: ["Alice", "Den"]) { lookupResult, error in 
            // encrypt text
            let encryptedMessage = try! eThree.encrypt(messageToEncrypt, for: lookupResult!)
        }
    }
}
```

## Enable Group Chat (Swift)
In this section, you'll find out how to build a group chat using the Virgil E3Kit SDK.

We assume that your users have installed and initialized the E3Kit SDK, and have registered their Cards on the Virgil Cloud.


### Create Group Chat
Let's imagine Alice wants to start a group chat with Bob and Carol. First, Alice creates a new group ticket by running the `createGroup` feature and the E3Kit stores the ticket on the Virgil Cloud. This ticket holds a shared root key for future group encryption.

Alice has to specify a `sessionId` (a unique 32-byte session identifier) and `participants`. We recommend tying this identifier to your unique transport channel id. If your channel id is not 32-bytes you can use SHA-256 to derive a session id from it.
```swift 
public func createGroup(id identifier: Data, with lookup: LookupResult) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let participants = Set(lookup.keys + [self.identity])

                try Group.validateParticipantsCount(participants.count)

                let ticket = try Ticket(crypto: self.crypto,
                                        sessionId: sessionId,
                                        participants: participants)

                let group = try self.getGroupManager().store(ticket, sharedWith: Array(lookup.values))

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
```

### Start Group Chat Session

Now, other participants, Bob and Carol, want to join the Alice's group and have to start the group session by loading the group ticket using the `loadGroup` method. This function requires specifying the group chat session ID, from the chat owner's Virgil Cards.
```swift
public func loadGroup(id identifier: Data, initiator card: Card) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let group = try self.getGroupManager().pull(sessionId: sessionId, from: card)

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
```

Also, use the loadGroup method when signing in from a new device.  Then, use the getGroup method to work with the group session locally.
```swift
public func getGroup(id identifier: Data) throws -> Group? {
    let sessionId = try self.computeSessionId(from: identifier)

    return try self.getGroupManager().retrieve(sessionId: sessionId)
}
```


### Encrypt and Decrypt Messages
To encrypt and decrypt messages, use the `encrypt` and `decrypt` E3Kit functions, which allows you to work with data and strings.

Use the following code-snippets to encrypt messages:
```swift
public func encrypt(data: Data) throws -> Data {
        let selfKeyPair = try self.localKeyStorage.retrieveKeyPair()

        let encrypted = try self.session.encrypt(plainText: data, privateKey: selfKeyPair.privateKey.key)

        return encrypted.serialize()
    }
```

Use the following code-snippets to decrypt messages:
```swift
public func decrypt(data: Data, from senderCard: Card, date: Date? = nil) throws -> Data {
        let encrypted = try GroupSessionMessage.deserialize(input: data)

        var card = senderCard
        if let date = date {
            while let previousCard = card.previousCard {
                guard card.createdAt > date else {
                    break
                }

                card = previousCard
            }
        }
```
At the decrypt step, you also use `lookupCards` method to verify that the message hasn't been tempered with.


### Manage Group Chat
E3Kit also allows you to perform other operations, like participants management, while you work with group chat.

#### Update Group Chat
In the event of changes in your group, i.e. adding a new member, or deleting an existing one, each group chat member has to update the encryption key by calling the `update` E3Kit method. This method requires specifying the group `session id` and group owner's Card.
```swift
public func update() -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = self.session.getSessionId()

                let card = try self.lookupManager.lookupCard(of: self.initiator)

                let group = try self.groupManager.pull(sessionId: sessionId, from: card)

                self.session = group.session
                self.participants = group.participants

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
```

#### Add New Chat Member
To add a new chat member, the chat owner has to use the `add` method and specify the new member's `identity`.
```swift

public func add(participant card: Card) -> GenericOperation<Void> {
        return self.add(participants: [card.identity: card])
    }
```

#### Delete Chat Member
To delete a chat member, the chat owner has to use the `delete` method and specify the member's `identity`.
```swift
public func remove(participant card: Card) -> GenericOperation<Void> {
        return self.remove(participants: [card.identity: card])
    }
```

#### Delete Group Chat
To delete a chat, the chat owner has to use the `deleteGroup` method and specify the `sessionId`.
```swift
public func deleteGroup(id identifier: Data) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                guard let group = try self.getGroupManager().retrieve(sessionId: sessionId) else {
                    throw EThreeError.groupWasNotFound
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
