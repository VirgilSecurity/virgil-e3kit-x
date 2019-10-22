# Virgil E3Kit Objective-C/Swift

[![Build Status](https://api.travis-ci.com/VirgilSecurity/virgil-e3kit-x.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-e3kit-x)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)
[![CocoaPods Compatible](https://img.shields.io/cocoapods/v/VirgilE3Kit.svg)](https://cocoapods.org/pods/VirgilE3Kit)
[![Platform](https://img.shields.io/cocoapods/p/VirgilE3Kit.svg?style=flat)](https://cocoapods.org/pods/VirgilE3Kit)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)

[Introduction](#introduction) | [Features](#features) | [Installation](#installation) | [Usage Examples](#usage-examples) | [Enable Group Chat](#enable-group-chat) | [Samples](#samples) | [License](#license) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) provides the E3Kit which simplifies work with Virgil Cloud and presents an easy-to-use API for adding a security layer to any application. In a few simple steps you can add end-to-end encryption with multidevice and group chats support.

The E3Kit allows developers to get up and running with Virgil API quickly and add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

## Features

- Strong end-to-end encryption with authorization
- One-to-one and group encryption
- Files and stream encryption
- Recovery features for secret keys
- Strong secret keys storage, integration with Keychain
- Integration with any CPaaS providers like Nexmo, Firebase, Twilio, PubNub, etc.
- Public keys cache features
- Access encrypted data from multiple user devices
- Easy setup and integration into new or existing projects

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

    pod 'VirgilE3Kit', '~> 0.8.0-beta2'
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
github "VirgilSecurity/virgil-e3kit-x" ~> 0.8.0-beta2
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

## Usage Examples

#### Register user
Use the following lines of code to authenticate user.

```swift
import VirgilE3Kit

// initialize E3Kit
let eThree = try! EThree(identity: "Bob", tokenCallback: tokenCallback)
    
eThree.register { error in 
    // done
}
```

#### Encrypt & decrypt

Virgil E3Kit lets you use a user's Private key and his or her Card to sign, then encrypt text.

```swift
import VirgilE3Kit

// TODO: init and register user (see Register User)

// prepare a message
let messageToEncrypt = "Hello, Alice and Den!"

// Search user's Cards to encrypt for
eThree!.findUsers(with: ["Alice", "Den"]) { users, error in 
    guard let users = users, error == nil else {
        // Error handling here
    }
    
    // encrypt text
    let encryptedMessage = try! eThree.authEncrypt(text: messageToEncrypt, for: users)
}
```

Decrypt and verify the signed & encrypted data using sender's public key and receiver's private key:

```swift
import VirgilE3Kit

// TODO: init and register user (see Register User)

// Find user
eThree.findUsers(with: [bobUID]) { users, error in
    guard let users = users, error == nil else {
        // Error handling here
    }
    
    // Decrypt text and verify if it was really written by Bob
    let originText = try! eThree.authDecrypt(text: encryptedText, from: users[bobUID]!)
}
```

#### Encrypt & decrypt large files

If the data that needs to be encrypted is too large for your RAM to encrypt all at once, use the following snippets to encrypt and decrypt streams.

Encryption:
```swift
import VirgilE3Kit

// TODO: init and register user (see Register User)
// TODO: Get users UIDs

let usersToEncryptTo = [user1UID, user2UID, user3UID]

// Find users
eThree.findUsers(with: usersToEncryptTo) { users, error in
    guard let users = users, error == nil else {
        // Error handling here
    }

    let fileURL = Bundle.main.url(forResource: "data", withExtension: "txt")!
    let inputStream = InputStream(url: fileURL)!
    let outputStream = OutputStream.toMemory()

    try eThree.encrypt(inputStream, to: outputStream, for: users)
}
```

Decryption:
> Stream encryption doesn’t sign the data. This is why decryption doesn’t need Card for verification unlike the general data decryption.
```swift
import VirgilE3Kit

// TODO: init and register user (see Register User)

let outputStream = OutputStream.toMemory()

try eThree.decrypt(encryptedStream, to: outputStream)
```

#### Multidevice support

In order to enable multidevice support you need to backup Private Key. It wiil be encrypted with [BrainKey](https://github.com/VirgilSecurity/virgil-pythia-x), generated from password and sent to virgil cloud.

```swift
ethree.backupPrivateKey(password: userPassword) { error in 
    guard error == nil else {
        // Error handling
    }
    // Private Key successfully backuped
}
```

After private key was backuped you can use `restorePrivateKey` method to load and decrypt Private Key from virgil cloud.

```swift
ethree.restorePrivateKey(password: userPassword) { error in 
    guard error == nil else {
        // Error handling
    }
    // Private Key successfully restored and saved locally
}
```

If you authorize users using password in your application, please do not use the same password to backup Private Key, since it's not secure. Instead, you can derive from your user password two different ones.

```swift
let derivedPasswords = ethree.derivePasswords(from: userPassword)

// This password should be used for backup/restore PrivateKey
let backupPassword = derivedPasswords.backupPassword
// This password should be used for other purposes, e.g user authorization
let loginPassword = derivedPasswords.loginPassword
```


#### Convinience initializer

`EThree` initializer has plenty of optional parameters to customize it's behaviour. You can easily set them using `EThreeParams` class.

```swift     
    let params = try! EThreeParams(identity: "Alice", 
                                   tokenCallback: tokenCallback)
     
    params.enableRatchet = true
    params.changedKeyDelegate = myDelegate
    
    let ethree = try! EThree(params: params)
```

`EThreeParams` can also be initialized from config plist file.

```swift 
    let configUrl = Bundle.main.url(forResource: "EThreeConfig", withExtension: "plist")!
    
    let params = try! EThreeParams(identity: "Alice", 
                                   tokenCallback: tokenCallback, 
                                   configUrl: configUrl)
    
    let ethree = try! EThree(params: params)
```
The example of config file is [here](https://github.com/VirgilSecurity/virgil-e3kit-x/tree/0.8.0-beta2/Tests/Data/ExampleConfig).

## Enable Group Chat
In this section, you'll find out how to build a group chat using the Virgil E3Kit.

We assume that your users have installed and initialized the E3Kit, and used snippet above to register.


#### Create group chat
Let's imagine Alice wants to start a group chat with Bob and Carol. First, Alice creates a new group ticket by running the `createGroup` feature and the E3Kit stores the ticket on the Virgil Cloud. This ticket holds a shared root key for future group encryption.

Alice has to specify a unique `identifier` of group with length > 10 and `findUsersResult` of participants. We recommend tying this identifier to your unique transport channel id.
```swift 
ethree.createGroup(id: groupId, with: users) { error in 
    guard error == nil else {
        // Error handling
    }
    // Group created and saved locally!
}
```

#### Start group chat session

Now, other participants, Bob and Carol, want to join the Alice's group and have to start the group session by loading the group ticket using the `loadGroup` method. This function requires specifying the group `identifier` and group initiator's Card.
```swift
ethree.loadGroup(id: groupId, initiator: findUsersResult["Alice"]!) { group, error in 
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

#### Encrypt and decrypt messages
To encrypt and decrypt messages, use the `encrypt` and `decrypt` E3Kit functions, which allows you to work with data and strings.

Use the following code-snippets to encrypt messages:
```swift
// prepare a message
let messageToEncrypt = "Hello, Bob and Carol!"

let encrypted = try! group.encrypt(text: messageToEncrypt)
```

Use the following code-snippets to decrypt messages:
```swift
let decrypted = try! group.decrypt(text: encrypted, from: findUsersResult["Alice"]!)
```
At the decrypt step, you also use `findUsers` method to verify that the message hasn't been tempered with.

### Manage group chat
E3Kit also allows you to perform other operations, like participants management, while you work with group chat. In this version of E3Kit only group initiator can change participants or delete group.

#### Add new participant
To add a new chat member, the chat owner has to use the `add` method and specify the new member's Card. New member will be able to decrypt all previous messages history.
```swift
group.add(participant: users["Den"]!) { error in 
    guard error == nil else {
        // Error handling
    }
    
    // Den was added!
}
```

#### Remove participant
To remove participant, group owner has to use the `remove` method and specify the member's Card. Removed participants won't be able to load or update this group.
```swift
group.remove(participant: users["Den"]!) { error in 
    guard error == nil else {
        // Error handling
    }
    
    // Den was removed!
}
```

#### Update group chat
In the event of changes in your group, i.e. adding a new participant, or deleting an existing one, each group chat participant has to update the encryption key by calling the `update` E3Kit method or reloading Group by `loadGroup`.
```swift
group.update { error in 
    guard error == nil else {
        // Error handling
    }

    // Group updated!
}
```

#### Delete group chat
To delete a group, the owner has to use the `deleteGroup` method and specify the group `identifier`.
```swift

ethree.deleteGroup(id: groupId) { error in
    guard error == nil else {
        // Error handling
    }
    
    // Group was deleted!
}
```

## Double Ratchet Chat
In this section, you'll find out how to create and use Double Ratchet chats feature.

We assume that your users have installed and initialized the E3Kit, and used snippet above to register.

#### Create chat

To create a peer-to-peer connection using Double Ratchet protocol use the folowing snippet
```swift

ethree.createRatchetChat(with: users["Bob"]) { chat, error in
    guard error == nil else {
        // Error handling
    }
    // Chat created and saved locally!
}
```

#### Join chat

After someone created chat with user, he can join it

```swift

ethree.joinRatchetChat(with: users["Alice"]) { chat, error in
    guard error == nil else {
        // Error handling
    }
    // Chat joined and saved locally!
}
```

#### Get chat

After joining or creating chat you can use getRatchetChat method to retrieve it from local storage.
```swift

let chat = try! ethree.getRatchetChat(with: users["Alice"])

```

#### Delete chat

Use this snippet to delete chat from local storage and clean cloud invites.

```swift

ethree.deleteRatchetChat(with: users["Bob"]) { error in
    guard error == nil else {
        // Error handling
    }
    
    // Group was deleted!
}
```

#### Encrypt and decrypt messages

Use the following code-snippets to encrypt messages:
```swift
// prepare a message
let messageToEncrypt = "Hello, Bob!"

let encrypted = try! chat.encrypt(text: messageToEncrypt)
```

Use the following code-snippets to decrypt messages:
```swift
let decrypted = try! chat.decrypt(text: encrypted)
```

## Samples

You can find the code samples for Objective-C/Swift here:

| Sample type | 
|----------| 
| [`iOS Demo`](https://github.com/VirgilSecurity/demo-e3kit-ios) | 

You can run the demo to check out the example of how to initialize the SDK, register users and encrypt messages using the E3Kit.


## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
