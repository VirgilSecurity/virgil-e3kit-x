//
// Copyright (C) 2015-2021 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilCrypto
import VirgilSDK

internal class CloudTempKeysStorage {
    private static let root = "unsafe-keys"
    private static let defaultKey = "default"
    private static let meta = "unencrypted"

    private let identity: String
    private let accessTokenProvider: AccessTokenProvider
    private let crypto: VirgilCrypto
    private let keyknoxClient: KeyknoxClient

    internal init(
        identity: String,
        accessTokenProvider: AccessTokenProvider,
        crypto: VirgilCrypto,
        keyknoxServiceUrl: URL
    ) {
        self.identity = identity
        self.accessTokenProvider = accessTokenProvider
        self.crypto = crypto

        let connection = EThree.getConnection()

        self.keyknoxClient = KeyknoxClient(
            accessTokenProvider: self.accessTokenProvider,
            serviceUrl: keyknoxServiceUrl,
            connection: connection,
            retryConfig: ExpBackoffRetry.Config()
        )
    }
}

extension CloudTempKeysStorage {
    // swiftlint:disable force_unwrapping
    internal func store(_ tempKey: VirgilPrivateKey, for identity: String) throws {
        let pushParams = KeyknoxPushParams(
            identities: [identity, self.identity],
            root: CloudTempKeysStorage.root,
            path: identity,
            key: CloudTempKeysStorage.defaultKey
        )

        let data = try self.crypto.exportPrivateKey(tempKey)

        let meta = CloudTempKeysStorage.meta.data(using: .utf8)!

        _ = try self.keyknoxClient.pushValue(
            params: pushParams,
            meta: meta,
            value: data,
            previousHash: nil
        )
    }
    // swiftlint:enable force_unwrapping

    internal func retrieve(from identity: String, path: String) throws -> VirgilKeyPair {
        let params = KeyknoxPullParams(
            identity: identity,
            root: CloudTempKeysStorage.root,
            path: path,
            key: CloudTempKeysStorage.defaultKey
        )

        let response = try self.keyknoxClient.pullValue(params: params)

        guard !response.value.isEmpty else {
            throw TemporaryChannelError.channelNotFound
        }

        return try self.crypto.importPrivateKey(from: response.value)
    }

    internal func delete(with identity: String) throws {
        let params = KeyknoxResetParams(
            root: CloudTempKeysStorage.root,
            path: identity,
            key: CloudTempKeysStorage.defaultKey
        )

        _ = try self.keyknoxClient.resetValue(params: params)
    }
}
