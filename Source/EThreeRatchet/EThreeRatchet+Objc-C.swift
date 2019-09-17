//
// Copyright (C) 2015-2019 Virgil Security Inc.
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

import VirgilSDK

extension EThreeRatchet {
    /// Initializes EThreeRatchet
    ///
    /// - Parameters:
    ///   - identity: identity of user
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - keyRotationInterval: Time Interval, which defines how often keys will be rotated
    ///   - completion: completion handler
    ///   - rethree: initialized `EThreeRatchet` instance
    ///   - error: corresponding error
    @objc public static func initialize(identity: String,
                                        tokenCallback: @escaping RenewJwtCallback,
                                        changedKeyDelegate: ChangedKeyDelegate? = nil,
                                        storageParams: KeychainStorageParams? = nil,
                                        keyRotationInterval: TimeInterval = 3_600,
                                        completion: @escaping (_ rethree: EThreeRatchet?, _ error: Error?) -> Void) {
        self.initialize(identity: identity,
                        tokenCallback: tokenCallback,
                        changedKeyDelegate: changedKeyDelegate,
                        storageParams: storageParams,
                        keyRotationInterval: keyRotationInterval)
            .start(completion: completion)
    }

    /// Initializes EThreeRatchet
    ///
    /// - Parameters:
    ///   - ethree: `EThree` instance
    ///   - keyRotationInterval: Time Interval, which defines how often keys will be rotated
    ///   - completion: completion handler
    ///   - rethree: initialized `EThreeRatchet` instance
    ///   - error: corresponding error
    @objc public static func initialize(ethree: EThree,
                                        keyRotationInterval: TimeInterval = 3_600,
                                        completion: @escaping (_ rethree: EThreeRatchet?, _ error: Error?) -> Void) {
        self.initialize(ethree: ethree, keyRotationInterval: keyRotationInterval).start(completion: completion)
    }

    /// Starts chat with user
    ///
    /// - Parameters:
    ///   - card: chat participant Card
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func startChat(with card: Card, completion: @escaping (Error?) -> Void) {
        self.startChat(with: card).start { _, error in
            completion(error)
        }
    }
}
