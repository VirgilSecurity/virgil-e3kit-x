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
import VirgilCrypto

// MARK: - Extension with Objective-C compatible operations
extension EThree {
    /// Initializes E3Kit with a callback to get Virgil access token
    ///
    /// - Parameters:
    ///   - tokenCallback: callback to get Virgil access token
    ///   - changedKeyDelegate: `ChangedKeyDelegate` to notify changing of User's keys
    ///   - storageParams: `KeychainStorageParams` with specific parameters
    ///   - completion: completion handler
    ///   - ethree: initialized EThree instance
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use constructor instead")
    @objc public static func initialize(tokenCallback: @escaping RenewJwtCallback,
                                        changedKeyDelegate: ChangedKeyDelegate? = nil,
                                        storageParams: KeychainStorageParams? = nil,
                                        completion: @escaping (_ ethree: EThree?, _ error: Error?) -> Void) {
        EThree.initialize(tokenCallback: tokenCallback,
                          changedKeyDelegate: changedKeyDelegate,
                          storageParams: storageParams)
            .start(completion: completion)
    }
    
    /// Creates group, saves in cloud and locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - findResult: Cards of participants. Result of findUsers call
    ///   - completion: completion handler
    ///   - group: created `Group`
    ///   - error: corresponding error
    @objc(dataId:findResult:completion:)
    public func createGroup(id identifier: Data,
                            with findResult: FindUsersResult,
                            completion: @escaping (_ group: Group?,
                                                   _ error: Error?) -> Void) {
        self.createGroup(id: identifier, with: findResult).start(completion: completion)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    ///   - completion: completion handler
    ///   - group: loaded `Group`
    ///   - error: corresponding error
    @objc(dataId:initiator:completion:)
    public func loadGroup(id identifier: Data,
                          initiator card: Card,
                          completion: @escaping (_ group: Group?,
                                                 _ error: Error?) -> Void) {
        self.loadGroup(id: identifier, initiator: card).start(completion: completion)
    }

    /// Deletes group from cloud and local storage
    ///
    /// - Parameters
    ///   - identifier: identifier of group
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc(dataId:completion:)
    public func deleteGroup(id identifier: Data, completion: @escaping (_ error: Error?) -> Void) {
        self.deleteGroup(id: identifier).start { _, error in
            completion(error)
        }
    }

    /// Creates group, saves in cloud and locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - findResult: Cards of participants. Result of findUsers call
    ///   - completion: completion handler
    ///   - group: created `Group`
    ///   - error: corresponding error
    @objc(stringId:findResult:completion:)
    public func createGroup(id identifier: String,
                            with findResult: FindUsersResult,
                            completion: @escaping (_ group: Group?,
                                                   _ error: Error?) -> Void) {
        self.createGroup(id: identifier, with: findResult).start(completion: completion)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    ///   - completion: completion handler
    ///   - group: loaded `Group`
    ///   - error: corresponding error
    @objc(stringId:initiator:completion:)
    public func loadGroup(id identifier: String,
                          initiator card: Card,
                          completion: @escaping (_ group: Group?,
                                                 _ error: Error?) -> Void) {
        self.loadGroup(id: identifier, initiator: card).start(completion: completion)
    }

    /// Deletes group from cloud and local storage
    ///
    /// - Parameters
    ///   - identifier: identifier of group
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc(stringId:completion:)
    public func deleteGroup(id identifier: String, completion: @escaping (_ error: Error?) -> Void) {
        self.deleteGroup(id: identifier).start { _, error in
            completion(error)
        }
    }
}
