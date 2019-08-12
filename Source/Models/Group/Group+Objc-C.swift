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

// MARK: - Extension with Objective-C compatible operations
extension Group {
    /// Updates group
    ///
    /// - Parameters:
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func update(completion: @escaping (_ error: Error?) -> Void) {
        self.update().start { _, error in
            completion(error)
        }
    }

    /// Adds new participants to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - lookup: Cards of users to add. Result of lookupCards call
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func add(participants lookup: LookupResult,
                          completion: @escaping (_ error: Error?) -> Void) {
        self.add(participants: lookup).start { _, error in
            completion(error)
        }
    }

    /// Adds new participant to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - card: Card of user to add
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func add(participant card: Card,
                          completion: @escaping (_ error: Error?) -> Void) {
        self.add(participant: card).start { _, error in
            completion(error)
        }
    }

    /// Share group access and history on new Card of existing participant
    ///
    /// - Parameters:
    ///   - participant: participant Card
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func reAdd(participant: Card, completion: @escaping (_ error: Error?) -> Void) {
        self.reAdd(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Removes participants from group
    ///
    /// - Note: Removed participant will not be able to decrypt previous history again after group update
    /// - Parameters:
    ///   - lookup: Cards of users to remove. Result of lookupCards call
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func remove(participants lookup: LookupResult,
                             completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participants: lookup).start { _, error in
            completion(error)
        }
    }

    /// Removes participant from group
    ///
    /// - Parameters:
    ///   - card: Card of user to remove
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc public func remove(participant card: Card,
                             completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participant: card).start { _, error in
            completion(error)
        }
    }
}
