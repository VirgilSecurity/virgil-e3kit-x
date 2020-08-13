//
// Copyright (C) 2015-2020 Virgil Security Inc.
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
    @objc open func update(completion: @escaping (_ error: Error?) -> Void) {
        self.update().start { _, error in
            completion(error)
        }
    }

    /// Adds new participants to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - participants: Cards of users to add. Result of findUsers call
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func add(participants: FindUsersResult,
                        completion: @escaping (_ error: Error?) -> Void) {
        self.add(participants: participants).start { _, error in
            completion(error)
        }
    }

    /// Adds new participants to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - participants: Identities of users to add
    ///   - completion: completion handler
    ///   - error: corresponding error
    open func add(participants: [String],
                  completion: @escaping (_ error: Error?) -> Void) {
        self.add(participants: participants).start { _, error in
            completion(error)
        }
    }

    /// Adds new participant to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - participant: Card of user to add
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func add(participant: Card,
                        completion: @escaping (_ error: Error?) -> Void) {
        self.add(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Adds new participant to group
    ///
    /// - Note: New participant will be able to decrypt all history
    /// - Parameters:
    ///   - participant: New participant will be able to decrypt all history
    ///   - completion: completion handler
    ///   - error: corresponding error
    open func add(participant: String,
                  completion: @escaping (_ error: Error?) -> Void) {
        self.add(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Share group access and history on new Card of existing participant
    ///
    /// - Parameters:
    ///   - participant: participant Card
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func reAdd(participant: Card, completion: @escaping (_ error: Error?) -> Void) {
        self.reAdd(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Share group access and history on new Card of existing participant
    ///
    /// - Parameters:
    ///   - participant: participant to re add
    ///   - completion: completion handler
    ///   - error: corresponding error
    open func reAdd(participant: String, completion: @escaping (_ error: Error?) -> Void) {
        self.reAdd(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Removes participants from group
    ///
    /// - Note: Removed participant will not be able to decrypt previous history again after group update
    /// - Parameters:
    ///   - participants: Cards of users to remove. Result of findUsers call
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func remove(participants: FindUsersResult,
                           completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participants: participants).start { _, error in
            completion(error)
        }
    }

    /// Removes participants from group
    ///
    /// - Note: Removed participant will not be able to decrypt previous history again after group update
    /// - Parameters:
    ///   - participants: Users to remove
    ///   - completion: completion handler
    ///   - error: corresponding error
    open func remove(participants: [String],
                     completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participants: participants).start { _, error in
            completion(error)
        }
    }

    /// Removes participant from group
    ///
    /// - Parameters:
    ///   - participant: Card of user to remove
    ///   - completion: completion handler
    ///   - error: corresponding error
    @objc open func remove(participant: Card,
                           completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participant: participant).start { _, error in
            completion(error)
        }
    }

    /// Removes participant from group
    ///
    /// - Parameters:
    ///   - participant: User to remove
    ///   - completion: completion handler
    ///   - error: corresponding error
    open func remove(participant: String,
                     completion: @escaping (_ error: Error?) -> Void) {
        self.remove(participant: participant).start { _, error in
            completion(error)
        }
    }
}
