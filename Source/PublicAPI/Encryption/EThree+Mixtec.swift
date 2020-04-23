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

// MARK: - Extension with group operations
extension EThree {
    /// Creates group, saves in cloud and locally
    ///
    /// - Note: identifier length should be > 10
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - users: Cards of participants. Result of findUsers call
    /// - Returns: CallbackOperation<Group>
    open func createGroup(id identifier: Data, with users: FindUsersResult = [:]) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                let participants = Set(users.keys + [self.identity])

                try Group.validateParticipantsCount(participants.count)

                let ticket = try Ticket(crypto: self.crypto,
                                        sessionId: sessionId,
                                        participants: participants)

                let group = try self.getGroupManager().store(ticket, sharedWith: Array(users.values))

                completion(group, nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    /// Returnes cached local group
    ///
    /// - Parameter identifier: identifier of group
    /// - Returns: Group if exists, nil otherwise
    /// - Throws: corresponding error
    open func getGroup(id identifier: Data) throws -> Group? {
        let sessionId = try self.computeSessionId(from: identifier)

        return try self.getGroupManager().retrieve(sessionId: sessionId)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    /// - Returns: CallbackOperation<Group>
    open func loadGroup(id identifier: Data, initiator card: Card) -> GenericOperation<Group> {
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

    /// Deletes group from cloud (if user is initiator) and local storage
    ///
    /// - Parameter identifier: identifier of group
    /// - Returns: CallbackOperation
    open func deleteGroup(id identifier: Data) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                let sessionId = try self.computeSessionId(from: identifier)

                try self.getGroupManager().delete(sessionId: sessionId)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}

// MARK: - Extension with group operations with string identifier
extension EThree {
    // swiftlint:disable force_unwrapping

    /// Creates group, saves in cloud and locally
    ///
    /// - Note: identifier length should be > 10
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - users: Cards of participants. Result of findUsers call
    /// - Returns: CallbackOperation<Group>
    open func createGroup(id identifier: String, with users: FindUsersResult = [:]) -> GenericOperation<Group> {
        let identifier = identifier.data(using: .utf8)!

        return self.createGroup(id: identifier, with: users)
    }

    /// Returnes cached local group
    ///
    /// - Parameter identifier: identifier of group
    /// - Returns: Group if exists, nil otherwise
    /// - Throws: corresponding error
    open func getGroup(id identifier: String) throws -> Group? {
        let identifier = identifier.data(using: .utf8)!

        return try self.getGroup(id: identifier)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    /// - Returns: CallbackOperation<Group>
    open func loadGroup(id identifier: String, initiator card: Card) -> GenericOperation<Group> {
        let identifier = identifier.data(using: .utf8)!

        return self.loadGroup(id: identifier, initiator: card)
    }

    /// Deletes group from cloud and local storage
    ///
    /// - Parameter identifier: identifier of group
    /// - Returns: CallbackOperation
    open func deleteGroup(id identifier: String) -> GenericOperation<Void> {
        let identifier = identifier.data(using: .utf8)!

        return self.deleteGroup(id: identifier)
    }

    // swiftlint:enable force_unwrapping
}

// MARK: - Extension with group operations with string users parameter
extension EThree {
    /// Creates group, saves in cloud and locally
    ///
    /// - Note: identifier length should be > 10
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - users: participants
    /// - Returns: CallbackOperation<Group>
    open func createGroup(id identifier: Data, with users: [String]) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let users = try users.isEmpty ? FindUsersResult() : self.findUsers(with: users)
                    .startSync()
                    .get()

                self.createGroup(id: identifier, with: users).start(completion: completion)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Creates group, saves in cloud and locally
    ///
    /// - Note: identifier length should be > 10
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - users: participants
    /// - Returns: CallbackOperation<Group>
    open func createGroup(id identifier: String, with users: [String]) -> GenericOperation<Group> {
        let identifier = identifier.data(using: .utf8)!

        return self.createGroup(id: identifier, with: users)
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - initiator: initiator
    /// - Returns: CallbackOperation<Group>
    open func loadGroup(id identifier: Data, initiator: String) -> GenericOperation<Group> {
        return CallbackOperation { _, completion in
            do {
                let card = try self.findUser(with: initiator).startSync().get()

                self.loadGroup(id: identifier, initiator: card).start(completion: completion)
            }
            catch {
                completion(nil, error)
            }
        }
    }

    /// Loads group from cloud, saves locally
    ///
    /// - Parameters:
    ///   - identifier: identifier of group
    ///   - card: Card of group initiator
    /// - Returns: CallbackOperation<Group>
    open func loadGroup(id identifier: String, initiator: String) -> GenericOperation<Group> {
        let identifier = identifier.data(using: .utf8)!

        return self.loadGroup(id: identifier, initiator: initiator)
    }
}
