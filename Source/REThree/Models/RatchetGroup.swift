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

import Foundation
import VirgilSDKRatchet
import VirgilCrypto

public class RatchetGroup {
    public static let ValidParticipatnsCountRange = 2...100

    /// Initiator
    @objc public let initiator: String
    /// Participants
    @objc public internal(set) var participants: Set<String>

    internal let localKeyStorage: LocalKeyStorage
    internal let groupManager: RatchetGroupManager
    internal let lookupManager: LookupManager

    internal var session: SecureGroupSession

    private let selfIdentity: String
    private let crypto: VirgilCrypto

    internal init(rawGroup: RatchetRawGroup,
                  crypto: VirgilCrypto,
                  localKeyStorage: LocalKeyStorage,
                  groupManager: RatchetGroupManager,
                  lookupManager: LookupManager) throws {
        try RatchetGroup.validateParticipantsCount(rawGroup.info.participants.count)

        self.initiator = rawGroup.info.initiator
        self.selfIdentity = localKeyStorage.identity
        self.participants = rawGroup.info.participants
        self.crypto = crypto
        self.session = rawGroup.session
        self.localKeyStorage = localKeyStorage
        self.groupManager = groupManager
        self.lookupManager = lookupManager
    }

    internal static func validateParticipantsCount(_ count: Int) throws {
        guard Group.ValidParticipatnsCountRange ~= count else {
            throw GroupError.invalidParticipantsCount
        }
    }

    internal func checkPermissions() throws {
        guard self.selfIdentity == self.initiator else {
            throw GroupError.groupPermissionDenied
        }
    }
}
