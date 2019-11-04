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

/// Declares error types and codes for EThree Ratchet capabilities
///
/// - encryptEmptyArray: Trying to encrypt empty array
/// - decryptEmptyArray: Trying to decrypt empty array
/// - missingLocalChat: Chat with provided user was not found locally
/// - chatAlreadyExists: Chat with provided user and name already exists
/// - selfChatIsForbidden: Chat with self is forbidden. Use regular encryption for this purpose.
/// - ratchetIsDisabled: enableRatchet parameter is set to false
/// - userIsNotUsingRatchet: Provided user has been never initialized with ratchet enabled
/// - noInvite: There is no invitation from provided user
/// - noSelfCardLocally: There is no self card in local storage
@objc(VTEEThreeRatchetError) public enum EThreeRatchetError: Int, LocalizedError {
    case encryptEmptyArray = 1
    case decryptEmptyArray = 2
    case missingLocalChat = 3
    case chatAlreadyExists = 4
    case selfChatIsForbidden = 5
    case ratchetIsDisabled = 6
    case userIsNotUsingRatchet = 7
    case noInvite = 8
    case noSelfCardLocally = 9

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .encryptEmptyArray:
            return "Trying to encrypt empty array"
        case .decryptEmptyArray:
            return "Trying to decrypt empty array"
        case .missingLocalChat:
            return "Chat with provided user was not found locally"
        case .chatAlreadyExists:
            return "Chat with provided user and name already exists"
        case .selfChatIsForbidden:
            return "Chat with self is forbidden. Use regular encryption for this purpose."
        case .ratchetIsDisabled:
            return "enableRatchet parameter is set to false"
        case .userIsNotUsingRatchet:
            return "Provided user has been never initialized with ratchet enabled"
        case .noInvite:
            return "There is no invitation from provided user"
        case .noSelfCardLocally:
            return "There is no self card in local storage"
        }
    }
}
