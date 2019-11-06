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

/// Declares error types and codes for EThree Unsafe Channel capabilities
///
/// - chatAlreadyExists: Unsafe channel with provided identity already exists.
/// - selfChannelIsForbidden: Unsafe channel with self is forbidden. Use regular encryption for this purpose.
/// - userIsRegistered: User with provided identity is registered.
///                     Creation of unsafe channels with registered users is forbidden.
/// - channelNotFound: Channel was not found
@objc(VTEUnsafeChannelError) public enum UnsafeChannelError: Int, LocalizedError {
    case chatAlreadyExists = 1
    case selfChannelIsForbidden = 2
    case userIsRegistered = 3
    case channelNotFound = 4

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .chatAlreadyExists:
            return "Unsafe channel with provided identity already exists."
        case .selfChannelIsForbidden:
            return "Unsafe channel with self is forbidden. Use regular encryption for this purpose."
        case .userIsRegistered:
            return """
                User with provided identity is registered.
                Creation of unsafe channels with registered users is forbidden.
            """
        case .channelNotFound:
            return "Channel was not found"
        }
    }
}
