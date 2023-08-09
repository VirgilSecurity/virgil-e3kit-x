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

/// Declares error types and codes for EThree
///
/// - verifierInitFailed: Initialization of VirgilCardVerifier failed
/// - strToDataFailed: String to Data failed
/// - strFromDataFailed: Data to String failed
/// - missingPrivateKey: No private key on device. You should call `register()` of `retrievePrivateKey()`
/// - missingPublicKey: Passed empty FindUsersResult
/// - missingIdentities: Passed empty array of identities to findUsers
/// - userIsAlreadyRegistered: User is already registered
/// - userIsNotRegistered: User is not registered
/// - privateKeyExists: Private key already exists in local key storage
/// - verificationFailed: Verification of message failed. This may be caused by rotating sender key. Try finding new one
@objc(VTEEThreeError) public enum EThreeError: Int, LocalizedError {
    case verifierInitFailed = 1
    case strToDataFailed = 3
    case strFromDataFailed = 4
    case missingPrivateKey = 5
    case missingPublicKey = 6
    case missingIdentities = 7
    case userIsAlreadyRegistered = 8
    case userIsNotRegistered = 9
    case privateKeyExists = 10
    case verificationFailed = 12
    case wrongPassword = 13

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .verifierInitFailed:
            return "Initialization of VirgilCardVerifier failed"
        case .strToDataFailed:
            return "String to Data failed"
        case .strFromDataFailed:
            return "Data to String failed"
        case .missingPrivateKey:
            return "No private key on device. You should call register() of retrievePrivateKey()"
        case .missingPublicKey:
            return "Passed empty FindUsersResult"
        case .missingIdentities:
            return "Passed empty array of identities to findUsers"
        case .userIsAlreadyRegistered:
            return "User is already registered"
        case .userIsNotRegistered:
            return "User is not registered"
        case .privateKeyExists:
            return "Private key already exists in local key storage"
        case .verificationFailed:
            return
                "Verification of message failed. This may be caused by rotating sender key. Try finding new one"
        case .wrongPassword:
            return "Wrong password"
        }
    }
}
