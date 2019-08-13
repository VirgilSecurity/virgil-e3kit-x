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

/// Declares error types and codes for Group
///
/// - missingCachedGroup: Group with provided id not found locally. Try to call loadGroup first
/// - groupPermissionDenied: Group with provided id not found locally. Try to call loadGroup first
/// - groupWasNotFound: Only group initiator can do changed on group
/// - invalidGroup: Group with provided id was not found
/// - invalidChangeParticipants: Group is invalid
/// - invalidParticipantsCount: Invalid change of group participants.
///                             e.g. Add smb who is already in group or remove smb who is not
/// - verificationFailed: Verification of message failed. This may be caused by rotating sender key. Try lookup new one
/// - shortGroupId: Group Id length should be > 10
/// - messageNotFromThisGroup: Message was encrypted in group with different identifier
/// - groupIsOutdated: Group is not up to date. Call update or loadGroup
/// - inconsistentState: Inconsistent state
@objc(VTEEGroupError) public enum GroupError: Int, LocalizedError {
    case missingCachedGroup = 1
    case groupPermissionDenied = 2
    case groupWasNotFound = 3
    case invalidGroup = 4
    case invalidChangeParticipants = 5
    case invalidParticipantsCount = 6
    case verificationFailed = 7
    case shortGroupId = 8
    case messageNotFromThisGroup = 9
    case groupIsOutdated = 10
    case inconsistentState = 11

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .missingCachedGroup:
            return "Group with provided id not found locally. Try to call loadGroup first"
        case .groupPermissionDenied:
            return "Only group initiator can do changed on group"
        case .groupWasNotFound:
            return "Group with provided id was not found"
        case .invalidGroup:
            return "Group is invalid"
        case .invalidChangeParticipants:
            return "Invalid change of group participants. e.g. Add smb who is already in group or remove smb who is not"
        case .invalidParticipantsCount:
            return "Please check valid participants count range in Group.ValidParticipatnsCountRange"
        case .verificationFailed:
            return "Verification of message failed. This may be caused by rotating sender key. Try lookup new one"
        case .shortGroupId:
            return "Group Id length should be > 10"
        case .messageNotFromThisGroup:
            return "Message was encrypted in group with different identifier"
        case .groupIsOutdated:
            return "Group is not up to date. Call update or loadGroup"
        case .inconsistentState:
            return "Inconsistent state"
        }
    }
}
