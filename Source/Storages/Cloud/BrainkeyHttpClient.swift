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
import VirgilCryptoFoundation
import VirgilSDK

internal enum BrainkeyHttpClientError: Int, LocalizedError {
    case constructingUrl = 1

    internal var errorDescription: String? {
        switch self {
        case .constructingUrl:
            return "constructing brainkey endpoint URL failed"
        }
    }
}

internal class BrainkeyHttpClient: BaseClient {
    // swiftlint:disable force_unwrapping
    internal static let defaultURL = URL(string: "https://api.virgilsecurity.com")!
    // swiftlint:enable force_unwrapping

    internal struct HardenV3Response: Decodable {
        private enum CodingKeys: String, CodingKey {
            case hardenedPoint = "hardened_point"
            case serverPublicKey = "server_public_key"
            case proofValueC = "proof_value_c"
            case proofValueS = "proof_value_s"
        }

        let hardenedPoint: Data
        let serverPublicKey: Data
        let proofValueC: Data
        let proofValueS: Data
    }

    internal func harden(blindedPoint: Data) throws -> HardenV3Response {
        guard let url = URL(string: "brainkey/v3/harden", relativeTo: self.serviceUrl) else {
            throw BrainkeyHttpClientError.constructingUrl
        }

        let params: [String: Any] = [
            "blinded_point": blindedPoint.base64EncodedString()
        ]

        let request = try ServiceRequest(url: url, method: .post, params: params)

        let tokenContext = TokenContext(service: "brainkey", operation: "harden")

        let response = try self.sendWithRetry(
            request,
            retry: ExpBackoffRetry(config: ExpBackoffRetry.Config()),
            tokenContext: tokenContext
        )
        .startSync()
        .get()

        return try self.processResponse(response)
    }
}
