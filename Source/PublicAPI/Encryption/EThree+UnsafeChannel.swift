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

public class UnsafeChannel {
    public let participant: String
    public let publicKey: VirgilPublicKey

    internal init(participant: String, publicKey: VirgilPublicKey, crypto: VirgilCrypto) {
        self.participant = participant
        self.publicKey = publicKey
    }
}

extension EThree {
    public func createUnsafeChannel(with identity: String) -> GenericOperation<UnsafeChannel> {
        return CallbackOperation { _, completion in
            do {
                let tempKeyPair = try self.crypto.generateKeyPair()

                try self.cloudUnsafeStorage.store(tempKeyPair.privateKey, for: identity)

                let unsafeChannel = UnsafeChannel(participant: identity,
                                                  publicKey: tempKeyPair.publicKey,
                                                  crypto: self.crypto)

            //    try self.storage.store(unsafeChannel)

                completion(unsafeChannel, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
