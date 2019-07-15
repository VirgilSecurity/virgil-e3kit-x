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

import VirgilCrypto
import VirgilSDK
import VirgilCryptoFoundation

public class FileTicketStorage: NSObject, TicketStorage {
    private let fileSystem: FileSystem
    private let queue = DispatchQueue(label: "FileTicketStorageQueue")

    @objc public init(identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair) throws {
        let credentials = FileSystemCredentials(crypto: crypto, keyPair: identityKeyPair)
        self.fileSystem = FileSystem(prefix: "VIRGIL-E3KIT",
                                     userIdentifier: identity,
                                     pathComponents: ["GROUP-TICKETS"],
                                     credentials: credentials)

        super.init()
    }

    @objc public func store(ticket: GroupSessionMessage) throws {
        try self.queue.sync {
            let data = ticket.serialize()
            let subdir = ticket.getSessionId().hexEncodedString()
            let name = String(ticket.getEpoch())

            try self.fileSystem.write(data: data, name: name, subdir: subdir)
        }
    }

    @objc public func store(tickets: [GroupSessionMessage]) throws {
        try tickets.forEach { try self.store(ticket: $0) }
    }

    @objc public func retrieveTickets(sessionId: Data) -> [GroupSessionMessage] {
        var result: [GroupSessionMessage] = []

        let subdir = sessionId.hexEncodedString()

        guard let entries = try? self.fileSystem.read(subdir: subdir), !entries.isEmpty else {
            return result
        }

        entries.forEach {
            if let ticket = try? GroupSessionMessage.deserialize(input: $0) {
                result.append(ticket)
            }
        }

        return result
    }

    public func deleteTickets(sessionId: Data) throws {
        try self.queue.sync {
            let subdir = sessionId.hexEncodedString()
            try self.fileSystem.delete(subdir: subdir)
        }
    }

    @objc public func reset() throws {
        try self.queue.sync {
            try self.fileSystem.delete()
        }
    }
}
