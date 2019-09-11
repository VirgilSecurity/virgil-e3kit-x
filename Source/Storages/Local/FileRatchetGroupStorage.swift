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
import VirgilSDKRatchet

internal class FileRatchetGroupStorage {
    internal let identity: String

    private let fileSystem: FileSystem
    private let crypto: VirgilCrypto
    private let privateKeyData: Data

    private let queue = DispatchQueue(label: "FileRatchetGroupStorageQueue")

    private let infoName = "GROUP-INFO"
    private let sessionName = "SESSION"
    private let ticketsSubdir = "TICKETS"

    internal init(identity: String, crypto: VirgilCrypto, identityKeyPair: VirgilKeyPair) throws {
        self.identity = identity
        self.crypto = crypto
        self.privateKeyData = try crypto.exportPrivateKey(identityKeyPair.privateKey)

        let credentials = FileSystemCredentials(crypto: crypto, keyPair: identityKeyPair)
        self.fileSystem = FileSystem(prefix: "VIRGIL-E3KIT",
                                     userIdentifier: identity,
                                     pathComponents: ["RATCHET-GROUPS"],
                                     credentials: credentials)

    }

    public func store(_ group: RatchetRawGroup) throws {
        try self.queue.sync {
            let sessionData = group.session.serialize()
            let infoData = try group.info.serialize()

            let subdir = group.session.identifier.hexEncodedString()

            // FIXME: one file?
            try self.fileSystem.write(data: sessionData, name: self.sessionName, subdir: subdir)
            try self.fileSystem.write(data: infoData, name: self.infoName, subdir: subdir)
        }
    }

    public func store(tickets: [RatchetTicket], sessionId: Data) throws {
        try tickets.forEach { try self.store(ticket: $0, sessionId: sessionId) }
    }

    public func store(ticket: RatchetTicket, sessionId: Data) throws {
        let subdir = "\(sessionId.hexEncodedString())/\(self.ticketsSubdir)"
        let name = String(ticket.groupMessage.getEpoch())

        let data = try ticket.serialize()
        try self.fileSystem.write(data: data, name: name, subdir: subdir)
    }

    public func retrieveTicket(sessionId: Data, epoch: UInt32) -> RatchetTicket? {
        let subdir = "\(sessionId.hexEncodedString())/\(self.ticketsSubdir)"
        let name = String(epoch)

        guard let data = try? self.fileSystem.read(name: name, subdir: subdir), !data.isEmpty else {
            return nil
        }

        return try? RatchetTicket.deserialize(data)
    }

    public func retrieve(sessionId: Data) -> RatchetRawGroup? {
        guard let session = self.retrieveSession(sessionId: sessionId),
            let info = self.retrieveInfo(sessionId: sessionId) else {
                return nil
        }

        return RatchetRawGroup(session: session, info: info)
    }

    @objc public func deleteSession(sessionId: Data) throws {
        try self.queue.sync {
            try self.fileSystem.delete(name: sessionId.hexEncodedString())
        }
    }

    @objc public func reset() throws {
        try self.queue.sync {
            try self.fileSystem.delete()
        }
    }
}

extension FileRatchetGroupStorage {
    private func retrieveSession(sessionId: Data) -> SecureGroupSession? {
        let subdir = sessionId.hexEncodedString()

        guard let data = try? self.fileSystem.read(name: self.sessionName, subdir: subdir),
            !data.isEmpty else {
                return nil
        }

        return try? SecureGroupSession(data: data, privateKeyData: self.privateKeyData, crypto: self.crypto)
    }

    private func retrieveInfo(sessionId: Data) -> RatchetGroupInfo? {
        let subdir = sessionId.hexEncodedString()

        guard let data = try? self.fileSystem.read(name: self.infoName, subdir: subdir),
            !data.isEmpty else {
                return nil
        }

        return try? RatchetGroupInfo.deserialize(data)
    }
}
