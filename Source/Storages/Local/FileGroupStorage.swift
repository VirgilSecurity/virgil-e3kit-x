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

/// Declares error types and codes for `FileGroupStorage`
///
/// - invalidFileName:
/// - emptyFile:
@objc(VTEFileGroupStorageError) public enum FileGroupStorageError: Int, LocalizedError {
    case invalidFileName = 1
    case emptyFile = 2

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .invalidFileName:
            return "Invalid file name"
        case .emptyFile:
            return "File is empty"
        }
    }
}

internal class FileGroupStorage {
    internal let identity: String

    private let fileSystem: FileSystem
    private let queue = DispatchQueue(label: "FileGroupStorageQueue")

    private let groupInfoName = "GROUP-INFO"
    private let ticketsSubdir = "TICKETS"

    internal init(identity: String, crypto: VirgilCrypto, keyWrapper: PrivateKeyWrapper) throws {
        self.identity = identity

        let credentials = FileSystemCredentials(crypto: crypto, privateKeyWrapper: keyWrapper)
        self.fileSystem = FileSystem(prefix: "VIRGIL-E3KIT",
                                     userIdentifier: identity,
                                     pathComponents: ["GROUPS"],
                                     credentials: credentials)

    }

    internal func store(_ group: RawGroup) throws {
        try self.queue.sync {
            guard let ticket = group.tickets.last else {
                throw RawGroupError.emptyTickets
            }

            let subdir = ticket.groupMessage.getSessionId().hexEncodedString()

            try self.store(info: group.info, subdir: subdir)

            try group.tickets.forEach { try self.store(ticket: $0, subdir: subdir) }
        }
    }

    internal func getEpochs(sessionId: Data) throws -> Set<String> {
        let subdir = "\(sessionId.hexEncodedString())/\(self.ticketsSubdir)"

        let epochs = try self.fileSystem
            .getFileNames(subdir: subdir)
            .sorted()

        return Set(epochs)
    }

    internal func retrieve(sessionId: Data, lastTicketsCount count: Int) throws -> RawGroup {
        let tickets = try self.retrieveLastTickets(count: count, sessionId: sessionId)

        let groupInfo = try self.retrieveGroupInfo(sessionId: sessionId)

        return try RawGroup(info: groupInfo, tickets: tickets)
    }

    internal func retrieve(sessionId: Data, epoch: UInt32) throws -> RawGroup {
        let ticket = try self.retrieveTicket(sessionId: sessionId, epoch: epoch)

        let groupInfo = try self.retrieveGroupInfo(sessionId: sessionId)

        return try RawGroup(info: groupInfo, tickets: [ticket])
    }

    internal func delete(sessionId: Data) throws {
        try self.queue.sync {
            try self.fileSystem.delete(subdir: sessionId.hexEncodedString())
        }
    }

    internal func reset() throws {
        try self.queue.sync {
            try self.fileSystem.delete()
        }
    }
}

extension FileGroupStorage {
    private func store(ticket: Ticket, subdir: String) throws {
        let subdir = "\(subdir)/\(self.ticketsSubdir)"
        let name = String(ticket.groupMessage.getEpoch())

        let data = try ticket.serialize()
        try self.fileSystem.write(data: data, name: name, subdir: subdir)
    }

    private func store(info: GroupInfo, subdir: String) throws {
        let data = try info.serialize()

        try self.fileSystem.write(data: data, name: self.groupInfoName, subdir: subdir)
    }

    private func retrieveGroupInfo(sessionId: Data) throws -> GroupInfo {
        let subdir = sessionId.hexEncodedString()

        let data = try self.fileSystem.read(name: self.groupInfoName, subdir: subdir)

        guard !data.isEmpty else {
            throw FileGroupStorageError.emptyFile
        }

        return try GroupInfo.deserialize(data)
    }

    private func retrieveTicket(sessionId: Data, epoch: UInt32) throws -> Ticket {
        let subdir = "\(sessionId.hexEncodedString())/\(self.ticketsSubdir)"
        let name = String(epoch)

        let data = try self.fileSystem.read(name: name, subdir: subdir)

        guard !data.isEmpty else {
            throw FileGroupStorageError.emptyFile
        }

        return try Ticket.deserialize(data)
    }

    private func retrieveLastTickets(count: Int, sessionId: Data) throws -> [Ticket] {
        var result: [Ticket] = []

        let subdir = "\(sessionId.hexEncodedString())/\(self.ticketsSubdir)"

        let epochs = try self.fileSystem
            .getFileNames(subdir: subdir)
            .map { (name: String) -> UInt32 in
                guard let epoch = UInt32(name) else {
                    throw FileGroupStorageError.invalidFileName
                }

                return epoch
            }
            .sorted()
            .suffix(count)

        try epochs.forEach {
            let ticket = try self.retrieveTicket(sessionId: sessionId, epoch: $0)

            result.append(ticket)
        }

        return result
    }
}
