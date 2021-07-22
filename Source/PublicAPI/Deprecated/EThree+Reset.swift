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

import VirgilSDK

// MARK: - Extension with deprecated reset operations
extension EThree {
    /// Deletes Private Key stored on Virgil's cloud. This will disable user to log in from other devices.
    ///
    /// - Parameters:
    ///   - password: String with password
    ///   - completion: completion handler
    ///   - error: corresponding error
    @available(*, deprecated, message: "Use resetPrivateKeyBackup without password instead")
    @objc open func resetPrivateKeyBackup(password: String, completion: @escaping (_ error: Error?) -> Void) {
        self.resetPrivateKeyBackup(password: password).start { _, error in
            completion(error)
        }
    }

    /// Deletes Private Key stored on Virgil's cloud. This will disable user to log in from other devices.
    ///
    /// - Parameter password: String with password
    /// - Returns: CallbackOperation<Void>
    @available(*, deprecated, message: "Use resetPrivateKeyBackup without password instead")
    open func resetPrivateKeyBackup(password: String) -> GenericOperation<Void> {
        return CallbackOperation { _, completion in
            do {
                try self.cloudKeyManager.delete(password: password)

                completion((), nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}
