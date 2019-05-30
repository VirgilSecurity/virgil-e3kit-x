//
//  EThreeError.swift
//  VirgilE3Kit
//
//  Created by Yevhen Pyvovarov on 5/30/19.
//

import Foundation

/// Declares error types and codes for EThree
///
/// - verifierInitFailed: Initialization of VirgilCardVerifier failed
/// - keyIsNotVirgil: Casting Key to Virgil Key failed
/// - strToDataFailed: String to Data failed
/// - strFromDataFailed: Data to String failed
/// - missingPrivateKey: No private key on device. You should call `register()` of `retrievePrivateKey()`
/// - missingPublicKey: Passed empty LookupResult
/// - missingIdentities: Passed empty array of identities to lookup for
/// - userIsAlreadyRegistered: User is already registered
/// - userIsNotRegistered: User is not registered
/// - privateKeyExists: Private key already exists in local key storage
@objc(VTEEThreeError) public enum EThreeError: Int, Error {
    case verifierInitFailed = 1
    case keyIsNotVirgil = 2
    case strToDataFailed = 3
    case strFromDataFailed = 4
    case missingPrivateKey = 5
    case missingPublicKey = 6
    case missingIdentities = 7
    case userIsAlreadyRegistered = 8
    case userIsNotRegistered = 9
    case privateKeyExists = 10

    public var localizedDescription: String {
        switch self {
        case .verifierInitFailed:
            return "Initialization of VirgilCardVerifier failed"
        case .keyIsNotVirgil:
            return "Casting Key to Virgil Key failed"
        case .strToDataFailed:
            return "String to Data failed"
        case .strFromDataFailed:
            return "Data to String failed"
        case .missingPrivateKey:
            return "No private key on device. You should call register() of retrievePrivateKey()"
        case .missingPublicKey:
            return "Passed empty LookupResult"
        case .missingIdentities:
            return "Passed empty array of identities to lookup for"
        case .userIsAlreadyRegistered:
            return "User is already registered"
        case .userIsNotRegistered:
            return "User is not registered"
        case .privateKeyExists:
            return "Private key already exists in local key storage"
        }
    }
}
