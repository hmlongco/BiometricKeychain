//
//  BiometricKeychain.swift
//  Arvest
//
//  Created by Michael Long on 11/25/20.
//

import Foundation
import LocalAuthentication

public class BiometricKeychainWrapper {

    public enum Options {
    case accessGroup(String)
    case authenticationContext(LAContext)
    case authenticationUISkip
    case afterFirstUnlock
    case afterFirstUnlockThisDeviceOnly
    case biometricAny
    case biometricCurrentSet
    case biometricUserPresence
    case whenUnlocked
    case whenUnlockedThisDeviceOnly
    }

    public var defaultAccessGroup: String?
    public var defaultBiometricAccessMode: CFString = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly

    public var status: OSStatus = errSecSuccess

    public init(defaultAccessGroup: String? = nil) {
        self.defaultAccessGroup = defaultAccessGroup
    }

    public func has(service: String, account: String, options: [Options] = []) -> Bool {
        var query = self.query(service: service, account: account, options: options)
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = privateNonInteractingContext

        var secItemResult: CFTypeRef?
        status = SecItemCopyMatching(query as CFDictionary, &secItemResult)

        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public func get(service: String, account: String, options: [Options] = []) -> String? {
        var query = self.query(service: service, account: account, options: options)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var secItemResult: CFTypeRef?
        status = SecItemCopyMatching(query as CFDictionary, &secItemResult)

        if status == errSecSuccess {
            if let data = secItemResult as? Data {
                return String(data: data, encoding: .utf8)
            }
            status = errSecItemNotFound
        }

        return nil
    }

    public func set(_ value: String, service: String, account: String, options: [Options] = [.afterFirstUnlockThisDeviceOnly]) {
        var query = self.query(service: service, account: account, options: options)
        query[kSecValueData as String] = value.data(using: .utf8)!

        status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            update(value, service: service, account: account, options: options)
        }
    }

    public func update(_ value: String, service: String, account: String, options: [Options] = [.afterFirstUnlockThisDeviceOnly]) {
        var query = self.query(service: service, account: account, options: options)
        query[kSecUseAuthenticationContext as String] = privateNonInteractingContext

        let update = [kSecValueData: value.data(using: .utf8)!]

        status = SecItemUpdate(query as CFDictionary, update as CFDictionary)

        if status == errSecInteractionNotAllowed {
            delete(service: service, account: account)
            set(value, service: service, account: account, options: options)
        }
    }

    public func delete(service: String, account: String) {
        let query = self.query(service: service, account: account)
        status = SecItemDelete(query as CFDictionary)
    }

    public func keys(service: String? = nil, account: String? = nil,
                     options: [Options] = [.authenticationUISkip]) -> [(service: String, account: String)] {
        var query = self.query(service: service, account: account, options: options)
        query[kSecReturnAttributes as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitAll

        var secItemResult: AnyObject?
        status = SecItemCopyMatching(query as CFDictionary, &secItemResult)

        if status == errSecSuccess, let results = secItemResult as? [[AnyHashable: Any]] {
            var keys: [(String, String)] = []
            for item in results {
                var service: String?
                var account: String?
                for (key, value) in item {
                    if let key = key as? String {
                        switch key {
                        case "svce":
                            service = value as? String
                        case "acct":
                            account = value as? String
                        default:
                            break
                        }
                    }
                }
                if let service = service, let account = account {
                    keys.append((service, account))
                }
            }
            return keys
        }

        return []
    }

    private func query(service: String?, account: String?, options: [Options] = []) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword]

        query.compactAdd(account, withKey: kSecAttrAccount as String)
        query.compactAdd(service, withKey: kSecAttrService as String)
        query.compactAdd(defaultAccessGroup, withKey: kSecAttrAccessGroup as String)

        for option in options {
            switch option {
            case .accessGroup(let group):
                query[kSecAttrAccessGroup as String] = group
            case .authenticationContext(let context):
                query[kSecUseAuthenticationContext as String] = context
            case .authenticationUISkip:
                query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip // no biometrically protected items will appear
            case .biometricAny, .biometricCurrentSet, .biometricUserPresence:
                let access = defaultBiometricAccessMode
                let option = biometric(option: option)
                query[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(kCFAllocatorDefault, access, option, nil)
            case .afterFirstUnlock:
                query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            case .afterFirstUnlockThisDeviceOnly:
                query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            case .whenUnlocked:
                query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
            case .whenUnlockedThisDeviceOnly:
                query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            }
        }

        return query
    }

    private func biometric(option: Options) -> SecAccessControlCreateFlags {
        switch option {
        case .biometricAny:
            if #available(iOS 11.3, *) {
                return .biometryAny
            } else {
                return .userPresence
            }
        case .biometricCurrentSet:
            if #available(iOS 11.3, *) {
                return .biometryCurrentSet
            } else {
                return .userPresence
            }
        default:
            return .userPresence
        }
    }

    private var privateNonInteractingContext: LAContext? = {
        let context = LAContext()
        context.interactionNotAllowed = true
        return context
    }()

}

extension Dictionary {
    mutating fileprivate func compactAdd(_ value: Value?, withKey key: Key) {
        if let value = value {
            self[key] = value
        }
    }
}

extension OSStatus {
    public var isSuccess: Bool {
        return self == errSecSuccess
    }
    public var isNotFound: Bool {
        return self == errSecItemNotFound
    }
    public var isAuthenticationFailed: Bool {
        return self == errSecAuthFailed
    }
    public var isUserCancelled: Bool {
        return self == errSecUserCanceled
    }
}
