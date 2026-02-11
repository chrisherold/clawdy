import CryptoKit
import Foundation
import OSLog
import Security

/// Represents a device's Ed25519 identity for gateway authentication.
public struct DeviceIdentity: Codable, Sendable {
    public var deviceId: String
    public var publicKey: String      // Base64 encoded
    public var privateKey: String     // Base64 encoded
    public var createdAtMs: Int

    public init(deviceId: String, publicKey: String, privateKey: String, createdAtMs: Int) {
        self.deviceId = deviceId
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.createdAtMs = createdAtMs
    }
}

/// Manages device Ed25519 keypair for gateway authentication.
/// 
/// The device identity is used to:
/// - Sign connect payloads for challenge-response auth
/// - Provide a stable device ID (SHA256 of public key)
/// - Enable device token persistence across sessions
///
/// Private key is stored securely in iOS Keychain.
public enum DeviceIdentityStore {
    private static let logger = Logger(subsystem: "com.clawdy", category: "device-identity")
    private static let keychainKey = "com.clawdy.device-identity"
    private static var cachedIdentity: DeviceIdentity?
    
    // MARK: - Public API
    
    /// Load existing identity or create a new one.
    /// Generates Ed25519 keypair on first call and stores in Keychain.
    public static func loadOrCreate() -> DeviceIdentity {
        if let cached = cachedIdentity {
            return cached
        }
        switch load() {
        case .found(let existing):
            logger.info("Loaded existing device identity: \(existing.deviceId.prefix(8), privacy: .public)...")
            cachedIdentity = existing
            return existing
        case .notFound:
            logger.info("No existing identity found; generating new identity")
            let identity = generate()
            save(identity)
            cachedIdentity = identity
            return identity
        case .failure(let status):
            if let cached = cachedIdentity {
                logger.warning("Keychain error (\(status)); using cached identity")
                return cached
            }
            logger.warning("Keychain error (\(status)); returning ephemeral identity")
            return generateFallbackIdentity(status: status)
        }
    }
    
    /// Sign a payload string with the device's private key.
    /// Returns base64url-encoded signature, or nil on failure.
    public static func signPayload(_ payload: String, identity: DeviceIdentity) -> String? {
        guard let privateKeyData = Data(base64Encoded: identity.privateKey) else {
            return nil
        }
        do {
            let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
            let signature = try privateKey.signature(for: Data(payload.utf8))
            return base64UrlEncode(signature)
        } catch {
            logger.error("Failed to sign payload: \(error.localizedDescription)")
            return nil
        }
    }
    
    /// Get the public key in base64url format for connect handshake.
    public static func publicKeyBase64Url(_ identity: DeviceIdentity) -> String? {
        guard let data = Data(base64Encoded: identity.publicKey) else {
            return nil
        }
        return base64UrlEncode(data)
    }
    
    /// Clear the stored identity (for testing/reset).
    public static func clear() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey
        ]
        SecItemDelete(query as CFDictionary)
        cachedIdentity = nil
    }
    
    // MARK: - Private Implementation
    
    private static func generate() -> DeviceIdentity {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.rawRepresentation
        let privateKeyData = privateKey.rawRepresentation
        
        // Device ID is SHA256 fingerprint of public key (hex string)
        let deviceId = SHA256.hash(data: publicKeyData)
            .compactMap { String(format: "%02x", $0) }
            .joined()
        
        return DeviceIdentity(
            deviceId: deviceId,
            publicKey: publicKeyData.base64EncodedString(),
            privateKey: privateKeyData.base64EncodedString(),
            createdAtMs: Int(Date().timeIntervalSince1970 * 1000)
        )
    }

    private static func generateFallbackIdentity(status: OSStatus) -> DeviceIdentity {
        let identity = generate()
        logger.warning("Generated ephemeral identity due to keychain error \(status). Pairing may be required.")
        return identity
    }
    
    private enum LoadResult {
        case found(DeviceIdentity)
        case notFound
        case failure(OSStatus)
    }

    private static func load() -> LoadResult {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecItemNotFound {
            logger.debug("Keychain identity not found")
            return .notFound
        }
        guard status == errSecSuccess else {
            logger.error("Keychain load failed: \(status)")
            return .failure(status)
        }
        guard let data = result as? Data else {
            logger.error("Keychain load returned invalid data")
            return .failure(errSecInternalError)
        }
        
        do {
            let identity = try JSONDecoder().decode(DeviceIdentity.self, from: data)
            // Validate required fields
            guard !identity.deviceId.isEmpty,
                  !identity.publicKey.isEmpty,
                  !identity.privateKey.isEmpty else {
                logger.error("Keychain identity missing required fields")
                return .failure(errSecDecode)
            }
            return .found(identity)
        } catch {
            logger.error("Failed to decode identity: \(error.localizedDescription)")
            return .failure(errSecDecode)
        }
    }
    
    private static func save(_ identity: DeviceIdentity) {
        do {
            let data = try JSONEncoder().encode(identity)
            
            // Delete any existing item first
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: keychainKey
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            
            // Add new item
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: keychainKey,
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            ]
            
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status != errSecSuccess {
                logger.error("Failed to save identity: \(status)")
            }
        } catch {
            logger.error("Failed to encode identity: \(error.localizedDescription)")
        }
    }
    
    private static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
