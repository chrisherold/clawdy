import Foundation
import OSLog
import Security

/// Represents a stored device authentication token.
public struct DeviceAuthEntry: Codable, Sendable {
    public let token: String
    public let role: String
    public let scopes: [String]
    public let updatedAtMs: Int

    public init(token: String, role: String, scopes: [String], updatedAtMs: Int) {
        self.token = token
        self.role = role
        self.scopes = scopes
        self.updatedAtMs = updatedAtMs
    }
}

/// Manages per-role device tokens for gateway authentication.
///
/// Device tokens are issued by the gateway after successful pairing/authentication.
/// They are stored in Keychain and associated with both deviceId and role.
///
/// Usage:
/// - After successful connect, store the issued device token
/// - On reconnect, load the token to include in connect params
/// - If token is rejected (expired/revoked), clear it and re-pair
public enum DeviceAuthStore {
    private static let logger = Logger(subsystem: "com.clawdy", category: "device-auth")
    private static let keychainService = "com.clawdy.device-auth"
    
    // MARK: - Public API
    
    /// Store a device token for a given device ID and role.
    /// Returns the created entry on success.
    @discardableResult
    public static func storeToken(
        deviceId: String,
        role: String,
        token: String,
        scopes: [String] = []
    ) -> DeviceAuthEntry? {
        let normalizedRole = normalizeRole(role)
        let entry = DeviceAuthEntry(
            token: token,
            role: normalizedRole,
            scopes: normalizeScopes(scopes),
            updatedAtMs: Int(Date().timeIntervalSince1970 * 1000)
        )
        
        if save(entry: entry, deviceId: deviceId) {
            return entry
        }
        return nil
    }
    
    /// Load a stored device token for a given device ID and role.
    /// Returns nil if no token exists or on error.
    public static func loadToken(deviceId: String, role: String) -> DeviceAuthEntry? {
        let normalizedRole = normalizeRole(role)
        return load(deviceId: deviceId, role: normalizedRole)
    }
    
    /// Clear a stored device token for a given device ID and role.
    public static func clearToken(deviceId: String, role: String) {
        let normalizedRole = normalizeRole(role)
        delete(deviceId: deviceId, role: normalizedRole)
    }
    
    /// Clear all stored tokens for a device ID.
    public static func clearAllTokens(deviceId: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrLabel as String: deviceId
        ]
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Private Implementation
    
    private static func keychainAccount(deviceId: String, role: String) -> String {
        "\(deviceId).\(role)"
    }
    
    private static func normalizeRole(_ role: String) -> String {
        role.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
    
    private static func normalizeScopes(_ scopes: [String]) -> [String] {
        let trimmed = scopes
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return Array(Set(trimmed)).sorted()
    }
    
    private static func save(entry: DeviceAuthEntry, deviceId: String) -> Bool {
        guard let data = try? JSONEncoder().encode(entry) else {
            logger.error("Failed to encode entry")
            return false
        }
        
        let account = keychainAccount(deviceId: deviceId, role: entry.role)
        logger.debug("Saving token: account=\(account, privacy: .public), deviceId=\(deviceId.prefix(8), privacy: .public)..., role=\(entry.role, privacy: .public)")
        
        // Delete any existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        
        // Add new item
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecAttrLabel as String: deviceId,  // For clearAllTokens lookup
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status != errSecSuccess {
            logger.error("Failed to save token: \(status)")
            return false
        }
        logger.debug("Token saved successfully for account=\(account, privacy: .public)")
        return true
    }
    
    private static func load(deviceId: String, role: String) -> DeviceAuthEntry? {
        let account = keychainAccount(deviceId: deviceId, role: role)
        logger.debug("Loading token: account=\(account, privacy: .public), deviceId=\(deviceId.prefix(8), privacy: .public)..., role=\(role, privacy: .public)")
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data else {
            if status == errSecItemNotFound {
                logger.debug("No token found for account=\(account, privacy: .public)")
            } else {
                logger.error("Keychain query failed: \(status)")
            }
            return nil
        }
        
        do {
            let entry = try JSONDecoder().decode(DeviceAuthEntry.self, from: data)
            // Validate token is not empty
            guard !entry.token.isEmpty else {
                logger.warning("Token is empty for account=\(account, privacy: .public)")
                return nil
            }
            logger.debug("Token loaded successfully for account=\(account, privacy: .public)")
            return entry
        } catch {
            logger.error("Failed to decode entry: \(error.localizedDescription)")
            return nil
        }
    }
    
    private static func delete(deviceId: String, role: String) {
        let account = keychainAccount(deviceId: deviceId, role: role)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            logger.error("Failed to delete token: \(status)")
        }
    }
}
