import Foundation

// MARK: - Gateway Protocol Types
// Types used for the unified WebSocket protocol (port 18789)

// MARK: - Protocol Constants

let GATEWAY_PROTOCOL_VERSION = 3
let GATEWAY_WS_PORT = 18789
let GATEWAY_CLIENT_ID = "openclaw-ios"  // Must match GATEWAY_CLIENT_IDS in gateway config
let GATEWAY_CLIENT_MODE = "node"

// MARK: - App Lifecycle Phase

/// App lifecycle phase for connection management
enum AppLifecyclePhase: Equatable {
    case active
    case inactive
    case background
}

// MARK: - Gateway Errors

enum GatewayError: LocalizedError {
    case notConnected
    case vpnNotConnected
    case connectionFailed(String)
    case requestFailed(String)
    
    var errorDescription: String? {
        switch self {
        case .notConnected:
            return "Not connected to gateway"
        case .vpnNotConnected:
            return "VPN is not connected"
        case .connectionFailed(let reason):
            return "Connection failed: \(reason)"
        case .requestFailed(let reason):
            return "Request failed: \(reason)"
        }
    }
}

// MARK: - Push Events

/// Push events received from the gateway.
public enum GatewayPush: Sendable {
    case snapshot(HelloOkPayload)
    case event(GatewayEvent)
    case seqGap(expected: Int, received: Int)
}

/// Parsed hello-ok/connect response payload.
public struct HelloOkPayload: @unchecked Sendable {
    public var serverName: String
    public var canvasHostUrl: String?
    public var policy: [String: Any]
    public var auth: [String: Any]?

    public init(serverName: String, canvasHostUrl: String?, policy: [String: Any], auth: [String: Any]?) {
        self.serverName = serverName
        self.canvasHostUrl = canvasHostUrl
        self.policy = policy
        self.auth = auth
    }
}

/// Gateway event frame.
public struct GatewayEvent: @unchecked Sendable {
    public var event: String
    public var payload: [String: Any]?
    public var seq: Int?

    public init(event: String, payload: [String: Any]?, seq: Int?) {
        self.event = event
        self.payload = payload
        self.seq = seq
    }
}

// MARK: - Gateway Response Error

/// Error from a gateway RPC response.
public struct GatewayResponseError: Error, LocalizedError {
    public var method: String
    public var code: String?
    public var message: String?
    public var details: [String: Any]

    public var errorDescription: String? {
        if let message = message {
            return "\(method): \(message)"
        }
        return "\(method) failed"
    }

    public init(method: String, code: String?, message: String?, details: [String: Any]) {
        self.method = method
        self.code = code
        self.message = message
        self.details = details
    }
}

// MARK: - Connect Options

/// Connect options for the gateway.
public struct GatewayConnectOptions: Sendable {
    public var role: String
    public var scopes: [String]
    public var caps: [String]
    public var commands: [String]
    public var permissions: [String: Bool]
    public var clientId: String
    public var clientMode: String
    public var clientDisplayName: String?

    public init(
        role: String = "node",
        scopes: [String] = [],
        caps: [String] = [],
        commands: [String] = [],
        permissions: [String: Bool] = [:],
        clientId: String = "openclaw-ios",
        clientMode: String = "node",
        clientDisplayName: String? = nil
    ) {
        self.role = role
        self.scopes = scopes
        self.caps = caps
        self.commands = commands
        self.permissions = permissions
        self.clientId = clientId
        self.clientMode = clientMode
        self.clientDisplayName = clientDisplayName
    }
    
    // MARK: - Factory Methods for Dual Role Connections
    
    /// Create connection options for the operator role.
    ///
    /// Operator connections are used for chat operations (send/receive messages, history).
    ///
    /// - Parameter displayName: Optional custom display name for the client.
    /// - Returns: Pre-configured options for an operator connection.
    public static func forOperator(displayName: String? = nil) -> GatewayConnectOptions {
        GatewayConnectOptions(
            role: "operator",
            scopes: ["operator.read", "operator.write"],
            caps: [],
            commands: [],
            permissions: [:],
            clientId: "openclaw-ios",
            clientMode: "ui",
            clientDisplayName: displayName
        )
    }
    
    /// Create connection options for the node role.
    ///
    /// Node connections are used for capability invokes (camera, location, etc.).
    /// Nodes advertise their capabilities and handle invoke requests.
    ///
    /// - Parameter displayName: Optional custom display name for the client.
    /// - Returns: Pre-configured options for a node connection.
    public static func forNode(displayName: String? = nil) -> GatewayConnectOptions {
        GatewayConnectOptions(
            role: "node",
            scopes: [],
            caps: ["camera", "location", "voice"],
            commands: [
                "camera.snap",
                "camera.clip",
                "camera.list",
                "location.get",
                "system.notify"
            ],
            permissions: ["camera.capture": true],
            clientId: "openclaw-ios",
            clientMode: "node",
            clientDisplayName: displayName
        )
    }
}

// MARK: - Base Frame

/// Base frame for determining message type.
struct BridgeBaseFrame: Codable, Sendable {
    let type: String

    init(type: String) {
        self.type = type
    }
}

// MARK: - Events

/// Event frame (bidirectional).
struct BridgeEventFrame: Codable, Sendable {
    let type: String
    let event: String
    let payloadJSON: String?

    init(type: String = "event", event: String, payloadJSON: String? = nil) {
        self.type = type
        self.event = event
        self.payloadJSON = payloadJSON
    }
}

// MARK: - RPC (Node -> Gateway)

/// RPC request from node to gateway.
struct BridgeRPCRequest: Codable, Sendable {
    let type: String
    let id: String
    let method: String
    let paramsJSON: String?

    init(type: String = "req", id: String, method: String, paramsJSON: String? = nil) {
        self.type = type
        self.id = id
        self.method = method
        self.paramsJSON = paramsJSON
    }
}

/// RPC error details.
struct BridgeRPCError: Codable, Sendable, Equatable {
    let code: String
    let message: String

    init(code: String, message: String) {
        self.code = code
        self.message = message
    }
}

/// RPC response from gateway.
struct BridgeRPCResponse: Codable, Sendable {
    let type: String
    let id: String
    let ok: Bool
    let payloadJSON: String?
    let error: BridgeRPCError?

    init(
        type: String = "res",
        id: String,
        ok: Bool,
        payloadJSON: String? = nil,
        error: BridgeRPCError? = nil
    ) {
        self.type = type
        self.id = id
        self.ok = ok
        self.payloadJSON = payloadJSON
        self.error = error
    }
}

// MARK: - Invoke (Gateway -> Node)

/// Invoke request from gateway to execute a capability.
struct BridgeInvokeRequest: Codable, Sendable {
    let type: String
    let id: String
    let command: String
    let paramsJSON: String?

    init(type: String = "invoke", id: String, command: String, paramsJSON: String? = nil) {
        self.type = type
        self.id = id
        self.command = command
        self.paramsJSON = paramsJSON
    }
}

/// Node error codes for invoke responses.
enum BridgeNodeErrorCode: String, Codable, Sendable {
    case notPaired = "NOT_PAIRED"
    case unauthorized = "UNAUTHORIZED"
    case backgroundUnavailable = "NODE_BACKGROUND_UNAVAILABLE"
    case invalidRequest = "INVALID_REQUEST"
    case unavailable = "UNAVAILABLE"
}

/// Node error for invoke responses.
struct BridgeNodeError: Error, Codable, Sendable, Equatable {
    var code: BridgeNodeErrorCode
    var message: String
    var retryable: Bool?
    var retryAfterMs: Int?

    init(
        code: BridgeNodeErrorCode,
        message: String,
        retryable: Bool? = nil,
        retryAfterMs: Int? = nil
    ) {
        self.code = code
        self.message = message
        self.retryable = retryable
        self.retryAfterMs = retryAfterMs
    }
}

/// Invoke response from node to gateway.
struct BridgeInvokeResponse: Codable, Sendable {
    let type: String
    let id: String
    let ok: Bool
    let payloadJSON: String?
    let error: BridgeNodeError?

    init(
        type: String = "invoke-res",
        id: String,
        ok: Bool,
        payloadJSON: String? = nil,
        error: BridgeNodeError? = nil
    ) {
        self.type = type
        self.id = id
        self.ok = ok
        self.payloadJSON = payloadJSON
        self.error = error
    }
}
