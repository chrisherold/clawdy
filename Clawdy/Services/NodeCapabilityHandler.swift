import Foundation
import OSLog
import UIKit

/// Handles node capability invocations from the Clawdbot gateway.
///
/// ## Unified WebSocket Architecture
/// All communication with the gateway flows through a single WebSocket connection
/// on port 18789. The gateway can invoke node capabilities via `node.invoke.request`
/// events, and this handler processes those invocations.
///
/// ## Supported Capabilities
/// | Capability      | Description                          |
/// |-----------------|--------------------------------------|
/// | chat.push       | Agent-initiated message delivery     |
/// | camera.list     | List available cameras               |
/// | camera.snap     | Capture a photo                      |
/// | camera.clip     | Record a video clip                  |
/// | location.get    | Get current GPS location             |
/// | system.notify   | Show a local notification            |
@MainActor
class NodeCapabilityHandler {
    private let logger = Logger(subsystem: "com.clawdy", category: "node-capability")
    // MARK: - Capability Handler Types
    
    /// Handler for chat.push capability - appends agent messages to transcript.
    /// Used for agent-initiated message delivery (e.g., cron jobs, async notifications).
    var onChatPush: ((_ text: String, _ speak: Bool) async -> String?)?
    
    /// Handler for camera.list capability - returns available cameras
    var onCameraList: (() async -> CameraListResult)?
    
    /// Handler for camera.snap capability - captures a photo
    var onCameraSnap: ((_ params: CameraSnapParams) async -> CameraSnapResult)?
    
    /// Handler for camera.clip capability - records a video clip
    var onCameraClip: ((_ params: CameraClipParams) async -> CameraClipResult)?
    
    /// Handler for location.get capability - returns current location
    var onLocationGet: ((_ params: LocationGetParams) async -> LocationGetResult)?
    
    /// Handler for system.notify capability - shows a notification
    /// Returns result indicating success, permission denied, or error
    var onSystemNotify: ((_ params: SystemNotifyParams) async -> SystemNotifyResult)?
    
    // MARK: - JSON Coding
    
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    
    // MARK: - Initialization
    
    init() {}
    
    // MARK: - Invoke Routing
    
    /// Handle an invoke request from the gateway.
    /// Parses the command and params, routes to the appropriate handler, and returns a response.
    /// - Parameter request: The invoke request from the gateway
    /// - Returns: The invoke response to send back to the gateway
    func handleInvoke(_ request: BridgeInvokeRequest) async -> BridgeInvokeResponse {
        logger.info("Handling invoke: \(request.command, privacy: .public)")
        
        // Check if app is in background (many capabilities require foreground)
        let isBackground = UIApplication.shared.applicationState == .background
        
        switch request.command {
        case "chat.push":
            return await handleChatPush(request: request)
            
        case "camera.list":
            return await handleCameraList(request: request, isBackground: isBackground)
            
        case "camera.snap":
            return await handleCameraSnap(request: request, isBackground: isBackground)
            
        case "camera.clip":
            return await handleCameraClip(request: request, isBackground: isBackground)
            
        case "location.get":
            return await handleLocationGet(request: request, isBackground: isBackground)
            
        case "system.notify":
            return await handleSystemNotify(request: request)
            
        default:
            return makeErrorResponse(
                id: request.id,
                code: .invalidRequest,
                message: "Unknown command: \(request.command)"
            )
        }
    }
    
    // MARK: - Chat Push Handler (Fallback Only)
    
    /// Handle chat.push - agent-initiated message delivery.
    /// Called when the gateway pushes a message to the device without a user prompt
    /// (e.g., cron jobs, background tasks, async notifications).
    private func handleChatPush(request: BridgeInvokeRequest) async -> BridgeInvokeResponse {
        // Parse params
        struct ChatPushParams: Codable {
            let text: String
            let speak: Bool?
        }
        
        guard let paramsJSON = request.paramsJSON,
              let paramsData = paramsJSON.data(using: .utf8),
              let params = try? decoder.decode(ChatPushParams.self, from: paramsData) else {
            return makeErrorResponse(
                id: request.id,
                code: .invalidRequest,
                message: "Invalid chat.push params: expected {text: string, speak?: boolean}"
            )
        }
        
        guard let handler = onChatPush else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "chat.push handler not registered"
            )
        }
        
        let speak = params.speak ?? true
        let messageId = await handler(params.text, speak)
        
        // Return success with message ID
        struct ChatPushResult: Codable {
            let messageId: String?
        }
        let result = ChatPushResult(messageId: messageId)
        
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    // MARK: - Camera Handlers
    
    private func handleCameraList(request: BridgeInvokeRequest, isBackground: Bool) async -> BridgeInvokeResponse {
        // camera.list can work in background (doesn't use camera hardware)
        
        guard let handler = onCameraList else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "camera.list handler not registered"
            )
        }
        
        let result = await handler()
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    private func handleCameraSnap(request: BridgeInvokeRequest, isBackground: Bool) async -> BridgeInvokeResponse {
        if isBackground {
            return makeErrorResponse(
                id: request.id,
                code: .backgroundUnavailable,
                message: "Camera requires app to be in foreground"
            )
        }
        
        let params: CameraSnapParams
        if let paramsJSON = request.paramsJSON,
           let paramsData = paramsJSON.data(using: .utf8),
           let decoded = try? decoder.decode(CameraSnapParams.self, from: paramsData) {
            params = decoded
        } else {
            params = CameraSnapParams(facing: nil, maxWidth: nil, quality: nil, delayMs: nil)
        }
        
        guard let handler = onCameraSnap else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "camera.snap handler not registered"
            )
        }
        
        let result = await handler(params)
        
        if let error = result.error {
            return makeErrorResponse(id: request.id, code: .unavailable, message: error)
        }
        
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    private func handleCameraClip(request: BridgeInvokeRequest, isBackground: Bool) async -> BridgeInvokeResponse {
        if isBackground {
            return makeErrorResponse(
                id: request.id,
                code: .backgroundUnavailable,
                message: "Camera requires app to be in foreground"
            )
        }
        
        let params: CameraClipParams
        if let paramsJSON = request.paramsJSON,
           let paramsData = paramsJSON.data(using: .utf8),
           let decoded = try? decoder.decode(CameraClipParams.self, from: paramsData) {
            params = decoded
        } else {
            params = CameraClipParams(facing: nil, durationMs: nil, includeAudio: nil)
        }
        
        guard let handler = onCameraClip else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "camera.clip handler not registered"
            )
        }
        
        let result = await handler(params)
        
        if let error = result.error {
            return makeErrorResponse(id: request.id, code: .unavailable, message: error)
        }
        
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    // MARK: - Location Handler
    
    private func handleLocationGet(request: BridgeInvokeRequest, isBackground: Bool) async -> BridgeInvokeResponse {
        // Location can work in background if "always" permission is granted
        // The handler will check permissions and return appropriate error
        
        let params: LocationGetParams
        if let paramsJSON = request.paramsJSON,
           let paramsData = paramsJSON.data(using: .utf8),
           let decoded = try? decoder.decode(LocationGetParams.self, from: paramsData) {
            params = decoded
        } else {
            // Use defaults if no params provided
            params = LocationGetParams()
        }
        
        guard let handler = onLocationGet else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "location.get handler not registered"
            )
        }
        
        let result = await handler(params)
        
        if let error = result.error {
            return makeErrorResponse(id: request.id, code: .unavailable, message: error)
        }
        
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    // MARK: - System Notify Handler
    
    private func handleSystemNotify(request: BridgeInvokeRequest) async -> BridgeInvokeResponse {
        guard let paramsJSON = request.paramsJSON,
              let paramsData = paramsJSON.data(using: .utf8),
              let params = try? decoder.decode(SystemNotifyParams.self, from: paramsData) else {
            return makeErrorResponse(
                id: request.id,
                code: .invalidRequest,
                message: "Invalid system.notify params: expected {title: string, body: string, sound?: boolean, priority?: string}"
            )
        }
        
        guard let handler = onSystemNotify else {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "system.notify handler not registered"
            )
        }
        
        let result = await handler(params)
        
        // Return appropriate response based on result
        if result.permissionDenied {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: "Notification permission denied. Enable notifications in Settings."
            )
        }
        
        if let error = result.error {
            return makeErrorResponse(
                id: request.id,
                code: .unavailable,
                message: error
            )
        }
        
        return makeSuccessResponse(id: request.id, payload: result)
    }
    
    // MARK: - Response Helpers
    
    private func makeSuccessResponse<T: Codable>(id: String, payload: T) -> BridgeInvokeResponse {
        let payloadJSON: String?
        if let data = try? encoder.encode(payload),
           let json = String(data: data, encoding: .utf8) {
            payloadJSON = json
        } else {
            payloadJSON = nil
        }
        
        return BridgeInvokeResponse(
            type: "invoke-res",
            id: id,
            ok: true,
            payloadJSON: payloadJSON,
            error: nil
        )
    }
    
    private func makeErrorResponse(
        id: String,
        code: BridgeNodeErrorCode,
        message: String
    ) -> BridgeInvokeResponse {
        return BridgeInvokeResponse(
            type: "invoke-res",
            id: id,
            ok: false,
            payloadJSON: nil,
            error: BridgeNodeError(code: code, message: message)
        )
    }
}

// MARK: - Capability Parameter & Result Types

/// Parameters for camera.snap capability
struct CameraSnapParams: Codable {
    let facing: String?  // "front" or "back", default "back"
    let maxWidth: Int?   // Maximum width in pixels
    let quality: Double? // JPEG quality 0.0-1.0, default 0.8
    let delayMs: Int?    // Delay before capture in milliseconds
    
    var facingValue: CameraFacing {
        switch facing?.lowercased() {
        case "front": return .front
        default: return .back
        }
    }
}

/// Camera facing direction
enum CameraFacing: String, Codable {
    case front
    case back
}

/// Result of camera.snap capability
struct CameraSnapResult: Codable {
    let format: String?
    let base64: String?
    let width: Int?
    let height: Int?
    let error: String?
}

/// Parameters for camera.clip capability
struct CameraClipParams: Codable {
    let facing: String?      // "front" or "back", default "back"
    let durationMs: Int?     // Duration in milliseconds, default 5000
    let includeAudio: Bool?  // Whether to include audio, default true
    
    var facingValue: CameraFacing {
        switch facing?.lowercased() {
        case "front": return .front
        default: return .back
        }
    }
    
    var durationSeconds: TimeInterval {
        let ms = durationMs ?? 5000
        return TimeInterval(ms) / 1000.0
    }
}

/// Result of camera.clip capability
struct CameraClipResult: Codable {
    let format: String?
    let base64: String?
    let durationMs: Int?
    let hasAudio: Bool?
    let error: String?
}

/// Result of camera.list capability
struct CameraListResult: Codable {
    let cameras: [CameraInfo]
}

/// Information about an available camera
struct CameraInfo: Codable {
    let id: String       // Device unique ID
    let name: String     // Human-readable name
    let facing: String   // "front" or "back"
    let isDefault: Bool
}

/// Parameters for location.get capability
struct LocationGetParams: Codable {
    let desiredAccuracy: String?  // "best", "nearestTenMeters", "hundredMeters", "kilometer", "threeKilometers"
    let maxAgeMs: Int?            // Maximum age of cached location in milliseconds
    let timeoutMs: Int?           // Timeout for location request in milliseconds
    
    init(desiredAccuracy: String? = nil, maxAgeMs: Int? = nil, timeoutMs: Int? = nil) {
        self.desiredAccuracy = desiredAccuracy
        self.maxAgeMs = maxAgeMs
        self.timeoutMs = timeoutMs
    }
}

/// Result of location.get capability
struct LocationGetResult: Codable {
    let latitude: Double?
    let longitude: Double?
    let accuracy: Double?         // Horizontal accuracy in meters
    let altitude: Double?
    let altitudeAccuracy: Double? // Vertical accuracy in meters
    let speed: Double?            // Speed in m/s
    let heading: Double?          // Heading in degrees (0-360)
    let timestamp: String?        // ISO 8601 timestamp
    let error: String?
}

/// Parameters for system.notify capability
struct SystemNotifyParams: Codable {
    let title: String
    let body: String
    let sound: Bool?              // Play sound, default true
    let priority: String?         // "passive", "active", "timeSensitive"
}

/// Result of system.notify capability
struct SystemNotifyResult: Codable {
    let scheduled: Bool
    let permissionDenied: Bool
    let error: String?
    
    static let success = SystemNotifyResult(scheduled: true, permissionDenied: false, error: nil)
    static let permissionDenied = SystemNotifyResult(scheduled: false, permissionDenied: true, error: nil)
    static func failed(_ message: String) -> SystemNotifyResult {
        SystemNotifyResult(scheduled: false, permissionDenied: false, error: message)
    }
}
