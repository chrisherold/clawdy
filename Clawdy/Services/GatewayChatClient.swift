import Foundation

/// Client for chat operations via the Clawdbot gateway.
/// 
/// In dual-role mode, chat operations are routed through `GatewayDualConnectionManager`
/// which uses two WebSocket connections:
/// - **Operator connection**: For chat.send, chat.history, chat.abort
/// - **Node connection**: For receiving node.invoke.request and sending node.invoke.result
/// 
/// This class provides a stable API for the ViewModel while the underlying transport
/// uses dual WebSocket connections for role separation.
actor GatewayChatClient {

    // MARK: - Types

    /// Response from chat.send
    struct SendResponse: Codable {
        let runId: String?
        let sessionKey: String?
    }

    /// Attachment payload for chat.send
    struct AttachmentPayload: Codable {
        let type: String        // "image"
        let mimeType: String    // "image/jpeg", "image/png", etc.
        let fileName: String    // filename for display
        let content: String     // base64-encoded image data
    }

    // MARK: - Dependencies

    private let connectionManager: GatewayDualConnectionManager

    // MARK: - State

    /// Current run ID from the most recent send (for abort support)
    private(set) var currentRunId: String?

    /// Session key to use for all chat operations (default "main").
    private(set) var sessionKey: String = "main"

    // MARK: - Initialization

    /// Initialize with the shared gateway connection manager.
    /// Must be called from MainActor context.
    @MainActor
    init() {
        self.connectionManager = .shared
    }

    // MARK: - Public API

    /// Send a message to the agent via gateway WebSocket.
    /// - Parameters:
    ///   - text: The message text
    ///   - images: Optional image attachments
    ///   - thinking: Thinking level ("low", "medium", "high", "none")
    /// - Returns: SendResponse with runId for abort support
    /// - Throws: GatewayError if not connected or request fails
    func sendMessage(
        text: String,
        images: [ImageAttachment] = [],
        thinking: String = "low"
    ) async throws -> SendResponse {
        // Convert image attachments to Data array
        var imageData: [Data]?
        if !images.isEmpty {
            imageData = images.compactMap { $0.getDataForUpload() }
            if imageData?.isEmpty == true {
                imageData = nil
            }
        }

        // Send via unified WebSocket connection
        let runId = try await connectionManager.sendMessage(text, images: imageData)
        currentRunId = runId
        
        return SendResponse(runId: runId, sessionKey: sessionKey)
    }

    /// Abort the current in-flight request via WebSocket.
    /// - Throws: GatewayError if not connected
    func abort() async throws {
        guard currentRunId != nil else {
            // No active run to abort
            return
        }

        try await connectionManager.abortRun()
        currentRunId = nil
    }

    /// Subscribe to chat events for the configured session.
    /// Note: In unified mode, WebSocket automatically subscribes on connect.
    /// This method is kept for API compatibility.
    func subscribe() async throws {
        // WebSocket handles subscription automatically
        print("[GatewayChatClient] subscribe() called - WebSocket handles this automatically")
    }

    /// Check if currently subscribed to chat events (has chat capability via operator connection)
    var isSubscribed: Bool {
        get async {
            await MainActor.run { connectionManager.status.hasChatCapability }
        }
    }

    /// Request chat history for the configured session via WebSocket.
    /// - Returns: Raw JSON data containing history (caller parses based on UI needs)
    /// - Throws: GatewayError if not connected or request fails
    func requestHistory() async throws -> Data {
        // Get raw history data from the unified WebSocket connection
        return try await connectionManager.loadHistory(limit: 200)
    }

    /// Update the session key used for all chat operations.
    /// - Parameter key: New session key to use
    func setSessionKey(_ key: String) async {
        sessionKey = key
        currentRunId = nil // Clear run ID since it's session-specific
        
        // Session key changes require reconfiguration
        print("[GatewayChatClient] Session key changed to '\(key)' - reconnect may be required")
        
        await MainActor.run {
            connectionManager.chatSessionKey = key
        }
    }

    /// Clear the current run state (called when response completes or connection drops)
    func clearRunState() {
        currentRunId = nil
    }

    // MARK: - Private Helpers

    /// Convert ImageAttachment to AttachmentPayload (kept for reference)
    private func imageToAttachment(_ image: ImageAttachment) -> AttachmentPayload? {
        guard let base64 = image.toBase64() else {
            print("[GatewayChatClient] Failed to encode image \(image.id) to base64")
            return nil
        }

        let ext = ImageAttachment.fileExtension(for: image.mediaType)
        let fileName = "\(image.id.uuidString.prefix(8)).\(ext)"

        return AttachmentPayload(
            type: "image",
            mimeType: image.mediaType,
            fileName: fileName,
            content: base64
        )
    }
}

// MARK: - Chat Event Types

/// Events received from the gateway's chat streaming.
/// These map to the ClawdbotChatEventPayload structure.
enum GatewayChatEvent: Sendable {
    /// Text delta from streaming response
    case textDelta(text: String, seq: Int?)

    /// Thinking text delta
    case thinkingDelta(text: String, seq: Int?)

    /// Tool call started
    case toolCallStart(name: String, id: String?)

    /// Tool call completed
    case toolCallEnd(name: String, id: String?, result: String?)

    /// Response generation completed
    case done(runId: String?, stopReason: String?, finalText: String?, seq: Int?)

    /// Error occurred during generation
    case error(code: String, message: String, seq: Int?)

    /// Agent status changed (busy, idle, etc.)
    case agentStatus(status: String)
}

/// Parser for raw chat event frames from the gateway.
/// Converts BridgeEventFrame with "chat" event into typed GatewayChatEvent.
struct GatewayChatEventParser {

    /// Agent event payload
    private struct AgentEventPayload: Codable {
        let status: String?
    }

    private let decoder = JSONDecoder()

    /// Parse a bridge event frame into a chat event.
    /// Returns nil if the event is not a chat event or cannot be parsed.
    func parse(_ frame: BridgeEventFrame) -> GatewayChatEvent? {
        guard let payloadJSON = frame.payloadJSON,
              let data = payloadJSON.data(using: .utf8) else {
            return nil
        }

        switch frame.event {
        case "chat":
            return parseStateChatEvent(data)
        case "agent":
            return parseAgentEvent(data)
        default:
            return nil
        }
    }

    private func parseStateChatEvent(_ data: Data) -> GatewayChatEvent? {
        guard let payload = try? JSONSerialization.jsonObject(with: data, options: []),
              let dict = payload as? [String: Any],
              let state = dict["state"] as? String else {
            return nil
        }

        let runId = dict["runId"] as? String
        let stopReason = dict["stopReason"] as? String
        let message = dict["message"]
        let seq = dict["seq"] as? Int

        switch state {
        case "delta":
            guard let text = extractText(from: message) else { return nil }
            return .textDelta(text: text, seq: seq)

        case "final":
            let text = extractText(from: message)
            return .done(runId: runId, stopReason: stopReason, finalText: text, seq: seq)

        case "aborted":
            return .done(runId: runId, stopReason: "aborted", finalText: nil, seq: seq)

        case "error":
            let errorMessage = dict["errorMessage"] as? String
            return .error(code: "ERROR", message: errorMessage ?? "Unknown error", seq: seq)

        default:
            return nil
        }
    }

    private func extractText(from message: Any?) -> String? {
        if let text = message as? String {
            return sanitizeText(text)
        }
        
        if let dict = message as? [String: Any] {
            if let text = dict["text"] as? String {
                return sanitizeText(text)
            }
            if let content = dict["content"] as? [Any] {
                let texts = content.compactMap { item -> String? in
                    guard let itemDict = item as? [String: Any] else { return nil }
                    let type = (itemDict["type"] as? String)?.lowercased()
                    if type == "text" || type == "thinking" {
                        return itemDict["text"] as? String
                    }
                    return nil
                }
                if !texts.isEmpty {
                    return sanitizeText(texts.joined())
                }
            }
        }
        
        return nil
    }

    private func sanitizeText(_ text: String) -> String {
        let patterns = ["\u{001B}\\[[0-9;]*[A-Za-z]", "\\[[0-9;]*[A-Za-z]"]
        var cleaned = text
        for pattern in patterns {
            if let regex = try? NSRegularExpression(pattern: pattern) {
                let range = NSRange(cleaned.startIndex..., in: cleaned)
                cleaned = regex.stringByReplacingMatches(in: cleaned, range: range, withTemplate: "")
            }
        }
        return cleaned
    }

    private func parseAgentEvent(_ data: Data) -> GatewayChatEvent? {
        guard let payload = try? decoder.decode(AgentEventPayload.self, from: data),
              let status = payload.status else {
            return nil
        }
        return .agentStatus(status: status)
    }
}
