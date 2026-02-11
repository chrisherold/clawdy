import Foundation
import OSLog
import UIKit

// MARK: - Gateway Connection

/// Shared WebSocket connection base for connecting to the Clawdbot gateway.
///
/// This actor handles:
/// - WebSocket connection lifecycle (connect/disconnect)
/// - Challenge-response authentication with device signature
/// - Request/response handling with timeouts
/// - Event streaming and push handling
/// - Watchdog/tick handling for connection health
/// - Automatic reconnection with exponential backoff
///
/// Used by `GatewayDualConnectionManager` to manage separate operator and node connections.
actor GatewayConnection {
    
    // MARK: - Types
    
    /// Connection role (determines which methods are allowed)
    enum Role: String, Sendable {
        case node = "node"
        case `operator` = "operator"
    }
    
    /// Connection state
    enum State: Sendable, Equatable {
        case disconnected
        case connecting
        case connected(serverName: String)
        case pairingPending
        case failed(reason: String)
        
        public var isConnected: Bool {
            if case .connected = self { return true }
            return false
        }
        
        public var isPairingPending: Bool {
            if case .pairingPending = self { return true }
            return false
        }
    }
    
    // MARK: - Configuration
    
    private let logger: Logger
    private let role: Role
    private let connectOptions: GatewayConnectOptions
    private let url: URL
    private var sharedToken: String?
    
    // MARK: - Connection State
    
    private var webSocket: URLSessionWebSocketTask?
    private var session: URLSession?
    private var pending: [String: CheckedContinuation<GatewayResponse, Error>] = [:]
    private(set) var state: State = .disconnected
    private var isConnecting = false
    private var connectWaiters: [CheckedContinuation<Void, Error>] = []
    private var backoffMs: Double = 500
    private var shouldReconnect = true
    private var allowAutoReconnect = true
    private var lastSeq: Int?
    private var lastTick: Date?
    private var tickIntervalMs: Double = 30000
    private var watchdogTask: Task<Void, Never>?
    private var tickTask: Task<Void, Never>?
    private var canvasHostUrl: String?
    
    // MARK: - Constants
    
    private let connectTimeoutSeconds: Double = 6
    private let connectChallengeTimeoutSeconds: Double = 3.0
    private let defaultRequestTimeoutMs: Double = 15000
    
    /// Enable verbose debug logging of all gateway messages
    static var verboseLogging = false
    
    // MARK: - Callbacks
    
    private var pushHandler: (@Sendable (GatewayPush) async -> Void)?
    private var disconnectHandler: (@Sendable (String) async -> Void)?
    private var invokeHandler: (@Sendable (BridgeInvokeRequest) async -> BridgeInvokeResponse)?
    private var stateChangeHandler: (@Sendable (State) async -> Void)?
    
    // MARK: - Initialization
    
    /// Create a new gateway connection.
    /// - Parameters:
    ///   - url: WebSocket URL (e.g., ws://host:18789)
    ///   - role: Connection role (operator or node)
    ///   - connectOptions: Connection options (scopes, caps, commands)
    ///   - sharedToken: Optional shared auth token (fallback if no device token)
    ///   - autoReconnect: Whether this connection should manage its own reconnect loop
    init(
        url: URL,
        role: Role,
        connectOptions: GatewayConnectOptions,
        sharedToken: String? = nil,
        autoReconnect: Bool = true
    ) {
        self.url = url
        self.role = role
        self.connectOptions = connectOptions
        self.sharedToken = sharedToken
        self.allowAutoReconnect = autoReconnect
        self.logger = Logger(subsystem: "com.clawdy", category: "gateway-\(role.rawValue)")
    }
    
    // MARK: - Handler Setup
    
    /// Set the push event handler.
    func setPushHandler(_ handler: (@Sendable (GatewayPush) async -> Void)?) {
        self.pushHandler = handler
    }
    
    /// Set the disconnect handler.
    func setDisconnectHandler(_ handler: (@Sendable (String) async -> Void)?) {
        self.disconnectHandler = handler
    }
    
    /// Set the invoke handler for node capabilities.
    func setInvokeHandler(_ handler: (@Sendable (BridgeInvokeRequest) async -> BridgeInvokeResponse)?) {
        self.invokeHandler = handler
    }
    
    /// Set the state change handler.
    func setStateChangeHandler(_ handler: (@Sendable (State) async -> Void)?) {
        self.stateChangeHandler = handler
    }
    
    // MARK: - Connection State Accessors
    
    /// Whether the connection is currently active.
    var isConnected: Bool {
        state.isConnected
    }
    
    /// Whether the connection is truly alive (state is connected AND WebSocket is running).
    /// Use this after returning from background to verify the connection is still valid.
    var isActuallyConnected: Bool {
        state.isConnected && webSocket?.state == .running
    }
    
    /// Current connection state.
    func currentState() -> State {
        state
    }
    
    /// Current canvas host URL from gateway.
    func currentCanvasHostUrl() -> String? {
        canvasHostUrl
    }
    
    /// Current remote address.
    func currentRemoteAddress() -> String? {
        guard let host = url.host else { return url.absoluteString }
        let port = url.port ?? (url.scheme == "wss" ? 443 : 80)
        if host.contains(":") {
            return "[\(host)]:\(port)"
        }
        return "\(host):\(port)"
    }
    
    // MARK: - Connection Management
    
    /// Connect to the gateway.
    func connect() async throws {
        if state.isConnected, webSocket?.state == .running { return }
        if isConnecting {
            try await withCheckedThrowingContinuation { cont in
                connectWaiters.append(cont)
            }
            return
        }
        isConnecting = true
        shouldReconnect = allowAutoReconnect
        await updateState(.connecting)
        defer { isConnecting = false }
        
        webSocket?.cancel(with: .goingAway, reason: nil)
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 300
        session = URLSession(configuration: config)
        webSocket = session?.webSocketTask(with: url)
        webSocket?.maximumMessageSize = 16 * 1024 * 1024 // 16 MB for large payloads
        
        webSocket?.resume()
        
        do {
            try await withTimeout(seconds: connectTimeoutSeconds) {
                try await self.sendConnect()
            }
        } catch {
            let wrapped = wrap(error, context: "connect to gateway @ \(url.absoluteString)")
            await updateState(.failed(reason: wrapped.localizedDescription))
            webSocket?.cancel(with: .goingAway, reason: nil)
            await disconnectHandler?("connect failed: \(wrapped.localizedDescription)")
            let waiters = connectWaiters
            connectWaiters.removeAll()
            for waiter in waiters {
                waiter.resume(throwing: wrapped)
            }
            logger.error("[\(self.role.rawValue)] ws connect failed: \(wrapped.localizedDescription, privacy: .public)")
            throw wrapped
        }
        
        listen()
        backoffMs = 500
        lastSeq = nil
        
        // Start watchdog (if auto reconnect enabled)
        if allowAutoReconnect {
            watchdogTask?.cancel()
            watchdogTask = Task { [weak self] in
                await self?.watchdogLoop()
            }
        }
        
        let waiters = connectWaiters
        connectWaiters.removeAll()
        for waiter in waiters {
            waiter.resume(returning: ())
        }
    }
    
    /// Disconnect from the gateway.
    func shutdown() async {
        shouldReconnect = false
        await updateState(.disconnected)
        
        watchdogTask?.cancel()
        watchdogTask = nil
        
        tickTask?.cancel()
        tickTask = nil
        
        webSocket?.cancel(with: .goingAway, reason: nil)
        webSocket = nil
        
        session?.invalidateAndCancel()
        session = nil
        
        await failPending(NSError(
            domain: "Gateway",
            code: 0,
            userInfo: [NSLocalizedDescriptionKey: "gateway channel shutdown"]))
        
        let waiters = connectWaiters
        connectWaiters.removeAll()
        for waiter in waiters {
            waiter.resume(throwing: NSError(
                domain: "Gateway",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "gateway channel shutdown"]))
        }
    }
    
    /// Enable or disable automatic reconnection.
    func setShouldReconnect(_ value: Bool) {
        shouldReconnect = value
    }

    /// Enable or disable internal auto-reconnect management.
    func setAutoReconnect(_ value: Bool) {
        allowAutoReconnect = value
        shouldReconnect = value
    }
    
    // MARK: - State Updates
    
    private func updateState(_ newState: State) async {
        guard state != newState else { return }
        state = newState
        await stateChangeHandler?(newState)
    }
    
    // MARK: - Connect Handshake
    
    private func sendConnect() async throws {
        let platform = "iOS"
        let primaryLocale = Locale.preferredLanguages.first ?? Locale.current.identifier
        let deviceName = await MainActor.run { UIDevice.current.name }
        let deviceFamily = await MainActor.run { UIDevice.current.userInterfaceIdiom == .pad ? "iPad" : "iPhone" }
        let clientDisplayName = connectOptions.clientDisplayName ?? deviceName
        let clientId = connectOptions.clientId
        let clientMode = connectOptions.clientMode
        let roleString = role.rawValue
        let scopes = connectOptions.scopes
        
        let reqId = UUID().uuidString
        var client: [String: Any] = [
            "id": clientId,
            "displayName": clientDisplayName,
            "version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev",
            "platform": platform,
            "mode": clientMode,
            "instanceId": DeviceIdentityStore.loadOrCreate().deviceId,
            "deviceFamily": deviceFamily,
        ]
        if let model = getModelIdentifier() {
            client["modelIdentifier"] = model
        }
        
        var params: [String: Any] = [
            "minProtocol": GATEWAY_PROTOCOL_VERSION,
            "maxProtocol": GATEWAY_PROTOCOL_VERSION,
            "client": client,
            "caps": connectOptions.caps,
            "locale": primaryLocale,
            "userAgent": ProcessInfo.processInfo.operatingSystemVersionString,
            "role": roleString,
            "scopes": scopes,
        ]
        if !connectOptions.commands.isEmpty {
            params["commands"] = connectOptions.commands
        }
        if !connectOptions.permissions.isEmpty {
            params["permissions"] = connectOptions.permissions
        }
        
        // Load device identity and stored token
        let identity = DeviceIdentityStore.loadOrCreate()
        let storedToken = DeviceAuthStore.loadToken(deviceId: identity.deviceId, role: roleString)?.token
        let authToken = storedToken ?? sharedToken
        let canFallbackToShared = storedToken != nil && sharedToken != nil
        
        // Debug logging for auth token source
        if storedToken != nil {
            logger.info("[\(self.role.rawValue)] using stored device token")
        } else if sharedToken != nil {
            logger.info("[\(self.role.rawValue)] using shared auth token (no stored device token)")
        } else {
            logger.info("[\(self.role.rawValue)] no auth token available - will need pairing")
        }
        
        if let authToken = authToken {
            params["auth"] = ["token": authToken]
        }
        
        // Build device signature for authentication
        let signedAtMs = Int(Date().timeIntervalSince1970 * 1000)
        let connectNonce = try await waitForConnectChallenge()
        let scopesValue = scopes.joined(separator: ",")
        var payloadParts = [
            connectNonce == nil ? "v1" : "v2",
            identity.deviceId,
            clientId,
            clientMode,
            roleString,
            scopesValue,
            String(signedAtMs),
            authToken ?? "",
        ]
        if let connectNonce = connectNonce {
            payloadParts.append(connectNonce)
        }
        let payload = payloadParts.joined(separator: "|")
        
        if let signature = DeviceIdentityStore.signPayload(payload, identity: identity),
           let publicKey = DeviceIdentityStore.publicKeyBase64Url(identity) {
            var device: [String: Any] = [
                "id": identity.deviceId,
                "publicKey": publicKey,
                "signature": signature,
                "signedAt": signedAtMs,
            ]
            if let connectNonce = connectNonce {
                device["nonce"] = connectNonce
            }
            params["device"] = device
        }
        
        let frame: [String: Any] = [
            "type": "req",
            "id": reqId,
            "method": "connect",
            "params": params,
        ]
        
        let data = try JSONSerialization.data(withJSONObject: frame)
        try await webSocket?.send(.data(data))
        
        do {
            let response = try await waitForConnectResponse(reqId: reqId)
            try await handleConnectResponse(response, identity: identity, role: roleString)
        } catch {
            if canFallbackToShared,
               case ConnectFailure.authFailure = error {
                DeviceAuthStore.clearToken(deviceId: identity.deviceId, role: roleString)
            }
            throw error
        }
    }
    
    private func waitForConnectChallenge() async throws -> String? {
        guard let ws = webSocket else {
            logger.warning("[\(self.role.rawValue)] waitForConnectChallenge: no websocket")
            return nil
        }
        logger.info("[\(self.role.rawValue)] waiting for connect.challenge (timeout: \(self.connectChallengeTimeoutSeconds)s)...")
        do {
            let nonce: String? = try await withTimeout(seconds: connectChallengeTimeoutSeconds) { [weak self] () -> String? in
                guard let self = self else { return nil }
                while true {
                    let msg = try await ws.receive()
                    guard let data = self.decodeMessageData(msg) else { continue }
                    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                          let type = json["type"] as? String,
                          type == "event",
                          let event = json["event"] as? String,
                          event == "connect.challenge" else {
                        // Log unexpected messages while waiting for challenge
                        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                            self.logger.info("[\(self.role.rawValue)] waitForConnectChallenge: got non-challenge message: \(String(describing: json["type"]), privacy: .public)")
                        }
                        continue
                    }
                    if let payload = json["payload"] as? [String: Any],
                       let nonce = payload["nonce"] as? String {
                        self.logger.info("[\(self.role.rawValue)] received connect.challenge with nonce")
                        return nonce
                    }
                }
            }
            return nonce
        } catch {
            if error is ConnectChallengeError {
                logger.warning("[\(self.role.rawValue)] connect.challenge timeout - aborting connect (nonce required)")
                throw error
            }
            if !Task.isCancelled {
                if error is CancellationError {
                    logger.warning("[\(self.role.rawValue)] connect.challenge cancelled - aborting connect")
                    throw error
                }
                if let urlError = error as? URLError, urlError.code == .cancelled {
                    logger.warning("[\(self.role.rawValue)] connect.challenge cancelled (URLSession) - aborting connect")
                    throw error
                }
            }
            logger.error("[\(self.role.rawValue)] waitForConnectChallenge error: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }
    
    private func waitForConnectResponse(reqId: String) async throws -> [String: Any] {
        guard let ws = webSocket else {
            throw NSError(
                domain: "Gateway",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "connect failed (no response)"])
        }
        while true {
            let msg = try await ws.receive()
            guard let data = decodeMessageData(msg) else { continue }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let type = json["type"] as? String,
                  type == "res",
                  let id = json["id"] as? String,
                  id == reqId else { continue }
            return json
        }
    }
    
    private func handleConnectResponse(
        _ res: [String: Any],
        identity: DeviceIdentity,
        role: String
    ) async throws {
        if let ok = res["ok"] as? Bool, !ok {
            let errorDict = res["error"] as? [String: Any]
            let msg = (errorDict?["message"] as? String) ?? "gateway connect failed"
            let lowercased = msg.lowercased()

            // Check for pairing required error
            if lowercased.contains("pairing required") {
                logger.warning("[\(self.role.rawValue)] pairing required: \(msg, privacy: .public)")
                await updateState(.pairingPending)
            } else if lowercased.contains("auth") || lowercased.contains("token") || lowercased.contains("unauthorized") || lowercased.contains("forbidden") {
                logger.error("[\(self.role.rawValue)] auth failure: \(msg, privacy: .public)")
                throw ConnectFailure.authFailure(msg)
            }
            
            throw NSError(domain: "Gateway", code: 1008, userInfo: [NSLocalizedDescriptionKey: msg])
        }
        
        guard let payload = res["payload"] as? [String: Any] else {
            throw NSError(
                domain: "Gateway",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "connect failed (missing payload)"])
        }
        
        // Extract server info
        let serverName = payload["serverName"] as? String ?? "Gateway"
        canvasHostUrl = (payload["canvasHostUrl"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        if canvasHostUrl?.isEmpty == true { canvasHostUrl = nil }
        
        // Extract tick interval
        let policy = payload["policy"] as? [String: Any] ?? [:]
        if let tick = policy["tickIntervalMs"] as? Double {
            tickIntervalMs = tick
        } else if let tick = policy["tickIntervalMs"] as? Int {
            tickIntervalMs = Double(tick)
        }
        
        // Store device token if issued
        if let auth = payload["auth"] as? [String: Any],
           let deviceToken = auth["deviceToken"] as? String {
            let authRole = auth["role"] as? String ?? role
            let scopes = (auth["scopes"] as? [String]) ?? []
            let stored = DeviceAuthStore.storeToken(
                deviceId: identity.deviceId,
                role: authRole,
                token: deviceToken,
                scopes: scopes)
            if stored != nil {
                logger.info("[\(self.role.rawValue)] stored device token for role=\(authRole, privacy: .public)")
            } else {
                logger.error("[\(self.role.rawValue)] failed to store device token")
            }
        } else {
            logger.info("[\(self.role.rawValue)] no device token in connect response")
        }
        
        // Start tick watchdog
        lastTick = Date()
        tickTask?.cancel()
        tickTask = Task { [weak self] in
            await self?.watchTicks()
        }
        
        // Update state to connected
        await updateState(.connected(serverName: serverName))
        
        // Notify snapshot
        let snapshotPayload = HelloOkPayload(
            serverName: serverName,
            canvasHostUrl: canvasHostUrl,
            policy: policy,
            auth: payload["auth"] as? [String: Any]
        )
        await pushHandler?(.snapshot(snapshotPayload))
    }
    
    // MARK: - Message Receive Loop
    
    private func listen() {
        webSocket?.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case let .failure(err):
                Task { await self.handleReceiveFailure(err) }
            case let .success(msg):
                Task {
                    await self.handle(msg)
                    await self.listen()
                }
            }
        }
    }
    
    private func handleReceiveFailure(_ err: Error) async {
        let wrapped = wrap(err, context: "gateway receive")
        logger.error("[\(self.role.rawValue)] ws receive failed: \(wrapped.localizedDescription, privacy: .public)")
        await updateState(.failed(reason: wrapped.localizedDescription))
        await disconnectHandler?("receive failed: \(wrapped.localizedDescription)")
        await failPending(wrapped)
        if allowAutoReconnect {
            await scheduleReconnect()
        }
    }
    
    private func handle(_ msg: URLSessionWebSocketTask.Message) async {
        guard let data = decodeMessageData(msg) else { return }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else { return }
        
        // Verbose debug logging - log all messages except ticks
        if Self.verboseLogging {
            let eventName = json["event"] as? String
            if eventName != "tick" {  // Skip tick spam
                if let prettyData = try? JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]),
                   let prettyString = String(data: prettyData, encoding: .utf8) {
                    logger.debug("← RECV \(type, privacy: .public):\n\(prettyString, privacy: .public)")
                } else {
                    logger.debug("← RECV \(type, privacy: .public): \(String(describing: json), privacy: .public)")
                }
            }
        }
        
        switch type {
        case "res":
            await handleResponse(json)
        case "event":
            await handleEvent(json)
        case "ping":
            if let id = json["id"] as? String {
                try? await sendJSON(["type": "pong", "id": id])
            }
        default:
            break
        }
    }
    
    private func handleResponse(_ json: [String: Any]) async {
        guard let id = json["id"] as? String,
              let waiter = pending.removeValue(forKey: id) else { return }
        
        let response = GatewayResponse(
            id: id,
            ok: json["ok"] as? Bool ?? false,
            payload: json["payload"] as? [String: Any],
            error: json["error"] as? [String: Any]
        )
        waiter.resume(returning: response)
    }
    
    private func handleEvent(_ json: [String: Any]) async {
        guard let eventName = json["event"] as? String else { return }
        
        // Ignore connect.challenge (handled separately)
        if eventName == "connect.challenge" { return }
        
        let payload = json["payload"] as? [String: Any]
        let seq = json["seq"] as? Int
        
        // Track sequence gaps
        if let seq = seq {
            if let last = lastSeq, seq > last + 1 {
                await pushHandler?(.seqGap(expected: last + 1, received: seq))
            }
            lastSeq = seq
        }
        
        // Handle tick - gateway sends these periodically to keep connection alive
        if eventName == "tick" {
            let now = Date()
            if let last = lastTick {
                let delta = now.timeIntervalSince(last)
                if delta > 45 {  // Log if more than 45s between ticks (unusual)
                    logger.warning("[\(self.role.rawValue)] tick received after \(String(format: "%.1f", delta))s gap")
                }
            }
            lastTick = now
        }
        
        // Handle node invoke requests (only for node role)
        if eventName == "node.invoke.request" && role == .node {
            await handleNodeInvoke(payload)
            return
        }
        
        // Forward to push handler
        let event = GatewayEvent(event: eventName, payload: payload, seq: seq)
        await pushHandler?(.event(event))
    }
    
    private func handleNodeInvoke(_ payload: [String: Any]?) async {
        guard let payload = payload,
              let id = payload["id"] as? String,
              let nodeId = payload["nodeId"] as? String,
              let command = payload["command"] as? String else { return }
        
        let paramsJSON = payload["paramsJSON"] as? String
        let timeoutMs = payload["timeoutMs"] as? Int
        
        // Convert to BridgeInvokeRequest for compatibility
        let request = BridgeInvokeRequest(
            type: "invoke",
            id: id,
            command: command,
            paramsJSON: paramsJSON
        )
        
        // Call invoke handler with timeout if specified
        let response: BridgeInvokeResponse
        if let handler = invokeHandler {
            if let timeoutMs = timeoutMs, timeoutMs > 0 {
                response = await invokeWithTimeout(request: request, timeoutMs: timeoutMs, handler: handler)
            } else {
                response = await handler(request)
            }
        } else {
            response = BridgeInvokeResponse(
                id: id,
                ok: false,
                error: BridgeNodeError(code: .unavailable, message: "No invoke handler")
            )
        }
        
        // Send result
        await sendInvokeResult(id: id, nodeId: nodeId, response: response)
    }
    
    private func invokeWithTimeout(
        request: BridgeInvokeRequest,
        timeoutMs: Int,
        handler: @escaping @Sendable (BridgeInvokeRequest) async -> BridgeInvokeResponse
    ) async -> BridgeInvokeResponse {
        return await withTaskGroup(of: BridgeInvokeResponse.self) { group in
            group.addTask { await handler(request) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeoutMs) * 1_000_000)
                return BridgeInvokeResponse(
                    id: request.id,
                    ok: false,
                    error: BridgeNodeError(
                        code: .unavailable,
                        message: "node invoke timed out")
                )
            }
            
            let first = await group.next()!
            group.cancelAll()
            return first
        }
    }
    
    private func sendInvokeResult(id: String, nodeId: String, response: BridgeInvokeResponse) async {
        var params: [String: Any] = [
            "id": id,
            "nodeId": nodeId,
            "ok": response.ok,
        ]
        if let payloadJSON = response.payloadJSON {
            params["payloadJSON"] = payloadJSON
        }
        if let error = response.error {
            params["error"] = [
                "code": error.code.rawValue,
                "message": error.message,
            ]
        }
        
        do {
            _ = try await request(method: "node.invoke.result", params: params, timeoutMs: 15000)
        } catch {
            logger.error("[\(self.role.rawValue)] node invoke result failed: \(error.localizedDescription, privacy: .public)")
        }
    }
    
    // MARK: - RPC Requests
    
    /// Send an RPC request to the gateway.
    /// - Parameters:
    ///   - method: RPC method name
    ///   - params: Request parameters
    ///   - timeoutMs: Timeout in milliseconds (default 15000)
    /// - Returns: Response payload as Data
    func request(
        method: String,
        params: [String: Any]?,
        timeoutMs: Double? = nil
    ) async throws -> Data {
        guard state.isConnected else {
            throw NSError(
                domain: "Gateway",
                code: 0,
                userInfo: [NSLocalizedDescriptionKey: "not connected"])
        }
        
        let id = UUID().uuidString
        let effectiveTimeout = timeoutMs ?? defaultRequestTimeoutMs
        
        let frame: [String: Any] = [
            "type": "req",
            "id": id,
            "method": method,
            "params": params as Any,
        ]
        
        let data: Data
        do {
            data = try JSONSerialization.data(withJSONObject: frame)
        } catch {
            logger.error("[\(self.role.rawValue)] request encode failed \(method, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
        
        // Verbose debug logging for outgoing messages
        if Self.verboseLogging && method != "connect" {
            if let prettyData = try? JSONSerialization.data(withJSONObject: frame, options: [.prettyPrinted, .sortedKeys]),
               let prettyString = String(data: prettyData, encoding: .utf8) {
                logger.debug("→ SEND \(method, privacy: .public):\n\(prettyString, privacy: .public)")
            }
        }
        
        // Send the request
        do {
            try await webSocket?.send(.data(data))
        } catch {
            let wrapped = wrap(error, context: "gateway send \(method)")
            await updateState(.failed(reason: wrapped.localizedDescription))
            webSocket?.cancel(with: .goingAway, reason: nil)
            if allowAutoReconnect {
                Task { [weak self] in
                    await self?.scheduleReconnect()
                }
            }
            throw wrapped
        }
        
        // Wait for response with timeout
        let response = try await withCheckedThrowingContinuation { (cont: CheckedContinuation<GatewayResponse, Error>) in
            pending[id] = cont
            
            // Timeout task
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(effectiveTimeout * 1_000_000))
                await self?.timeoutRequest(id: id, timeoutMs: effectiveTimeout)
            }
        }
        
        if !response.ok {
            let code = response.error?["code"] as? String
            let msg = response.error?["message"] as? String
            throw GatewayResponseError(method: method, code: code, message: msg, details: response.error ?? [:])
        }
        
        if let payload = response.payload {
            return try JSONSerialization.data(withJSONObject: payload)
        }
        return Data()
    }
    
    // MARK: - Watchdog
    
    private func watchdogLoop() async {
        while shouldReconnect {
            try? await Task.sleep(nanoseconds: 30 * 1_000_000_000)
            guard shouldReconnect else { return }
            if state.isConnected { continue }
            do {
                try await connect()
            } catch {
                let wrapped = wrap(error, context: "gateway watchdog reconnect")
                logger.error("[\(self.role.rawValue)] watchdog reconnect failed: \(wrapped.localizedDescription, privacy: .public)")
            }
        }
    }
    
    private func watchTicks() async {
        // Use 2.5x tolerance to be more forgiving of network jitter
        let tolerance = tickIntervalMs * 2.5
        while state.isConnected {
            try? await Task.sleep(nanoseconds: UInt64(tolerance * 1_000_000))
            guard state.isConnected else { return }
            if let last = lastTick {
                let delta = Date().timeIntervalSince(last) * 1000
                if delta > tolerance {
                    let message = allowAutoReconnect ? "tick missed; reconnecting" : "tick missed; connection stale"
                    logger.error("[\(self.role.rawValue)] \(message)")
                    await updateState(.failed(reason: message))
                    await failPending(
                        NSError(
                            domain: "Gateway",
                            code: 4,
                            userInfo: [NSLocalizedDescriptionKey: message]))
                    if allowAutoReconnect {
                        await scheduleReconnect()
                    }
                    return
                }
            }
        }
    }
    
    private func scheduleReconnect() async {
        guard shouldReconnect else { return }
        let delay = backoffMs / 1000
        backoffMs = min(backoffMs * 2, 30000)
        try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        guard shouldReconnect else { return }
        do {
            try await connect()
        } catch {
            let wrapped = wrap(error, context: "gateway reconnect")
            logger.error("[\(self.role.rawValue)] reconnect failed: \(wrapped.localizedDescription, privacy: .public)")
            await scheduleReconnect()
        }
    }
    
    // MARK: - Helpers
    
    private func sendJSON(_ dict: [String: Any]) async throws {
        if Self.verboseLogging {
            let method = dict["method"] as? String ?? dict["type"] as? String ?? "unknown"
            // Skip logging pong responses (noisy)
            if method != "pong" {
                if let prettyData = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted, .sortedKeys]),
                   let prettyString = String(data: prettyData, encoding: .utf8) {
                    logger.debug("→ SEND \(method, privacy: .public):\n\(prettyString, privacy: .public)")
                }
            }
        }
        
        let data = try JSONSerialization.data(withJSONObject: dict)
        try await webSocket?.send(.data(data))
    }
    
    private nonisolated func decodeMessageData(_ msg: URLSessionWebSocketTask.Message) -> Data? {
        switch msg {
        case let .data(data): return data
        case let .string(text): return text.data(using: .utf8)
        @unknown default: return nil
        }
    }
    
    private func failPending(_ error: Error) async {
        let waiters = pending
        pending.removeAll()
        for (_, waiter) in waiters {
            waiter.resume(throwing: error)
        }
    }
    
    private func timeoutRequest(id: String, timeoutMs: Double) async {
        guard let waiter = pending.removeValue(forKey: id) else { return }
        let err = NSError(
            domain: "Gateway",
            code: 5,
            userInfo: [NSLocalizedDescriptionKey: "gateway request timed out after \(Int(timeoutMs))ms"])
        waiter.resume(throwing: err)
    }
    
    private func wrap(_ error: Error, context: String) -> Error {
        if let urlError = error as? URLError {
            let desc = urlError.localizedDescription.isEmpty ? "cancelled" : urlError.localizedDescription
            return NSError(
                domain: URLError.errorDomain,
                code: urlError.errorCode,
                userInfo: [NSLocalizedDescriptionKey: "\(context): \(desc)"])
        }
        let ns = error as NSError
        let desc = ns.localizedDescription.isEmpty ? "unknown" : ns.localizedDescription
        return NSError(domain: ns.domain, code: ns.code, userInfo: [NSLocalizedDescriptionKey: "\(context): \(desc)"])
    }
    
    private func withTimeout<T>(
        seconds: Double,
        operation: @escaping () async throws -> T
    ) async throws -> T {
        // Use Result to wrap both success and timeout cases
        try await withThrowingTaskGroup(of: Result<T, Error>.self) { group in
            group.addTask {
                do {
                    let value = try await operation()
                    return .success(value)
                } catch {
                    return .failure(error)
                }
            }
            group.addTask {
                do {
                    try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                    return .failure(ConnectChallengeError.timeout)
                } catch {
                    // Sleep was cancelled - return cancellation error
                    return .failure(error)
                }
            }
            
            // Get first completed result
            guard let first = try await group.next() else {
                throw ConnectChallengeError.timeout
            }
            
            group.cancelAll()
            
            switch first {
            case .success(let value):
                return value
            case .failure(let error):
                throw error
            }
        }
    }
    
    private func getModelIdentifier() -> String? {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(validatingUTF8: $0)
            }
        }
        return machine
    }
}

// MARK: - Gateway Response (Private)

private struct GatewayResponse {
    var id: String
    var ok: Bool
    var payload: [String: Any]?
    var error: [String: Any]?
    
    init(id: String, ok: Bool, payload: [String: Any]?, error: [String: Any]?) {
        self.id = id
        self.ok = ok
        self.payload = payload
        self.error = error
    }
}

extension GatewayResponse: @unchecked Sendable {}

// MARK: - Connect Failure Error

private enum ConnectFailure: Error {
    case authFailure(String)
}

// MARK: - Connect Challenge Error

private enum ConnectChallengeError: Error {
    case timeout
}
