import Foundation
import Combine
import OSLog
import UIKit

// MARK: - Dual Connection Status

/// Combined connection status for both operator and node connections.
enum DualConnectionStatus: Equatable, Sendable {
    case disconnected
    case connecting
    case partialOperator    // Only operator connected (chat works, no invokes)
    case partialNode        // Only node connected (invokes work, no chat)
    case connected          // Both connected (full functionality)
    case pairingPendingOperator  // Operator connection waiting for pairing
    case pairingPendingNode      // Node connection waiting for pairing
    case pairingPendingBoth      // Both connections waiting for pairing
    
    var isConnected: Bool {
        return self == .connected
    }
    
    var isPartiallyConnected: Bool {
        return self == .partialOperator || self == .partialNode
    }
    
    var hasChatCapability: Bool {
        return self == .connected || self == .partialOperator
    }
    
    var hasNodeCapability: Bool {
        return self == .connected || self == .partialNode
    }
    
    var isPairingPending: Bool {
        switch self {
        case .pairingPendingOperator, .pairingPendingNode, .pairingPendingBoth:
            return true
        default:
            return false
        }
    }
    
    var displayText: String {
        switch self {
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting..."
        case .partialOperator:
            return "Connected (chat only)"
        case .partialNode:
            return "Connected (node only)"
        case .connected:
            return "Connected"
        case .pairingPendingOperator:
            return "Pairing pending (operator)"
        case .pairingPendingNode:
            return "Pairing pending (node)"
        case .pairingPendingBoth:
            return "Pairing pending"
        }
    }
    
    var statusColor: String {
        switch self {
        case .disconnected:
            return "red"
        case .connecting, .pairingPendingOperator, .pairingPendingNode, .pairingPendingBoth:
            return "yellow"
        case .partialOperator, .partialNode:
            return "orange"
        case .connected:
            return "green"
        }
    }
}

enum GatewayConnectionFailure: Equatable, Sendable {
    case none
    case hostUnreachable(reason: String)
    case other(reason: String)
}

// MARK: - Gateway Dual Connection Manager

/// Manages dual WebSocket connections for operator (chat) and node (capabilities) roles.
///
/// The Clawdbot gateway enforces strict role separation:
/// - **Operator role**: Required for `chat.send`, `chat.history`, `chat.abort`
/// - **Node role**: Required for receiving `node.invoke.request` and sending `node.invoke.result`
///
/// Both connections share the same device identity (Ed25519 keypair) but have separate
/// device tokens stored per role in `DeviceAuthStore`.
///
/// ## Usage
/// ```swift
/// let manager = GatewayDualConnectionManager.shared
/// await manager.connect(credentials: credentials)
///
/// // Chat operations → operator connection
/// try await manager.sendMessage("Hello")
///
/// // Invokes handled automatically via node connection
/// ```
@MainActor
class GatewayDualConnectionManager: ObservableObject {
    
    // MARK: - Singleton
    
    static let shared = GatewayDualConnectionManager()
    
    // MARK: - Published State
    
    /// Combined connection status for both connections
    @Published public private(set) var status: DualConnectionStatus = .disconnected
    
    /// Server name from the operator connection (if connected)
    @Published public private(set) var serverName: String?
    
    /// Whether auto-connect is enabled
    @Published public var autoConnectEnabled: Bool = true

    /// Whether the gateway auth token is missing (blocking connection attempts)
    @Published public private(set) var authTokenMissing: Bool = false

    /// Track the last connection failure classification
    @Published public private(set) var lastFailure: GatewayConnectionFailure = .none
    
    // MARK: - Private State
    
    private let logger = Logger(subsystem: "com.clawdy", category: "dual-connection")
    
    /// Operator connection for chat operations
    private var operatorConnection: GatewayConnection?
    
    /// Node connection for capability invokes
    private var nodeConnection: GatewayConnection?
    
    /// Track individual connection states
    private var operatorState: GatewayConnection.State = .disconnected
    private var nodeState: GatewayConnection.State = .disconnected
    
    /// Track whether we're in the middle of a connect operation
    private var isConnecting = false
    
    /// Whether user manually disconnected
    private var isManuallyDisconnected = false
    
    /// Stored credentials for reconnection
    private var currentCredentials: KeychainManager.GatewayCredentials?
    
    /// Background task for maintaining connection
    private var backgroundTaskId: UIBackgroundTaskIdentifier = .invalid
    
    /// Whether we were connected before entering background
    private var wasConnectedBeforeBackground = false

    /// Whether VPN reconnected while app was in background
    private var pendingVPNReconnect = false
    
    /// Connection loop tasks (one per role)
    private var operatorConnectLoopTask: Task<Void, Never>?
    private var nodeConnectLoopTask: Task<Void, Never>?

    /// Track pairing pending start times
    private var operatorPairingStartedAt: Date?
    private var nodePairingStartedAt: Date?
    
    /// Current backoff delay per connection (milliseconds)
    private var operatorBackoffMs: Double = 500
    private var nodeBackoffMs: Double = 500
    
    /// Maximum backoff delay (milliseconds)
    private let maxBackoffMs: Double = 30_000
    
    /// How long to keep retrying pairing before giving up (seconds)
    private let pairingTimeoutSeconds: TimeInterval = 5 * 60
    
    /// How often to retry connecting while waiting for pairing (seconds)
    private let pairingRetryIntervalSeconds: UInt64 = 5
    
    // MARK: - Dependencies
    
    private let vpnMonitor = VPNStatusMonitor.shared
    private let keychain = KeychainManager.shared
    private let capabilityHandler = NodeCapabilityHandler()
    
    private var cancellables = Set<AnyCancellable>()
    
    // MARK: - Callbacks
    
    /// Callback for when the gateway invokes a node capability
    var onInvoke: (@Sendable (BridgeInvokeRequest) async -> BridgeInvokeResponse)?
    
    /// Callback for parsed chat/agent events from the gateway
    var onChatEvent: (@Sendable (GatewayChatEvent) -> Void)?
    
    /// Session key for chat events
    var chatSessionKey: String = "agent:main:main"
    
    /// Callback for when app returns to foreground while still connected
    var onDidBecomeActiveWhileConnected: (() -> Void)?
    
    // MARK: - Initialization
    
    private init() {
        // Load verbose logging setting from UserDefaults
        GatewayConnection.verboseLogging = UserDefaults.standard.bool(forKey: "com.clawdy.debug.verboseLogging")
        
        setupVPNMonitoring()
    }
    
    // MARK: - VPN Monitoring
    
    private func setupVPNMonitoring() {
        vpnMonitor.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.handleVPNStatusChange(status)
            }
            .store(in: &cancellables)
    }
    
    private func handleVPNStatusChange(_ vpnStatus: VPNStatus) {
        switch vpnStatus {
        case .connected:
            guard autoConnectEnabled, !isManuallyDisconnected else { return }
            guard keychain.hasGatewayCredentials() else { return }
            guard !status.isConnected, !isConnecting else { return }

            let appIsActive = UIApplication.shared.applicationState == .active
            if appIsActive {
                Task { @MainActor in
                    await self.connectIfNeeded()
                }
            } else {
                pendingVPNReconnect = true
                logger.info("VPN connected in background; deferring reconnect until foreground")
            }
            
        case .disconnected:
            pendingVPNReconnect = false
            logger.info("VPN disconnected; attempting auto-connect if configured")

            guard autoConnectEnabled, !isManuallyDisconnected else { return }
            guard keychain.hasGatewayCredentials() else { return }
            guard !status.isConnected, !isConnecting else { return }

            Task { @MainActor in
                await self.connectIfNeeded()
            }
            
        case .unknown:
            break
        }
    }
    
    // MARK: - Connection Management

    private func requiresAuthToken(for host: String) -> Bool {
        let normalized = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1" {
            return false
        }
        if normalized.hasPrefix("127.") {
            return false
        }
        return true
    }

    private func isAuthTokenMissing(for credentials: KeychainManager.GatewayCredentials) -> Bool {
        guard requiresAuthToken(for: credentials.host) else { return false }
        let token = credentials.authToken?.trimmingCharacters(in: .whitespacesAndNewlines)
        return token?.isEmpty ?? true
    }

    private func updateAuthTokenMissing(_ missing: Bool) {
        guard authTokenMissing != missing else { return }
        authTokenMissing = missing
    }

    private func handleMissingAuthToken() {
        updateAuthTokenMissing(true)
        isConnecting = false
        status = .disconnected
        logger.warning("Cannot connect - auth token missing")
    }

    private func isHostUnreachable(reason: String) -> Bool {
        let normalized = reason.lowercased()
        let matches = [
            "could not find host",
            "dns lookup failed",
            "timed out",
            "timeout",
            "connection refused",
            "network is unreachable",
            "not connected to the internet",
        ]
        return matches.contains { normalized.contains($0) }
    }

    private func updateLastFailure(reason: String) {
        if isHostUnreachable(reason: reason) {
            lastFailure = .hostUnreachable(reason: reason)
        } else {
            lastFailure = .other(reason: reason)
        }
    }

    private func clearLastFailure() {
        if lastFailure != .none {
            lastFailure = .none
        }
    }
    
    /// Connect both operator and node connections if not already connected.
    func connectIfNeeded() async {
        logger.info("connectIfNeeded called, status=\(self.status.displayText)")
        
        if status.isConnected || isConnecting {
            return
        }
        
        guard let credentials = keychain.loadGatewayCredentials() else {
            status = .disconnected
            updateAuthTokenMissing(false)
            logger.warning("Cannot connect - no gateway credentials")
            return
        }

        if isAuthTokenMissing(for: credentials) {
            handleMissingAuthToken()
            return
        }
        updateAuthTokenMissing(false)

        await connect(credentials: credentials)
    }
    
    /// Connect to the gateway with specific credentials.
    func connect(credentials: KeychainManager.GatewayCredentials) async {
        if isAuthTokenMissing(for: credentials) {
            handleMissingAuthToken()
            return
        }
        updateAuthTokenMissing(false)
        isManuallyDisconnected = false
        pendingVPNReconnect = false
        stopConnectLoops()
        isConnecting = true
        currentCredentials = credentials
        
        // Reset backoff values for fresh connection
        operatorBackoffMs = 500
        nodeBackoffMs = 500
        
        // Only update status to connecting if we're not in a pairing state
        if !status.isPairingPending {
            status = .connecting
        }
        
        logger.info("Connecting to \(credentials.host) with dual connections")
        
        // Build WebSocket URL
        // For TLS connections, use port 443 (standard HTTPS, used by Tailscale Serve)
        // For non-TLS connections, use the gateway's native WebSocket port
        let scheme = credentials.useTLS ? "wss" : "ws"
        let port = credentials.useTLS ? 443 : GATEWAY_WS_PORT
        guard let url = URL(string: "\(scheme)://\(credentials.host):\(port)") else {
            status = .disconnected
            isConnecting = false
            logger.error("Invalid gateway URL")
            return
        }
        
        let sharedToken = credentials.authToken
        let deviceName = await MainActor.run { UIDevice.current.name }
        
        // Create operator connection for chat operations
        let operatorOptions = GatewayConnectOptions.forOperator(displayName: deviceName)
        operatorConnection = GatewayConnection(
            url: url,
            role: .operator,
            connectOptions: operatorOptions,
            sharedToken: sharedToken,
            autoReconnect: false
        )
        
        // Create node connection
        let nodeOptions = GatewayConnectOptions.forNode(displayName: deviceName)
        nodeConnection = GatewayConnection(
            url: url,
            role: .node,
            connectOptions: nodeOptions,
            sharedToken: sharedToken,
            autoReconnect: false
        )
        
        // Set up handlers
        await setupOperatorHandlers()
        await setupNodeHandlers()

        // Start connect loops
        startOperatorLoop()
    }
    
    /// Set up handlers for the operator connection.
    private func setupOperatorHandlers() async {
        await operatorConnection?.setStateChangeHandler { @MainActor [weak self] state in
            self?.handleOperatorStateChange(state)
        }
        
        await operatorConnection?.setPushHandler { @MainActor [weak self] push in
            await self?.handleOperatorPush(push)
        }
        
        await operatorConnection?.setDisconnectHandler { @MainActor [weak self] reason in
            self?.handleOperatorDisconnect(reason: reason)
        }
    }
    
    /// Set up handlers for the node connection.
    private func setupNodeHandlers() async {
        await nodeConnection?.setStateChangeHandler { @MainActor [weak self] state in
            self?.handleNodeStateChange(state)
        }
        
        await nodeConnection?.setPushHandler { @MainActor [weak self] push in
            await self?.handleNodePush(push)
        }
        
        await nodeConnection?.setDisconnectHandler { @MainActor [weak self] reason in
            self?.handleNodeDisconnect(reason: reason)
        }
        
        await nodeConnection?.setInvokeHandler { @MainActor [weak self] request in
            guard let self = self else {
                return BridgeInvokeResponse(
                    id: request.id,
                    ok: false,
                    error: BridgeNodeError(code: .unavailable, message: "Handler unavailable")
                )
            }
            
            // Route to custom handler or capability handler
            if let handler = self.onInvoke {
                return await handler(request)
            }
            return await self.capabilityHandler.handleInvoke(request)
        }
    }
    
    // MARK: - Connection Loops

    private func startOperatorLoop() {
        guard operatorConnectLoopTask == nil else { return }
        isConnecting = true
        operatorConnectLoopTask = Task { [weak self] in
            await self?.operatorConnectLoop()
        }
    }

    private func startNodeLoop() {
        guard nodeConnectLoopTask == nil else { return }
        isConnecting = true
        nodeConnectLoopTask = Task { [weak self] in
            await self?.nodeConnectLoop()
        }
    }

    private func startNodeLoopIfReady() {
        guard nodeConnectLoopTask == nil else { return }
        guard operatorState.isConnected || operatorState.isPairingPending else { return }
        startNodeLoop()
    }

    private func stopConnectLoops() {
        operatorConnectLoopTask?.cancel()
        nodeConnectLoopTask?.cancel()
        operatorConnectLoopTask = nil
        nodeConnectLoopTask = nil
        isConnecting = false
        updateCombinedStatus()
    }

    private func applyBackoffDelay(currentBackoffMs: Double) async -> Double {
        let delayMs = currentBackoffMs
        let nextBackoffMs = min(currentBackoffMs * 2, maxBackoffMs)
        try? await Task.sleep(nanoseconds: UInt64(delayMs * 1_000_000))
        return nextBackoffMs
    }

    private func operatorConnectLoop() async {
        defer {
            operatorConnectLoopTask = nil
            if nodeConnectLoopTask == nil {
                isConnecting = false
                updateCombinedStatus()
            }
        }

        while !Task.isCancelled {
            guard !isManuallyDisconnected else { return }

            if operatorState.isConnected {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }

            if operatorState.isPairingPending {
                if let startedAt = operatorPairingStartedAt,
                   Date().timeIntervalSince(startedAt) > pairingTimeoutSeconds {
                    logger.warning("Operator pairing timed out after \(Int(self.pairingTimeoutSeconds))s")
                    operatorPairingStartedAt = nil
                    operatorState = .disconnected
                    updateCombinedStatus()
                    continue
                }

                try? await Task.sleep(nanoseconds: pairingRetryIntervalSeconds * 1_000_000_000)
                guard !Task.isCancelled else { return }
                await connectOperator()
                continue
            }

            await connectOperator()

            guard !Task.isCancelled else { return }

            if operatorState.isConnected || operatorState.isPairingPending {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }

            operatorBackoffMs = await applyBackoffDelay(currentBackoffMs: operatorBackoffMs)
        }
    }

    private func nodeConnectLoop() async {
        defer {
            nodeConnectLoopTask = nil
            if operatorConnectLoopTask == nil {
                isConnecting = false
                updateCombinedStatus()
            }
        }

        while !Task.isCancelled {
            guard !isManuallyDisconnected else { return }

            if nodeState.isConnected {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }

            if nodeState.isPairingPending {
                if let startedAt = nodePairingStartedAt,
                   Date().timeIntervalSince(startedAt) > pairingTimeoutSeconds {
                    logger.warning("Node pairing timed out after \(Int(self.pairingTimeoutSeconds))s")
                    nodePairingStartedAt = nil
                    nodeState = .disconnected
                    updateCombinedStatus()
                    continue
                }

                try? await Task.sleep(nanoseconds: pairingRetryIntervalSeconds * 1_000_000_000)
                guard !Task.isCancelled else { return }
                await connectNode()
                continue
            }

            await connectNode()

            guard !Task.isCancelled else { return }

            if nodeState.isConnected || nodeState.isPairingPending {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                continue
            }

            nodeBackoffMs = await applyBackoffDelay(currentBackoffMs: nodeBackoffMs)
        }
    }

    /// Connect the operator connection.
    private func connectOperator() async {
        do {
            try await operatorConnection?.connect()
            // State change handler will handle success
        } catch {
            logger.error("Operator connection failed: \(error.localizedDescription)")
            // Check if GatewayConnection set the pairing pending state
            if let connection = operatorConnection,
               await connection.currentState().isPairingPending {
                handleOperatorStateChange(.pairingPending)
            } else if error.localizedDescription.lowercased().contains("pairing required") {
                handleOperatorStateChange(.pairingPending)
            }
        }
    }
    
    /// Connect the node connection.
    private func connectNode() async {
        do {
            try await nodeConnection?.connect()
            // State change handler will handle success
        } catch {
            logger.error("Node connection failed: \(error.localizedDescription)")
            // Check if GatewayConnection set the pairing pending state
            if let connection = nodeConnection,
               await connection.currentState().isPairingPending {
                handleNodeStateChange(.pairingPending)
            } else if error.localizedDescription.lowercased().contains("pairing required") {
                handleNodeStateChange(.pairingPending)
            }
        }
    }
    
    // MARK: - State Change Handlers
    
    private func handleOperatorStateChange(_ state: GatewayConnection.State) {
        operatorState = state
        updateCombinedStatus()
        startNodeLoopIfReady()
        
        if case .connected(let name) = state {
            serverName = name
            operatorPairingStartedAt = nil
            clearLastFailure()
            // Reset backoff on successful connection
            operatorBackoffMs = 500
            logger.info("Operator connected to: \(name)")
        } else if case .pairingPending = state {
            if operatorPairingStartedAt == nil {
                operatorPairingStartedAt = Date()
                logger.warning("Operator pairing required - awaiting approval")
            }
        } else if case .failed(let reason) = state {
            operatorPairingStartedAt = nil
            updateLastFailure(reason: reason)
        } else {
            operatorPairingStartedAt = nil
        }
    }
    
    private func handleNodeStateChange(_ state: GatewayConnection.State) {
        nodeState = state
        updateCombinedStatus()
        
        if case .connected = state {
            nodePairingStartedAt = nil
            clearLastFailure()
            // Reset backoff on successful connection
            nodeBackoffMs = 500
            logger.info("Node connected")
        } else if case .pairingPending = state {
            if nodePairingStartedAt == nil {
                nodePairingStartedAt = Date()
                logger.warning("Node pairing required - awaiting approval")
            }
        } else if case .failed(let reason) = state {
            nodePairingStartedAt = nil
            updateLastFailure(reason: reason)
        } else {
            nodePairingStartedAt = nil
        }
    }
    
    private func handleOperatorDisconnect(reason: String) {
        logger.warning("Operator disconnected: \(reason)")
        updateLastFailure(reason: reason)
        
        // Don't override pairing state
        if !operatorState.isPairingPending {
            operatorState = .disconnected
        }
        
        updateCombinedStatus()
    }
    
    private func handleNodeDisconnect(reason: String) {
        logger.warning("Node disconnected: \(reason)")
        updateLastFailure(reason: reason)
        
        // Don't override pairing state
        if !nodeState.isPairingPending {
            nodeState = .disconnected
        }
        
        updateCombinedStatus()
    }
    
    // MARK: - Push Handlers
    
    private func handleOperatorPush(_ push: GatewayPush) async {
        switch push {
        case .snapshot(let payload):
            await MainActor.run {
                serverName = payload.serverName
                logger.info("Operator snapshot: \(payload.serverName)")
            }
            
        case .event(let event):
            await handleChatEvent(event)
            
        case .seqGap(let expected, let received):
            logger.warning("Operator seq gap: expected \(expected), got \(received)")
        }
    }
    
    private func handleNodePush(_ push: GatewayPush) async {
        switch push {
        case .snapshot(let payload):
            logger.info("Node snapshot: \(payload.serverName)")
            
        case .event(let event):
            // Node connection receives chat/agent events but doesn't process them.
            // Only invoke events are relevant for the node role.
            // Avoid logging common chat events to reduce noise.
            let eventName = event.event
            if eventName != "chat" && eventName != "agent" && eventName != "tick" && eventName != "health" {
                logger.debug("Node event: \(eventName)")
            }
            
        case .seqGap(let expected, let received):
            logger.warning("Node seq gap: expected \(expected), got \(received)")
        }
    }
    
    /// Handle chat events from the operator connection.
    /// Filters events to only process those matching the configured session key.
    private func handleChatEvent(_ event: GatewayEvent) async {
        // Filter by session key - only process events for our configured session
        if let payload = event.payload,
           let eventSessionKey = payload["sessionKey"] as? String {
            if eventSessionKey != chatSessionKey {
                // Event is for a different session, ignore it silently
                return
            }
        }
        // Note: Events without sessionKey (like tick, health) are allowed through
        // as they are system events, not session-specific chat events

        guard let chatEvent = convertToChatEvent(event) else { return }

        await MainActor.run {
            onChatEvent?(chatEvent)
        }
    }
    
    // MARK: - Combined Status
    
    private func updateCombinedStatus() {
        let opConnected = operatorState.isConnected
        let nodeConnected = nodeState.isConnected
        let opPairing = operatorState.isPairingPending
        let nodePairing = nodeState.isPairingPending
        
        let newStatus: DualConnectionStatus
        
        switch (opConnected, nodeConnected, opPairing, nodePairing) {
        case (true, true, _, _):
            newStatus = .connected
        case (true, false, _, true):
            newStatus = .pairingPendingNode
        case (true, false, _, false):
            newStatus = .partialOperator
        case (false, true, true, _):
            newStatus = .pairingPendingOperator
        case (false, true, false, _):
            newStatus = .partialNode
        case (false, false, true, true):
            newStatus = .pairingPendingBoth
        case (false, false, true, false):
            newStatus = .pairingPendingOperator
        case (false, false, false, true):
            newStatus = .pairingPendingNode
        case (false, false, false, false):
            newStatus = isConnecting ? .connecting : .disconnected
        }
        
        if status != newStatus {
            // Debug: log state when transitioning to/from connecting
            if newStatus == .connecting || status == .connecting {
                let connectingFlag = isConnecting
                let opStateDesc = String(describing: operatorState)
                let nodeStateDesc = String(describing: nodeState)
                logger.info("Combined status: \(newStatus.displayText) (op=\(opConnected), node=\(nodeConnected), isConnecting=\(connectingFlag), opState=\(opStateDesc), nodeState=\(nodeStateDesc))")
            } else {
                logger.info("Combined status: \(newStatus.displayText)")
            }
            status = newStatus
            updateBackgroundTaskForCurrentStatus()
        }
    }
    
    // MARK: - Disconnect
    
    /// Disconnect both connections.
    func disconnect() async {
        isManuallyDisconnected = true
        stopConnectLoops()
        endBackgroundTask()
        
        await operatorConnection?.shutdown()
        await nodeConnection?.shutdown()
        
        operatorConnection = nil
        nodeConnection = nil
        operatorState = .disconnected
        nodeState = .disconnected
        operatorPairingStartedAt = nil
        nodePairingStartedAt = nil
        operatorBackoffMs = 500
        nodeBackoffMs = 500
        serverName = nil
        status = .disconnected
        
        logger.info("Disconnected both connections")
    }
    
    private func disconnectGracefully(reason: String) async {
        stopConnectLoops()
        endBackgroundTask()
        
        await operatorConnection?.shutdown()
        await nodeConnection?.shutdown()
        
        operatorConnection = nil
        nodeConnection = nil
        operatorState = .disconnected
        nodeState = .disconnected
        operatorPairingStartedAt = nil
        nodePairingStartedAt = nil
        operatorBackoffMs = 500
        nodeBackoffMs = 500
        serverName = nil
        status = .disconnected
        
        logger.info("Disconnected gracefully: \(reason)")
    }
    
    // MARK: - Chat Operations (via Operator Connection)
    
    /// Send a chat message via the operator connection.
    func sendMessage(_ text: String, images: [Data]? = nil) async throws -> String {
        guard let connection = operatorConnection,
              await connection.isConnected else {
            throw GatewayError.notConnected
        }
        
        let idempotencyKey = UUID().uuidString
        
        var params: [String: Any] = [
            "sessionKey": chatSessionKey,
            "message": text,
            "deliver": false,
            "idempotencyKey": idempotencyKey,
        ]
        
        if let images = images, !images.isEmpty {
            params["attachments"] = images.map { imageData in
                [
                    "type": "image",
                    "mimeType": "image/jpeg",
                    "fileName": "\(UUID().uuidString.prefix(8)).jpg",
                    "content": imageData.base64EncodedString(),
                ]
            }
        }
        
        let responseData = try await connection.request(method: "chat.send", params: params)
        if let json = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
           let runId = json["runId"] as? String {
            return runId
        }
        return idempotencyKey
    }
    
    /// Load chat history via the operator connection.
    func loadHistory(limit: Int = 200) async throws -> Data {
        guard let connection = operatorConnection,
              await connection.isConnected else {
            throw GatewayError.notConnected
        }
        
        let params: [String: Any] = [
            "sessionKey": chatSessionKey,
            "limit": limit,
        ]
        return try await connection.request(method: "chat.history", params: params)
    }
    
    /// Abort the current chat run via the operator connection.
    func abortRun() async throws {
        guard let connection = operatorConnection else {
            throw GatewayError.notConnected
        }
        
        let params: [String: Any] = ["sessionKey": chatSessionKey]
        _ = try await connection.request(method: "chat.abort", params: params, timeoutMs: 5000)
    }
    
    // MARK: - Node Operations (via Node Connection)
    
    /// Send a node event via the node connection.
    func sendNodeEvent(event: String, payloadJSON: String?) async {
        guard let connection = nodeConnection else { return }
        
        let params: [String: Any] = [
            "event": event,
            "payloadJSON": payloadJSON as Any,
        ]
        
        do {
            _ = try await connection.request(method: "node.event", params: params, timeoutMs: 8000)
        } catch {
            logger.error("Node event failed: \(error.localizedDescription)")
        }
    }
    
    // MARK: - Connection Testing
    
    /// Test connection to gateway with given credentials.
    func testConnection(credentials: KeychainManager.GatewayCredentials) async throws -> String {
        guard vpnMonitor.status.isConnected else {
            throw GatewayError.vpnNotConnected
        }

        if isAuthTokenMissing(for: credentials) {
            updateAuthTokenMissing(true)
            throw GatewayError.connectionFailed("Auth token required")
        }
        updateAuthTokenMissing(false)

        // For TLS connections, use port 443 (standard HTTPS, used by Tailscale Serve)
        // For non-TLS connections, use the gateway's native WebSocket port
        let scheme = credentials.useTLS ? "wss" : "ws"
        let port = credentials.useTLS ? 443 : GATEWAY_WS_PORT
        guard let url = URL(string: "\(scheme)://\(credentials.host):\(port)") else {
            throw GatewayError.connectionFailed("Invalid gateway URL")
        }
        
        // Test with operator role (chat scopes)
        let testDisplayName = await MainActor.run { "\(UIDevice.current.name) (Test)" }
        let testOptions = GatewayConnectOptions(
            role: "operator",
            scopes: ["operator.read", "operator.write"],
            caps: [],
            commands: [],
            permissions: [:],
            clientId: GATEWAY_CLIENT_ID,
            clientMode: "ui",
            clientDisplayName: testDisplayName
        )

        let testConnection = GatewayConnection(
            url: url,
            role: .operator,
            connectOptions: testOptions,
            sharedToken: credentials.authToken,
            autoReconnect: false
        )
        
        actor ServerNameHolder {
            var name: String?
            func set(_ value: String) { name = value }
            func get() -> String? { name }
        }
        let serverNameHolder = ServerNameHolder()
        
        await testConnection.setPushHandler { push in
            if case .snapshot(let payload) = push {
                await serverNameHolder.set(payload.serverName)
            }
        }
        
        let testTask = Task {
            try await testConnection.connect()
        }
        
        let timeoutTask = Task {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            testTask.cancel()
        }
        
        defer {
            testTask.cancel()
            timeoutTask.cancel()
            Task {
                await testConnection.shutdown()
            }
        }
        
        try await testTask.value
        try await Task.sleep(nanoseconds: 1_000_000_000)
        
        if let name = await serverNameHolder.get() {
            return name
        }
        
        if await testConnection.isConnected {
            return "Gateway"
        }
        
        throw GatewayError.connectionFailed("Could not establish connection")
    }
    
    // MARK: - App Lifecycle
    
    /// Handle app lifecycle phase changes.
    func handleLifecycleChange(_ phase: AppLifecyclePhase) {
        switch phase {
        case .active:
            handleBecameActive()
        case .inactive:
            break
        case .background:
            handleEnteredBackground()
        }
    }
    
    private func handleBecameActive() {
        endBackgroundTask()

        if pendingVPNReconnect {
            pendingVPNReconnect = false
            if autoConnectEnabled && !isManuallyDisconnected {
                logger.info("handleBecameActive: VPN reconnected in background, reconnecting now")
                Task { @MainActor in
                    await self.connectIfNeeded()
                }
            }
            return
        }
        
        // Skip if we're already connecting - don't interrupt an in-progress connection attempt
        if status == .connecting || isConnecting {
            logger.info("handleBecameActive: already connecting, skipping")
            return
        }
        
        // Only try to reconnect if we were previously connected and are now disconnected.
        // This avoids interfering with fresh app launches or manual disconnects.
        guard wasConnectedBeforeBackground else {
            logger.info("handleBecameActive: was not connected before background, skipping")
            return
        }
        
        // Check connection state when becoming active after being connected before background.
        Task { @MainActor in
            // Validate that connections are actually alive, not just that status says connected.
            // WebSocket connections can die silently when background task expires.
            let operatorAlive = await operatorConnection?.isActuallyConnected ?? false
            let nodeAlive = await nodeConnection?.isActuallyConnected ?? false
            
            // Check if VPN is connected - no point reconnecting without VPN
            let vpnConnected = vpnMonitor.status.isConnected
            
            logger.info("handleBecameActive: op=\(operatorAlive), node=\(nodeAlive), vpn=\(vpnConnected), status=\(self.status.displayText)")
            
            if operatorAlive && nodeAlive && status.isConnected {
                logger.info("Connection still active after background")
                onDidBecomeActiveWhileConnected?()
            } else if vpnConnected && !isManuallyDisconnected {
                if !operatorAlive && !nodeAlive {
                    logger.info("Connection lost during background, forcing reconnect...")
                    isManuallyDisconnected = false
                    await forceReconnect()
                } else {
                    logger.info("Partial connection after background (op=\(operatorAlive), node=\(nodeAlive)), resuming loops")
                    if !operatorAlive {
                        startOperatorLoop()
                    }
                    if !nodeAlive {
                        startNodeLoopIfReady()
                    }
                }
            } else if !vpnConnected {
                logger.info("VPN not connected, skipping reconnect")
                // Update status to disconnected if we think we're connected but VPN is down
                if status != .disconnected {
                    status = .disconnected
                }
            } else {
                logger.info("Manually disconnected, skipping auto-reconnect")
            }
        }
    }
    
    /// Force a full reconnection by cleaning up state and reconnecting.
    /// Use this when returning from background or when the Retry button is pressed.
    func forceReconnect() async {
        logger.info("Force reconnect: cleaning up stale connections")
        
        stopConnectLoops()
        
        // Shut down existing connections cleanly
        await operatorConnection?.shutdown()
        await nodeConnection?.shutdown()
        
        // Reset state
        operatorConnection = nil
        nodeConnection = nil
        operatorState = .disconnected
        nodeState = .disconnected
        operatorPairingStartedAt = nil
        nodePairingStartedAt = nil
        operatorBackoffMs = 500
        nodeBackoffMs = 500
        status = .disconnected
        
        // Now reconnect
        await connectIfNeeded()
    }
    
    private func handleEnteredBackground() {
        wasConnectedBeforeBackground = status.isConnected || status.isPartiallyConnected
        
        guard wasConnectedBeforeBackground else { return }
        
        startBackgroundTask()
        logger.info("Started background task to maintain connections")
    }
    
    private func startBackgroundTask() {
        guard backgroundTaskId == .invalid else { return }
        
        backgroundTaskId = UIApplication.shared.beginBackgroundTask(withName: "GatewayDualConnection") { [weak self] in
            self?.logger.info("Background time expired")
            self?.endBackgroundTask()
        }
    }
    
    private func endBackgroundTask() {
        guard backgroundTaskId != .invalid else { return }
        
        UIApplication.shared.endBackgroundTask(backgroundTaskId)
        backgroundTaskId = .invalid
        logger.info("Ended background task")
    }
    
    private func updateBackgroundTaskForCurrentStatus() {
        let isBackground = UIApplication.shared.applicationState == .background
        guard isBackground else { return }
        
        if status.isConnected || status.isPartiallyConnected {
            startBackgroundTask()
        } else {
            endBackgroundTask()
        }
    }
    
    // MARK: - Event Conversion
    
    private func convertToChatEvent(_ event: GatewayEvent) -> GatewayChatEvent? {
        let payload = event.payload
        let seq = event.seq
        
        switch event.event {
        case "chat":
            return parseChatPayload(payload, seq: seq)
        case "agent":
            if let status = payload?["status"] as? String {
                return .agentStatus(status: status)
            }
            return nil
        default:
            return nil
        }
    }
    
    private func parseChatPayload(_ payload: [String: Any]?, seq: Int?) -> GatewayChatEvent? {
        guard let payload = payload else { return nil }
        
        if let state = payload["state"] as? String {
            let runId = payload["runId"] as? String
            let stopReason = payload["stopReason"] as? String
            let message = payload["message"]
            
            switch state {
            case "delta":
                if let text = extractText(from: message) {
                    return .textDelta(text: text, seq: seq)
                }
            case "final":
                let text = extractText(from: message)
                return .done(runId: runId, stopReason: stopReason, finalText: text, seq: seq)
            case "aborted":
                return .done(runId: runId, stopReason: "aborted", finalText: nil, seq: seq)
            case "error":
                let errorMessage = payload["errorMessage"] as? String
                return .error(code: "ERROR", message: errorMessage ?? "Unknown error", seq: seq)
            default:
                break
            }
        }
        
        if let type = payload["type"] as? String {
            switch type {
            case "textDelta":
                if let text = payload["text"] as? String {
                    return .textDelta(text: text, seq: seq)
                }
            case "thinkingDelta":
                if let text = payload["text"] as? String {
                    return .thinkingDelta(text: text, seq: seq)
                }
            case "toolCallStart":
                if let name = payload["name"] as? String {
                    return .toolCallStart(name: name, id: payload["id"] as? String)
                }
            case "toolCallEnd":
                if let name = payload["name"] as? String {
                    return .toolCallEnd(
                        name: name,
                        id: payload["id"] as? String,
                        result: payload["result"] as? String
                    )
                }
            case "done":
                return .done(
                    runId: payload["runId"] as? String,
                    stopReason: payload["stopReason"] as? String,
                    finalText: nil,
                    seq: seq
                )
            case "error":
                return .error(
                    code: payload["code"] as? String ?? "UNKNOWN",
                    message: payload["message"] as? String ?? "Unknown error",
                    seq: seq
                )
            default:
                break
            }
        }
        
        return nil
    }
    
    private func extractText(from message: Any?) -> String? {
        if let text = message as? String {
            return text
        }
        
        if let dict = message as? [String: Any] {
            if let text = dict["text"] as? String {
                return text
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
                    return texts.joined()
                }
            }
        }
        
        return nil
    }
}
