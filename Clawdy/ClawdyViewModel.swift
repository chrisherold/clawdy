import Foundation
import Combine
import SwiftUI
import UIKit
import PhotosUI

// MARK: - Models

/// Input mode for user interaction
enum InputMode: String, Codable {
    case voice
    case text
}

/// Connection capabilities indicating which features are available
struct ConnectionCapabilities: Equatable {
    enum RoleStatus: Equatable {
        case connected
        case disconnected
        case pairingPending
    }

    /// Chat (operator role) availability
    let chat: RoleStatus
    /// Node features (camera, location invokes) availability
    let node: RoleStatus

    var isChatAvailable: Bool {
        chat == .connected
    }

    var isNodeAvailable: Bool {
        node == .connected
    }
}

enum ConnectionStatus: Equatable {
    case connected(serverName: String)
    case connecting
    case disconnected(reason: String)
    case partialOperator(serverName: String, nodeStatus: ConnectionCapabilities.RoleStatus)  // Chat works, node pending/unavailable
    case partialNode(chatStatus: ConnectionCapabilities.RoleStatus)                           // Node works, chat pending/unavailable
    case pairingPending(chatStatus: ConnectionCapabilities.RoleStatus, nodeStatus: ConnectionCapabilities.RoleStatus)  // Waiting for pairing approval

    var color: SwiftUI.Color {
        switch self {
        case .connected: return .green
        case .connecting, .pairingPending(_, _): return .yellow
        case .disconnected: return .red
        case .partialOperator(_, _), .partialNode(_): return .orange
        }
    }

    /// Primary status title (e.g., "Connected", "Connecting...", "Disconnected")
    var title: String {
        switch self {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnected: return "Disconnected"
        case .partialOperator(_, _): return "Partial"
        case .partialNode(_): return "Partial"
        case .pairingPending(_, _): return "Pairing..."
        }
    }

    /// Subtitle with additional details (server name or error reason)
    var subtitle: String? {
        switch self {
        case .connected(let serverName):
            return "Server: \(serverName)"
        case .connecting:
            return nil
        case .disconnected(let reason):
            return reason
        case .partialOperator(let serverName, let nodeStatus):
            let nodeDetail = nodeStatus == .pairingPending ? "node pairing" : "node unavailable"
            return "Chat ready • \(nodeDetail) • \(serverName)"
        case .partialNode(let chatStatus):
            let chatDetail = chatStatus == .pairingPending ? "chat pairing" : "chat unavailable"
            return "Node ready • \(chatDetail)"
        case .pairingPending(let chatStatus, let nodeStatus):
            if chatStatus == .pairingPending && nodeStatus == .pairingPending {
                return "Waiting for approval"
            }
            return "Pairing required"
        }
    }

    /// Full display text for backward compatibility
    var displayText: String {
        switch self {
        case .connected(let serverName): return "Connected to \(serverName)"
        case .connecting: return "Connecting..."
        case .disconnected(let reason): return reason
        case .partialOperator(let serverName, let nodeStatus):
            let nodeDetail = nodeStatus == .pairingPending ? "node pairing" : "node unavailable"
            return "Partial: \(serverName) (\(nodeDetail))"
        case .partialNode(let chatStatus):
            let chatDetail = chatStatus == .pairingPending ? "chat pairing" : "chat unavailable"
            return "Partial (\(chatDetail))"
        case .pairingPending(_, _):
            return "Pairing pending..."
        }
    }

    /// Accessibility description with capability details
    var accessibilityDescription: String {
        switch self {
        case .connected(let serverName):
            return "Gateway connected to \(serverName). Chat and device features available."
        case .connecting:
            return "Gateway connecting."
        case .disconnected(let reason):
            return "Gateway disconnected. \(reason)"
        case .partialOperator(let serverName, let nodeStatus):
            let nodeDetail = roleDescription(for: nodeStatus, role: "Device features")
            return "Gateway partially connected to \(serverName). Chat available. \(nodeDetail)."
        case .partialNode(let chatStatus):
            let chatDetail = roleDescription(for: chatStatus, role: "Chat")
            return "Gateway partially connected. Device features available. \(chatDetail)."
        case .pairingPending(let chatStatus, let nodeStatus):
            let chatDetail = roleDescription(for: chatStatus, role: "Chat")
            let nodeDetail = roleDescription(for: nodeStatus, role: "Device features")
            return "Gateway pairing pending. \(chatDetail). \(nodeDetail)."
        }
    }

    private func roleDescription(for status: ConnectionCapabilities.RoleStatus, role: String) -> String {
        switch status {
        case .connected:
            return "\(role) connected"
        case .disconnected:
            return "\(role) unavailable"
        case .pairingPending:
            return "\(role) pairing pending"
        }
    }
    
    /// Available capabilities based on connection status
    var capabilities: ConnectionCapabilities? {
        switch self {
        case .connected:
            return ConnectionCapabilities(chat: .connected, node: .connected)
        case .partialOperator(_, let nodeStatus):
            return ConnectionCapabilities(chat: .connected, node: nodeStatus)
        case .partialNode(let chatStatus):
            return ConnectionCapabilities(chat: chatStatus, node: .connected)
        case .pairingPending(let chatStatus, let nodeStatus):
            return ConnectionCapabilities(chat: chatStatus, node: nodeStatus)
        case .connecting, .disconnected:
            return nil  // Don't show capability indicators when not connected
        }
    }
    
    /// Whether chat functionality is available
    var canChat: Bool {
        capabilities?.isChatAvailable ?? false
    }
    
    /// Whether node features (camera, location) are available
    var hasNodeFeatures: Bool {
        capabilities?.isNodeAvailable ?? false
    }
}

/// Processing state indicating what the assistant is currently doing
enum ProcessingState: Equatable {
    case idle
    case thinking
    case responding
    case usingTool(name: String)
    
    var displayText: String {
        switch self {
        case .idle: return ""
        case .thinking: return "Thinking..."
        case .responding: return "Speaking..."
        case .usingTool(let name): return "Using \(name)..."
        }
    }
    
    var isActive: Bool {
        return self != .idle
    }
}

/// Information about a tool call made during response generation
struct ToolCallInfo: Identifiable, Equatable, Codable {
    let id: UUID
    let name: String
    let input: String?  // e.g., "ls -la" or file path
    var output: String?  // Truncated result (max ~200 words)
    var isComplete: Bool
    
    init(id: UUID = UUID(), name: String, input: String? = nil, output: String? = nil, isComplete: Bool = false) {
        self.id = id
        self.name = name
        self.input = input
        self.output = output
        self.isComplete = isComplete
    }
}

struct TranscriptMessage: Identifiable, Equatable, Codable {
    let id: UUID
    var text: String  // Mutable for streaming updates
    let isUser: Bool
    let timestamp: Date
    var isStreaming: Bool
    var wasInterrupted: Bool
    var toolCalls: [ToolCallInfo]  // Tool calls made during this message
    
    /// Image attachment IDs (references to temp files, NOT persisted across launches)
    /// Images are session-only - they exist in ImageAttachmentStore during the session
    var imageAttachmentIds: [UUID]

    init(text: String, isUser: Bool, isStreaming: Bool = false, wasInterrupted: Bool = false, toolCalls: [ToolCallInfo] = [], imageAttachmentIds: [UUID] = []) {
        self.id = UUID()
        self.text = text
        self.isUser = isUser
        self.timestamp = Date()
        self.isStreaming = isStreaming
        self.wasInterrupted = wasInterrupted
        self.toolCalls = toolCalls
        self.imageAttachmentIds = imageAttachmentIds
    }
    
    // MARK: - Custom Codable (exclude imageAttachmentIds from persistence)
    
    enum CodingKeys: String, CodingKey {
        case id, text, isUser, timestamp, isStreaming, wasInterrupted, toolCalls
        // imageAttachmentIds intentionally excluded - images are session-only
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        text = try container.decode(String.self, forKey: .text)
        isUser = try container.decode(Bool.self, forKey: .isUser)
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        isStreaming = try container.decode(Bool.self, forKey: .isStreaming)
        wasInterrupted = try container.decode(Bool.self, forKey: .wasInterrupted)
        toolCalls = try container.decode([ToolCallInfo].self, forKey: .toolCalls)
        imageAttachmentIds = []  // Always empty when loading from persistence
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(text, forKey: .text)
        try container.encode(isUser, forKey: .isUser)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(isStreaming, forKey: .isStreaming)
        try container.encode(wasInterrupted, forKey: .wasInterrupted)
        try container.encode(toolCalls, forKey: .toolCalls)
        // imageAttachmentIds intentionally NOT encoded - images are session-only
    }
}

// MARK: - View Model

@MainActor
class ClawdyViewModel: ObservableObject {
    @Published var isRecording = false
    @Published var isSpeaking = false
    @Published var isGeneratingAudio = false
    @Published var isContinuousMode = false {
        didSet {
            UserDefaults.standard.set(isContinuousMode, forKey: "com.clawdy.continuousMode")
            UIApplication.shared.isIdleTimerDisabled = isContinuousMode
            print("[ContinuousMode] didSet: isContinuousMode=\(isContinuousMode), isIdleTimerDisabled=\(UIApplication.shared.isIdleTimerDisabled)")
        }
    }
    @Published var connectionStatus: ConnectionStatus = .disconnected(reason: "Not connected") {
        didSet {
            handleConnectionStatusChange(from: oldValue, to: connectionStatus)
        }
    }
    @Published var vpnStatus: VPNStatus = .unknown
    @Published var authTokenMissing: Bool = false
    @Published var gatewayFailure: GatewayConnectionFailure = .none
    @Published var messages: [TranscriptMessage] = []
    @Published var currentTranscription = ""
    /// Current processing state for UI indicators (thinking, tool use, etc.)
    @Published var processingState: ProcessingState = .idle {
        didSet {
            // Auto-restart recording when processing finishes in continuous mode (fallback for no TTS)
            if oldValue.isActive && !processingState.isActive && isContinuousMode && !isRecording && !isSpeaking {
                restartRecordingForContinuousMode()
            }
        }
    }
    
    /// Current streaming response text (updated incrementally)
    @Published var streamingResponseText = ""
    
    /// Current streaming message being received (for live display in transcript)
    /// This is the message currently being streamed from the gateway, before it's finalized and added to messages array
    @Published var streamingMessage: TranscriptMessage?
    
    /// Whether an abort is currently being processed
    @Published var isAborting = false
    
    /// Whether a reconnection is currently in progress
    @Published var isReconnecting = false
    
    /// Toast message to display (auto-hides after 2 seconds)
    @Published var toastMessage: String? = nil
    
    // MARK: - Camera Flash Properties
    
    /// Whether the camera flash overlay should be shown (for camera.snap feedback)
    @Published var showingCameraFlash: Bool = false
    
    // MARK: - Image Attachment Properties
    
    /// Store for all images in current session (uses shared singleton for memory pressure handling)
    let imageStore = ImageAttachmentStore.shared
    
    /// Images pending attachment to next message
    @Published var pendingImages: [ImageAttachment] = []
    

    
    /// Maximum images allowed per message
    let maxImagesPerMessage = 3
    
    // MARK: - Quick Look Properties
    
    /// URLs of images to display in Quick Look (full-screen viewer)
    @Published var quickLookImages: [URL] = []
    
    /// Index of the initially selected image in Quick Look
    @Published var quickLookIndex: Int = 0
    
    /// Whether Quick Look full-screen viewer is currently shown
    @Published var showingQuickLook: Bool = false
    
    // MARK: - Input Mode Properties
    
    /// Current input mode (voice or text)
    @Published var inputMode: InputMode = .voice {
        didSet {
            saveInputMode()
        }
    }
    
    /// Text input buffer for text mode
    @Published var textInput: String = "" {
        didSet {
            saveDraftTextInput()
        }
    }

    private let speechRecognizer = SpeechRecognizer()
    private let vpnMonitor = VPNStatusMonitor.shared
    private var cancellables = Set<AnyCancellable>()
    
    /// Gateway chat client for sending messages when in gateway mode
    private let gatewayChatClient = GatewayChatClient()
    
    /// Gateway dual connection manager for separate operator (chat) and node (capabilities) WebSocket connections.
    /// The Clawdbot gateway enforces strict role separation, requiring two connections:
    /// - Operator connection: For chat.send, chat.history, chat.abort
    /// - Node connection: For receiving node.invoke.request and sending node.invoke.result
    private let gatewayDualConnectionManager = GatewayDualConnectionManager.shared
    
    /// Node capability handler for gateway mode invocations
    private let nodeCapabilityHandler = NodeCapabilityHandler()
    
    /// Gateway streaming state tracking
    private var gatewayFullText: String = ""
    private var lastGatewaySeq: Int?
    private var isGatewayToolExecuting = false
    private var gatewayResponseContinuation: CheckedContinuation<Void, Never>?
    
    /// Suppress gateway finalization after a user-initiated cancel/interrupt
    private var suppressGatewayFinalization = false
    
    /// Incremental TTS manager for streaming speech
    private let incrementalTTS = IncrementalTTSManager()

    /// Server name for display in status indicator
    private var serverName: String {
        return gatewayDualConnectionManager.serverName ?? "gateway"
    }

    init() {
        // Set session key from saved credentials BEFORE setting up bindings
        // This ensures history loads with the correct session key
        if let credentials = KeychainManager.shared.loadGatewayCredentials() {
            gatewayDualConnectionManager.chatSessionKey = credentials.sessionKey
        }

        loadInputMode()
        loadDraftTextInput()
        loadContinuousMode()
        setupBindings()
        setupContinuousMode()
        Task {
            // Prune old messages on app launch (removes messages older than 7 days)
            await MessagePersistenceManager.shared.pruneOldMessages()

            // Load persisted messages to populate the transcript view
            let persistedMessages = await MessagePersistenceManager.shared.loadMessages()
            await MainActor.run {
                self.messages = persistedMessages
            }
        }
    }

    private func loadContinuousMode() {
        isContinuousMode = UserDefaults.standard.bool(forKey: "com.clawdy.continuousMode")
    }

    private func setupContinuousMode() {
        // Set up silence detection callback for continuous mode
        speechRecognizer.onSilenceDetected = { [weak self] in
            guard let self = self, self.isContinuousMode, self.isRecording else { return }
            self.stopRecordingAndSend()
        }

        // Set up timeout restart callback (handles Apple's 60s limit)
        speechRecognizer.onTimeoutRestart = { [weak self] in
            guard let self = self, self.isContinuousMode else { return }
            print("[ContinuousMode] Recognition timeout - restarting")
            self.isRecording = false
            self.restartRecordingWithRecovery()
        }

        // Set up callback for when recognition stops unexpectedly (error or isFinal)
        speechRecognizer.onRecognitionStopped = { [weak self] in
            guard let self = self, self.isContinuousMode else { return }
            print("[ContinuousMode] Recognition stopped unexpectedly - restarting")
            self.isRecording = false
            self.restartRecordingWithRecovery()
        }
    }

    /// Restart recording with error recovery and exponential backoff
    private func restartRecordingWithRecovery(retryCount: Int = 0) {
        let maxRetries = 5
        let baseDelay: TimeInterval = 0.3

        guard retryCount < maxRetries else {
            print("[ContinuousMode] Max retries reached, stopping continuous mode")
            isContinuousMode = false
            return
        }

        let delay = baseDelay * pow(2.0, Double(retryCount))

        print("[ContinuousMode] restartRecordingWithRecovery attempt \(retryCount + 1)/\(maxRetries), delay: \(delay)s")

        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self else { return }
            guard self.isContinuousMode else {
                print("[ContinuousMode] Recovery aborted: continuous mode disabled")
                return
            }
            guard !self.isRecording else {
                print("[ContinuousMode] Recovery aborted: already recording")
                return
            }
            guard !self.isSpeaking else {
                print("[ContinuousMode] Recovery deferred: still speaking, will restart when TTS finishes")
                return
            }

            Task {
                do {
                    try await self.speechRecognizer.startRecording()
                    await MainActor.run {
                        self.isRecording = true
                        if self.isContinuousMode {
                            self.speechRecognizer.startSilenceDetection()
                        }
                    }
                    print("[ContinuousMode] Recording restarted successfully")
                } catch {
                    print("[ContinuousMode] Restart failed (attempt \(retryCount + 1)): \(error)")
                    await MainActor.run {
                        self.restartRecordingWithRecovery(retryCount: retryCount + 1)
                    }
                }
            }
        }
    }

    private func setupBindings() {
        speechRecognizer.$transcribedText
            .receive(on: DispatchQueue.main)
            .sink { [weak self] text in
                self?.currentTranscription = text
            }
            .store(in: &cancellables)

        // Bind incremental TTS speaking state
        incrementalTTS.$isSpeaking
            .receive(on: DispatchQueue.main)
            .sink { [weak self] speaking in
                guard let self = self else { return }
                let wasSpeaking = self.isSpeaking
                self.isSpeaking = speaking

                // Auto-restart recording when TTS finishes in continuous mode
                if wasSpeaking && !speaking && self.isContinuousMode {
                    self.restartRecordingForContinuousMode()
                }
            }
            .store(in: &cancellables)
        
        // Bind Kokoro audio generation state
        incrementalTTS.$isGeneratingAudio
            .receive(on: DispatchQueue.main)
            .sink { [weak self] generating in
                self?.isGeneratingAudio = generating
            }
            .store(in: &cancellables)

        // Monitor VPN status changes
        vpnMonitor.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.vpnStatus = status
            }
            .store(in: &cancellables)
        
        // Monitor gateway dual connection status
        gatewayDualConnectionManager.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                guard let self = self else { return }
                switch status {
                case .disconnected:
                    if self.gatewayDualConnectionManager.authTokenMissing {
                        self.connectionStatus = .disconnected(reason: "Auth token required")
                    } else {
                        self.connectionStatus = .disconnected(reason: "Not connected")
                    }
                case .connecting:
                    self.connectionStatus = .connecting
                case .partialOperator:
                    // Operator connected (chat works), node not connected
                    let name = self.gatewayDualConnectionManager.serverName ?? "gateway"
                    self.connectionStatus = .partialOperator(serverName: name, nodeStatus: .disconnected)
                    self.isReconnecting = false
                case .partialNode:
                    // Node connected, operator not connected (invokes work, no chat)
                    self.connectionStatus = .partialNode(chatStatus: .disconnected)
                case .connected:
                    // Both connections active - full functionality
                    let name = self.gatewayDualConnectionManager.serverName ?? "gateway"
                    self.connectionStatus = .connected(serverName: name)
                    self.isReconnecting = false
                case .pairingPendingOperator:
                    // Chat waiting for pairing, node connected
                    self.connectionStatus = .partialNode(chatStatus: .pairingPending)
                case .pairingPendingNode:
                    // Operator connected, node waiting for pairing
                    let name = self.gatewayDualConnectionManager.serverName ?? "gateway"
                    self.connectionStatus = .partialOperator(serverName: name, nodeStatus: .pairingPending)
                case .pairingPendingBoth:
                    self.connectionStatus = .pairingPending(chatStatus: .pairingPending, nodeStatus: .pairingPending)
                }
            }
            .store(in: &cancellables)

        gatewayDualConnectionManager.$authTokenMissing
            .receive(on: DispatchQueue.main)
            .sink { [weak self] missing in
                self?.authTokenMissing = missing
            }
            .store(in: &cancellables)

        gatewayDualConnectionManager.$lastFailure
            .receive(on: DispatchQueue.main)
            .sink { [weak self] failure in
                self?.gatewayFailure = failure
            }
            .store(in: &cancellables)
        
        // Route gateway chat events to the UI mapper
        gatewayDualConnectionManager.onChatEvent = { [weak self] event in
            Task { @MainActor in
                self?.handleGatewayChatEvent(event)
            }
        }
        
        // Request chat history when dual connection becomes active (operator role connected)
        // Monitor status changes and load history when chat capability becomes available
        gatewayDualConnectionManager.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                guard let self = self else { return }
                // Load history when we gain chat capability
                if status.hasChatCapability {
                    print("[ViewModel] Chat capability available, loading gateway history...")
                    Task { await self.loadGatewayHistory() }
                }
            }
            .store(in: &cancellables)
        
        // Refresh chat history when app returns to foreground while still connected.
        // This catches any messages that arrived while the app was backgrounded
        // (e.g., from cron jobs, sub-agents, or other async sources).
        gatewayDualConnectionManager.onDidBecomeActiveWhileConnected = { [weak self] in
            print("[ViewModel] App became active while connected, refreshing chat history...")
            Task { await self?.loadGatewayHistory() }
        }
        
        // Wire up node capability invocations from the gateway
        setupNodeCapabilityHandlers()
        gatewayDualConnectionManager.onInvoke = { [weak self] request in
            guard let self = self else {
                return BridgeInvokeResponse(
                    type: "invoke-res",
                    id: request.id,
                    ok: false,
                    payloadJSON: nil,
                    error: BridgeNodeError(code: .unavailable, message: "ViewModel deallocated")
                )
            }
            return await self.nodeCapabilityHandler.handleInvoke(request)
        }
        
        // Observe image attachment store cleared (e.g., due to memory pressure).
        // When images are cleared from the store, also clear pendingImages to keep UI in sync.
        NotificationCenter.default.publisher(for: .imageAttachmentsCleared)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self = self else { return }
                if !self.pendingImages.isEmpty {
                    self.pendingImages.removeAll()
                    self.showToast("Images cleared due to low memory")
                }
            }
            .store(in: &cancellables)
        
        // Observe replies from chat push notification actions.
        // When user replies to a notification, send the reply text as a new message to the agent.
        NotificationCenter.default.publisher(for: .chatPushReplyReceived)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] notification in
                guard let self = self else { return }
                guard let replyText = notification.userInfo?["text"] as? String,
                      !replyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                    return
                }
                
                print("[ClawdyViewModel] Received notification reply: \"\(replyText.prefix(50))...\"")
                
                // Add the reply as a user message and send to agent
                self.addMessage(replyText, isUser: true)
                self.sendCommand(replyText)
            }
            .store(in: &cancellables)
    }

    func startRecording() {
        Task {
            do {
                try await speechRecognizer.startRecording()
                isRecording = true
                // Start silence detection timer in continuous mode
                if isContinuousMode {
                    speechRecognizer.startSilenceDetection()
                }
            } catch {
                addMessage("Error starting recording: \(error.localizedDescription)", isUser: false)
            }
        }
    }

    func stopRecording() {
        isRecording = false
        let transcription = speechRecognizer.stopRecording()

        guard !transcription.isEmpty else {
            // In continuous mode, silently restart without error message
            if isContinuousMode {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    if self.isContinuousMode && !self.isRecording && !self.isSpeaking {
                        self.startRecording()
                    }
                }
                return
            }
            addMessage("No speech detected. Please try again.", isUser: false)
            return
        }

        addMessage(transcription, isUser: true)
        sendCommand(transcription)
    }

    /// Called by silence detection in continuous mode
    private func stopRecordingAndSend() {
        guard isRecording else { return }
        isRecording = false
        let transcription = speechRecognizer.stopRecording()

        guard !transcription.isEmpty else {
            // Restart recording if no speech detected in continuous mode
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                if self.isContinuousMode && !self.isRecording && !self.isSpeaking {
                    self.startRecording()
                }
            }
            return
        }

        addMessage(transcription, isUser: true)
        sendCommand(transcription)
        // Recording will restart after TTS finishes via the isSpeaking observer
    }

    /// Toggle continuous conversation mode
    func toggleContinuousMode() {
        isContinuousMode.toggle()
        // Explicitly set idle timer (didSet on @Published can be unreliable)
        UIApplication.shared.isIdleTimerDisabled = isContinuousMode
        print("[ContinuousMode] toggled to \(isContinuousMode), isIdleTimerDisabled = \(UIApplication.shared.isIdleTimerDisabled)")

        if isContinuousMode {
            // Start recording if not already recording or speaking
            if !isRecording && !isSpeaking {
                startRecording()
            }
        } else {
            // Stop recording if currently recording
            if isRecording {
                isRecording = false
                _ = speechRecognizer.stopRecording()
            }

            // Stop any ongoing TTS
            incrementalTTS.stop()

            // Switch to .ambient category (allows auto-lock) and deactivate.
            // This overrides .record/.playback categories that prevent screen lock
            // (AVSpeechSynthesizer has a known bug where it never deactivates the session)
            do {
                let session = AVAudioSession.sharedInstance()
                try session.setCategory(.ambient)
                try session.setActive(false, options: .notifyOthersOnDeactivation)
            } catch {
                print("[ContinuousMode] Audio session cleanup error: \(error)")
            }
        }
    }

    /// Flag to prevent multiple restart attempts
    private var isRestartingContinuousMode = false

    /// Restart recording after TTS finishes in continuous mode
    private func restartRecordingForContinuousMode() {
        guard !isRestartingContinuousMode else {
            print("[ContinuousMode] restartRecordingForContinuousMode: already restarting, skipping")
            return
        }
        isRestartingContinuousMode = true

        // Longer delay to ensure audio session is fully released by TTS
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { [weak self] in
            guard let self = self else { return }
            self.isRestartingContinuousMode = false

            guard self.isContinuousMode else {
                print("[ContinuousMode] restartRecordingForContinuousMode: continuous mode disabled, aborting")
                return
            }
            guard !self.isRecording else {
                print("[ContinuousMode] restartRecordingForContinuousMode: already recording, skipping")
                return
            }
            guard !self.isSpeaking else {
                print("[ContinuousMode] restartRecordingForContinuousMode: still speaking, will retry when TTS finishes")
                return
            }
            guard !self.processingState.isActive else {
                print("[ContinuousMode] restartRecordingForContinuousMode: still processing, will retry when processing finishes")
                return
            }

            print("[ContinuousMode] Restarting recording via recovery")
            self.restartRecordingWithRecovery()
        }
    }

    // MARK: - Text Input
    
    /// Send the current text input as a command, with any attached images.
    /// Uses the same pipeline as voice input but with image support.
    /// Preserves draft text and images if offline or disconnected.
    func sendTextInput() {
        let trimmed = textInput.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Allow send with just images (no text required)
        guard !trimmed.isEmpty || !pendingImages.isEmpty else { return }
        
        // Check if we're offline - preserve draft and images
        // The offline banner is shown by ContentView based on connection state
        // and sendCommand will show an appropriate error message
        let isOffline = {
            if case .disconnected = connectionStatus { return true }
            if case .partialNode = connectionStatus { return true }
            return false
        }()
        
        // Capture images before clearing for use in the gateway call
        let imagesToSend = pendingImages
        let imageIds = imagesToSend.map { $0.id }
        
        if isOffline {
            // Don't clear the input or images when offline - preserve the draft
            // Still attempt to send so user gets the offline error message
            addMessageWithImages(trimmed, isUser: true, imageAttachmentIds: imageIds)
            sendCommand(trimmed, images: imagesToSend)
            return
        }
        
        let message = trimmed
        textInput = "" // Clear immediately for responsiveness (only when online)
        clearDraftTextInput()
        pendingImages = [] // Clear images after capturing
        
        // Medium haptic feedback on send with images
        if !imagesToSend.isEmpty {
            let impact = UIImpactFeedbackGenerator(style: .medium)
            impact.impactOccurred()
        }
        
        addMessageWithImages(message, isUser: true, imageAttachmentIds: imageIds)
        sendCommand(message, images: imagesToSend)
    }
    
    // MARK: - Input Mode Persistence
    
    /// Save input mode preference to UserDefaults
    private func saveInputMode() {
        UserDefaults.standard.set(inputMode.rawValue, forKey: "inputMode")
    }
    
    /// Load input mode preference from UserDefaults
    private func loadInputMode() {
        if let raw = UserDefaults.standard.string(forKey: "inputMode"),
           let mode = InputMode(rawValue: raw) {
            inputMode = mode
        }
    }

    // MARK: - Draft Persistence

    private func saveDraftTextInput() {
        UserDefaults.standard.set(textInput, forKey: "draftTextInput")
    }

    private func loadDraftTextInput() {
        if let draft = UserDefaults.standard.string(forKey: "draftTextInput") {
            textInput = draft
        }
    }

    private func clearDraftTextInput() {
        UserDefaults.standard.removeObject(forKey: "draftTextInput")
    }
    
    // MARK: - Image Attachment Methods
    
    /// Add images from PhotosPicker selection.
    /// Loads the full quality image from each item and adds to the store.
    /// - Parameter items: Selected PhotosPickerItem array
    func addImages(from items: [PhotosPickerItem]) async {
        for item in items {
            // Stop if we've reached the max
            guard pendingImages.count < maxImagesPerMessage else {
                showToast("Maximum \(maxImagesPerMessage) images reached")
                break
            }
            
            do {
                // Try to load as Image first to get full quality, then convert to JPEG
                // This avoids the heavy compression that happens with Data.self
                if let image = try await item.loadTransferable(type: Image.self) {
                    // Convert SwiftUI Image to UIImage via ImageRenderer
                    let renderer = ImageRenderer(content: image)
                    renderer.scale = 1.0 // Full resolution
                    if let uiImage = renderer.uiImage,
                       let data = uiImage.jpegData(compressionQuality: 0.9) {
                        let mediaType = "image/jpeg"
                        let attachment = try imageStore.addImage(from: data, mediaType: mediaType)
                        pendingImages.append(attachment)
                        
                        // Light haptic feedback on image added
                        let impact = UIImpactFeedbackGenerator(style: .light)
                        impact.impactOccurred()
                        
                        // VoiceOver announcement for accessibility
                        announceImageAdded(count: pendingImages.count)
                        continue
                    }
                }
                
                // Fallback: Load as raw Data
                guard let data = try await item.loadTransferable(type: Data.self) else {
                    continue
                }
                
                // Detect media type from data
                let mediaType = ImageAttachment.detectMediaType(from: data)
                
                // Add to store (validates size, saves to temp file)
                let attachment = try imageStore.addImage(from: data, mediaType: mediaType)
                pendingImages.append(attachment)
                
                // Light haptic feedback on image added
                let impact = UIImpactFeedbackGenerator(style: .light)
                impact.impactOccurred()
                
                // VoiceOver announcement for accessibility
                announceImageAdded(count: pendingImages.count)
                
            } catch let error as ImageError {
                switch error {
                case .tooLarge:
                    showToast("Image exceeds 50MB limit")
                default:
                    showToast("Failed to add image")
                }
            } catch {
                showToast("Failed to add image")
            }
        }
    }
    
    /// Add image from camera capture.
    /// Converts UIImage to JPEG data and adds to the store.
    /// - Parameter capturedImage: The captured UIImage from camera
    func addImage(from capturedImage: UIImage) async {
        guard pendingImages.count < maxImagesPerMessage else {
            showToast("Maximum \(maxImagesPerMessage) images reached")
            return
        }
        
        // Convert to JPEG data
        guard let data = capturedImage.jpegData(compressionQuality: 1.0) else {
            showToast("Failed to process camera image")
            return
        }
        
        do {
            let attachment = try imageStore.addImage(from: data, mediaType: "image/jpeg")
            pendingImages.append(attachment)
            
            // Light haptic feedback on image added
            let impact = UIImpactFeedbackGenerator(style: .light)
            impact.impactOccurred()
            
            // VoiceOver announcement for accessibility
            announceImageAdded(count: pendingImages.count)
            
        } catch let error as ImageError {
            switch error {
            case .tooLarge:
                showToast("Image exceeds 50MB limit")
            default:
                showToast("Failed to add image")
            }
        } catch {
            showToast("Failed to add image")
        }
    }
    
    /// Add image from clipboard paste.
    /// Reads UIPasteboard.general.image and adds to the store.
    func addImageFromClipboard() async {
        guard pendingImages.count < maxImagesPerMessage else {
            showToast("Maximum \(maxImagesPerMessage) images reached")
            return
        }
        
        do {
            if let attachment = try imageStore.addImageFromClipboard() {
                pendingImages.append(attachment)
                
                // Light haptic feedback on image added
                let impact = UIImpactFeedbackGenerator(style: .light)
                impact.impactOccurred()
                
                // VoiceOver announcement for accessibility
                announceImageAdded(count: pendingImages.count)
            }
        } catch let error as ImageError {
            switch error {
            case .tooLarge:
                showToast("Image exceeds 50MB limit")
            default:
                showToast("Failed to paste image")
            }
        } catch {
            showToast("Failed to paste image")
        }
    }
    
    /// Remove a pending image by ID.
    /// Removes from pendingImages array and deletes from store.
    /// - Parameter id: UUID of the image to remove
    func removePendingImage(_ id: UUID) {
        pendingImages.removeAll { $0.id == id }
        imageStore.remove(id)
        
        // Light haptic feedback on image removed
        let impact = UIImpactFeedbackGenerator(style: .light)
        impact.impactOccurred()
        
        // VoiceOver announcement handled by ImageThumbnailView's remove button
        // (posts "Image removed" announcement directly)
    }
    
    // MARK: - VoiceOver Announcements
    
    /// Announce that an image was added for VoiceOver users.
    /// Includes the current count of attached images.
    /// - Parameter count: Current number of pending images after addition
    private func announceImageAdded(count: Int) {
        let announcement: String
        if count == 1 {
            announcement = "Image added. 1 image attached."
        } else {
            announcement = "Image added. \(count) images attached."
        }
        UIAccessibility.post(notification: .announcement, argument: announcement)
    }

    // MARK: - Connection Status Feedback

    private func handleConnectionStatusChange(from oldStatus: ConnectionStatus, to newStatus: ConnectionStatus) {
        guard oldStatus != newStatus else { return }
        guard UIApplication.shared.applicationState == .active else { return }

        if shouldAnnounceConnectionChange(from: oldStatus, to: newStatus) {
            UIAccessibility.post(notification: .announcement, argument: newStatus.accessibilityDescription)
        }

        triggerConnectionHaptic(for: newStatus)
    }

    private func shouldAnnounceConnectionChange(from oldStatus: ConnectionStatus, to newStatus: ConnectionStatus) -> Bool {
        if oldStatus.capabilities != newStatus.capabilities {
            return true
        }
        return oldStatus.title != newStatus.title
    }

    private func triggerConnectionHaptic(for status: ConnectionStatus) {
        let generator = UINotificationFeedbackGenerator()
        switch status {
        case .connected:
            generator.notificationOccurred(.success)
        case .disconnected:
            generator.notificationOccurred(.error)
        case .partialOperator, .partialNode, .connecting, .pairingPending:
            generator.notificationOccurred(.warning)
        }
    }
    
    // MARK: - Quick Look Methods
    
    /// Show an image in full-screen Quick Look viewer.
    /// Sets up the Quick Look state with all images from the message for swiping between.
    /// - Parameters:
    ///   - attachment: The attachment to display initially
    ///   - allIds: All image IDs in the context (e.g., from the message) for swiping
    func showImageFullScreen(_ attachment: ImageAttachment, allIds: [UUID]) {
        // Build array of URLs for all images in context
        let urls = allIds.compactMap { imageStore.attachment(for: $0)?.tempFileURL }
        
        guard !urls.isEmpty else { return }
        
        // Find the index of the tapped image
        guard let index = urls.firstIndex(of: attachment.tempFileURL) else { return }
        
        // Set Quick Look state
        quickLookImages = urls
        quickLookIndex = index
        showingQuickLook = true
    }

    private func sendCommand(_ command: String, images: [ImageAttachment] = []) {
        // Check if a response is currently streaming - if so, interrupt it first.
        // This allows the user to send a new message mid-response, which will:
        // 1. Stop TTS immediately (mid-word)
        // 2. Abort the gateway generation
        // 3. Save the partial response with [interrupted] marker
        // 4. Provide haptic feedback
        // Then the new command proceeds normally.
        if isCurrentlyStreaming {
            interruptCurrentResponse()
        }
        

        Task {
            await sendCommandWithGateway(command, images: images)
        }
    }
    
    /// Whether a response is currently being streamed from the gateway.
    /// Used to detect if the user sends a new message while still receiving a response.
    private var isCurrentlyStreaming: Bool {
        return streamingMessage != nil && streamingMessage?.isStreaming == true
    }
    
    /// Interrupt the current streaming response to allow a new command.
    /// This method:
    /// - Stops TTS immediately (mid-word)
    /// - Aborts the gateway generation
    /// - Saves the partial response with [interrupted] marker
    /// - Triggers haptic feedback
    /// - Resets processing state
    private func interruptCurrentResponse() {
        // 6.7: Trigger heavy haptic feedback on interruption
        let impact = UIImpactFeedbackGenerator(style: .heavy)
        impact.impactOccurred()
        
        // 6.3: Stop TTS immediately (mid-word) via incrementalTTS.stop()
        incrementalTTS.stop()
        
        finalizeCancelledStreamingMessage(marker: "[interrupted]")
        
        // 6.4: Abort generation via gateway client
        suppressGatewayFinalization = true
        gatewayFullText = ""
        lastGatewaySeq = nil
        isGatewayToolExecuting = false
        finishGatewayResponse()
        Task {
            try? await gatewayChatClient.abort()
        }
        
        // 6.8: Reset processing state and continue with new message
        streamingMessage = nil
        streamingResponseText = ""
        processingState = .idle
    }
    
    /// Save a partial streaming response with a cancellation marker.
    private func finalizeCancelledStreamingMessage(marker: String) {
        if var partialMessage = streamingMessage, !partialMessage.text.isEmpty {
            partialMessage.isStreaming = false
            partialMessage.wasInterrupted = true
            partialMessage.text += "\n\n\(marker)"
            messages.append(partialMessage)
            
            Task {
                await MessagePersistenceManager.shared.saveMessage(partialMessage)
            }
        } else if !streamingResponseText.isEmpty {
            var message = TranscriptMessage(text: streamingResponseText + "\n\n\(marker)", isUser: false)
            message.wasInterrupted = true
            messages.append(message)
            
            Task {
                await MessagePersistenceManager.shared.saveMessage(message)
            }
        }
    }
    
    // MARK: - Gateway Chat History
    
    /// Load chat history from the gateway after subscription is established.
    private func loadGatewayHistory() async {
        do {
            let data = try await gatewayChatClient.requestHistory()
            let payload = try JSONDecoder().decode(GatewayChatHistoryPayload.self, from: data)
            print("[ViewModel] Gateway history received: \(payload.messages.count) messages for session \(payload.sessionKey)")
            let historyMessages = mapGatewayHistoryMessages(payload.messages)
            print("[ViewModel] Mapped to \(historyMessages.count) transcript messages")
            await MainActor.run {
                // Clear any streaming state before replacing messages with history
                // This prevents duplicate messages when history includes content that was streaming
                if let streaming = self.streamingMessage, !streaming.text.isEmpty {
                    print("[ViewModel] Clearing streaming message before history update: '\(streaming.text.prefix(50))...'")
                }
                self.streamingMessage = nil
                self.streamingResponseText = ""
                self.gatewayFullText = ""
                
                self.messages = historyMessages
                print("[ViewModel] Updated messages array, now has \(self.messages.count) messages")
            }
            await MessagePersistenceManager.shared.clearAllMessages()
            await MessagePersistenceManager.shared.saveMessages(historyMessages)
        } catch {
            print("[ViewModel] Failed to load gateway history: \(error.localizedDescription)")
        }
    }
    
    private struct GatewayToolCallEntry {
        let id: String?
        let name: String
        let info: ToolCallInfo
    }
    
    private struct GatewayToolResultEntry {
        let id: String?
        let name: String?
        let text: String
    }
    
    /// Map gateway history messages into local transcript messages.
    private func mapGatewayHistoryMessages(_ historyMessages: [GatewayChatHistoryMessage]) -> [TranscriptMessage] {
        var transcript: [TranscriptMessage] = []
        var toolCallLookup: [String: (messageIndex: Int, toolIndex: Int)] = [:]
        transcript.reserveCapacity(historyMessages.count)
        
        for message in historyMessages {
            if isToolResultMessage(message) {
                applyToolResultMessage(message, to: &transcript, toolCallLookup: &toolCallLookup)
                continue
            }
            
            let text = gatewayTextContent(from: message)
            let toolEntries = gatewayToolCallEntries(from: message)
            var toolCalls = toolEntries.map { $0.info }
            
            let inlineResults = gatewayToolResultEntries(from: message)
            applyInlineToolResults(inlineResults, to: &toolCalls)
            
            let isUser = message.role.lowercased() == "user"
            
            // Filter out heartbeat messages
            if isUser && isHeartbeatUserMessage(text) {
                continue
            }
            if !isUser && isHeartbeatOnlyResponse(text) {
                continue
            }
            
            let transcriptMessage = TranscriptMessage(
                text: text,
                isUser: isUser,
                isStreaming: false,
                wasInterrupted: false,
                toolCalls: toolCalls
            )
            transcript.append(transcriptMessage)
            
            let messageIndex = transcript.count - 1
            for (index, entry) in toolEntries.enumerated() {
                if let id = entry.id {
                    toolCallLookup[id.lowercased()] = (messageIndex: messageIndex, toolIndex: index)
                }
            }
        }
        
        return transcript
    }
    
    private func isToolResultMessage(_ message: GatewayChatHistoryMessage) -> Bool {
        let role = message.role.lowercased()
        return role == "toolresult" || role == "tool_result"
    }
    
    private func gatewayTextContent(from message: GatewayChatHistoryMessage) -> String {
        let parts = message.content.compactMap { content -> String? in
            let kind = (content.type ?? "text").lowercased()
            guard kind == "text" || kind.isEmpty else { return nil }
            return content.text
        }
        return parts.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    private func gatewayToolCallEntries(from message: GatewayChatHistoryMessage) -> [GatewayToolCallEntry] {
        var entries: [GatewayToolCallEntry] = []
        for content in message.content where isToolCallContent(content) {
            let toolName = content.name ?? message.toolName ?? "tool"
            let toolCallId = content.id ?? message.toolCallId
            let argsText = content.arguments?.stringValue()
            let toolUUID = toolCallId.flatMap(UUID.init(uuidString:)) ?? UUID()
            let info = ToolCallInfo(id: toolUUID, name: toolName, input: argsText, output: nil, isComplete: false)
            entries.append(GatewayToolCallEntry(id: toolCallId, name: toolName, info: info))
        }
        return entries
    }
    
    private func gatewayToolResultEntries(from message: GatewayChatHistoryMessage) -> [GatewayToolResultEntry] {
        message.content.compactMap { content -> GatewayToolResultEntry? in
            guard isToolResultContent(content) else { return nil }
            let rawText = content.text ?? content.content?.stringValue() ?? ""
            let trimmed = rawText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            return GatewayToolResultEntry(
                id: content.id ?? message.toolCallId,
                name: content.name ?? message.toolName,
                text: trimmed
            )
        }
    }
    
    private func applyInlineToolResults(_ results: [GatewayToolResultEntry], to toolCalls: inout [ToolCallInfo]) {
        for result in results {
            if let id = result.id,
               let index = toolCalls.firstIndex(where: { $0.id.uuidString.lowercased() == id.lowercased() }) {
                toolCalls[index].output = truncateToWords(result.text, maxWords: 200)
                toolCalls[index].isComplete = true
                continue
            }
            if let name = result.name,
               let index = toolCalls.firstIndex(where: { $0.name == name }) {
                toolCalls[index].output = truncateToWords(result.text, maxWords: 200)
                toolCalls[index].isComplete = true
            }
        }
    }
    
    private func applyToolResultMessage(
        _ message: GatewayChatHistoryMessage,
        to transcript: inout [TranscriptMessage],
        toolCallLookup: inout [String: (messageIndex: Int, toolIndex: Int)]
    ) {
        let resultText = gatewayTextContent(from: message)
        guard !resultText.isEmpty else { return }
        
        let toolCallId = message.toolCallId ?? message.content.compactMap { $0.id }.first
        let toolName = message.toolName ?? message.content.compactMap { $0.name }.first
        
        if let id = toolCallId?.lowercased(), let lookup = toolCallLookup[id] {
            var targetMessage = transcript[lookup.messageIndex]
            targetMessage.toolCalls[lookup.toolIndex].output = truncateToWords(resultText, maxWords: 200)
            targetMessage.toolCalls[lookup.toolIndex].isComplete = true
            transcript[lookup.messageIndex] = targetMessage
            return
        }
        
        if let name = toolName,
           let messageIndex = transcript.lastIndex(where: { message in
               message.toolCalls.contains(where: { $0.name == name })
           }),
           let toolIndex = transcript[messageIndex].toolCalls.firstIndex(where: { $0.name == name }) {
            var targetMessage = transcript[messageIndex]
            targetMessage.toolCalls[toolIndex].output = truncateToWords(resultText, maxWords: 200)
            targetMessage.toolCalls[toolIndex].isComplete = true
            transcript[messageIndex] = targetMessage
            return
        }
        
        let fallbackToolName = toolName ?? "tool"
        let toolCall = ToolCallInfo(
            name: fallbackToolName,
            input: nil,
            output: truncateToWords(resultText, maxWords: 200),
            isComplete: true
        )
        let toolResultMessage = TranscriptMessage(
            text: "",
            isUser: false,
            isStreaming: false,
            wasInterrupted: false,
            toolCalls: [toolCall]
        )
        transcript.append(toolResultMessage)
    }
    
    private func isToolCallContent(_ content: GatewayChatHistoryContent) -> Bool {
        let kind = (content.type ?? "").lowercased()
        if ["toolcall", "tool_call", "tooluse", "tool_use"].contains(kind) {
            return true
        }
        return content.name != nil && content.arguments != nil
    }
    
    private func isToolResultContent(_ content: GatewayChatHistoryContent) -> Bool {
        let kind = (content.type ?? "").lowercased()
        return kind == "toolresult" || kind == "tool_result"
    }
    
    // MARK: - Gateway Chat Event Handling
    
    /// Await the completion of the current gateway response.
    private func waitForGatewayResponse() async {
        await withCheckedContinuation { continuation in
            gatewayResponseContinuation = continuation
        }
    }
    
    /// Resolve any pending gateway response continuation.
    private func finishGatewayResponse() {
        guard let continuation = gatewayResponseContinuation else { return }
        gatewayResponseContinuation = nil
        continuation.resume()
    }
    
    /// Ensure the streaming message exists for gateway events.
    private func ensureGatewayStreamingMessage() {
        if streamingMessage == nil {
            streamingMessage = TranscriptMessage(
                text: "",
                isUser: false,
                isStreaming: true
            )
        }
    }

    /// Determine whether a gateway chat event should be processed (dedupe by seq).
    private func shouldProcessGatewaySeq(_ seq: Int?) -> Bool {
        guard let seq else { return true }
        if let last = lastGatewaySeq, seq <= last {
            return false
        }
        lastGatewaySeq = seq
        return true
    }

    /// Allow terminal events with the same seq as the last delta (gateway sometimes reuses seq).
    private func shouldProcessGatewayFinalSeq(_ seq: Int?) -> Bool {
        guard let seq else { return true }
        if let last = lastGatewaySeq, seq < last {
            return false
        }
        lastGatewaySeq = seq
        return true
    }

    /// Normalize whitespace for loose string comparisons.
    private func normalizeWhitespace(_ text: String) -> String {
        text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }
    
    // MARK: - Heartbeat Message Filtering
    
    /// The standard heartbeat system prompt that should be filtered
    private let heartbeatSystemPrompt = "Read HEARTBEAT.md if it exists (workspace context). Follow it strictly. Do not infer or repeat old tasks from prior chats. If nothing needs attention, reply HEARTBEAT_OK."
    
    /// Check if a user message is a heartbeat system message (should be filtered)
    /// Returns true if the message should be hidden from the UI
    private func isHeartbeatUserMessage(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Check if it's exactly the heartbeat prompt
        if trimmed == heartbeatSystemPrompt {
            return true
        }
        
        // Check if it ends with the heartbeat prompt (has custom payload above it)
        // The format is: [custom content]\n\n[heartbeat prompt]
        if trimmed.hasSuffix(heartbeatSystemPrompt) {
            return true
        }
        
        return false
    }
    
    /// Check if an assistant message is a heartbeat-only response (should be filtered)
    /// Returns true if the message should be hidden from the UI
    /// Only filters if the message is EXACTLY "HEARTBEAT_OK" - any additional content means it should be shown
    private func isHeartbeatOnlyResponse(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed == "HEARTBEAT_OK"
    }
    
    /// Check if a partial response could still be a heartbeat-only response
    /// Returns true while the text is a prefix of "HEARTBEAT_OK" (we don't know yet if it will be more)
    private func couldBeHeartbeatResponse(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // If it's exactly HEARTBEAT_OK, it could still get more text appended
        if trimmed == "HEARTBEAT_OK" {
            return true
        }
        // If HEARTBEAT_OK starts with this text, it could still become HEARTBEAT_OK
        return "HEARTBEAT_OK".hasPrefix(trimmed) && !trimmed.isEmpty
    }
    
    /// Handle chat events from the gateway and map them to the existing UI state.
    private func handleGatewayChatEvent(_ event: GatewayChatEvent) {
        guard !suppressGatewayFinalization else { return }
        
        switch event {
        case .textDelta(let text, let seq):
            guard shouldProcessGatewaySeq(seq) else { return }
            if text.isEmpty { return }

            // Track if this could be a heartbeat response (suppress TTS until we know)
            let shouldSuppressTTS = couldBeHeartbeatResponse(text)
            
            if gatewayFullText.isEmpty {
                gatewayFullText = text
                if inputMode == .voice && !isGatewayToolExecuting && !shouldSuppressTTS {
                    incrementalTTS.appendText(text)
                }
            } else if text == gatewayFullText {
                return
            } else {
                let normalizedIncoming = normalizeWhitespace(text)
                let normalizedCurrent = normalizeWhitespace(gatewayFullText)

                if text.count >= gatewayFullText.count && normalizedIncoming.contains(normalizedCurrent) {
                    if text.hasPrefix(gatewayFullText) {
                        let suffix = text.dropFirst(gatewayFullText.count)
                        if !suffix.isEmpty, inputMode == .voice && !isGatewayToolExecuting && !shouldSuppressTTS {
                            incrementalTTS.appendText(String(suffix))
                        }
                    }
                    gatewayFullText = text
                } else if normalizedCurrent.contains(normalizedIncoming) {
                    return
                } else if text.hasPrefix(gatewayFullText) {
                    let suffix = text.dropFirst(gatewayFullText.count)
                    if !suffix.isEmpty {
                        gatewayFullText += suffix
                        if inputMode == .voice && !isGatewayToolExecuting && !shouldSuppressTTS {
                            incrementalTTS.appendText(String(suffix))
                        }
                    }
                } else {
                    gatewayFullText += text
                    if inputMode == .voice && !isGatewayToolExecuting && !shouldSuppressTTS {
                        incrementalTTS.appendText(text)
                    }
                }
            }
            
            // Don't update UI for potential heartbeat responses
            if shouldSuppressTTS {
                return
            }
            
            streamingResponseText = gatewayFullText
            processingState = .responding
            
            ensureGatewayStreamingMessage()
            streamingMessage?.text = gatewayFullText
            
        case .thinkingDelta(_, let seq):
            guard shouldProcessGatewaySeq(seq) else { return }
            processingState = .thinking
            
        case .toolCallStart(let name, let toolId):
            processingState = .usingTool(name: name)
            isGatewayToolExecuting = true
            
            ensureGatewayStreamingMessage()
            let toolCall = ToolCallInfo(
                id: toolId.map { UUID(uuidString: $0) ?? UUID() } ?? UUID(),
                name: name,
                input: nil,
                output: nil,
                isComplete: false
            )
            streamingMessage?.toolCalls.append(toolCall)
            
        case .toolCallEnd(let name, let toolId, let result):
            processingState = .responding
            isGatewayToolExecuting = false
            
            let matchingIndex = streamingMessage?.toolCalls.firstIndex(where: { call in
                if let toolId = toolId, let uuid = UUID(uuidString: toolId) {
                    return call.id == uuid && !call.isComplete
                }
                return call.name == name && !call.isComplete
            })
            
            if let index = matchingIndex {
                streamingMessage?.toolCalls[index].output = truncateToWords(result, maxWords: 200)
                streamingMessage?.toolCalls[index].isComplete = true
            }
            
        case .done(_, _, let finalText, let seq):
            guard shouldProcessGatewayFinalSeq(seq) else { return }
            guard gatewayResponseContinuation != nil else { return }
            
            // Check if this is a heartbeat-only response before processing
            let effectiveFinalText = finalText ?? gatewayFullText
            let isHeartbeat = isHeartbeatOnlyResponse(effectiveFinalText)
            
            if let finalText, !finalText.isEmpty, !isHeartbeat {
                let normalizedFinal = normalizeWhitespace(finalText)
                let normalizedCurrent = normalizeWhitespace(gatewayFullText)
                let shouldReplace = gatewayFullText.isEmpty
                    || finalText.count > gatewayFullText.count
                    || !normalizedFinal.hasPrefix(normalizedCurrent)

                if shouldReplace {
                    // Check if finalText has content beyond what we already sent to TTS
                    if finalText.count > gatewayFullText.count && finalText.hasPrefix(gatewayFullText) {
                        let missingSuffix = String(finalText.dropFirst(gatewayFullText.count))
                        if !missingSuffix.isEmpty && inputMode == .voice && !isGatewayToolExecuting {
                            print("[TTS] Final text has additional content: '\(missingSuffix)'")
                            incrementalTTS.appendText(missingSuffix)
                        }
                    } else if gatewayFullText.isEmpty && inputMode == .voice && !isGatewayToolExecuting {
                        // No deltas were received, send the entire final text
                        print("[TTS] No deltas received, sending entire final text")
                        incrementalTTS.appendText(finalText)
                    }
                    gatewayFullText = finalText
                    streamingResponseText = finalText
                    ensureGatewayStreamingMessage()
                    streamingMessage?.text = finalText
                }
            }
            if inputMode == .voice && !isHeartbeat {
                incrementalTTS.flush()
            }
            processingState = .idle
            isGatewayToolExecuting = false
            
            finalizeGatewayStreamingMessage()
            Task {
                await gatewayChatClient.clearRunState()
            }
            finishGatewayResponse()
            
            // Reload history after a brief delay to sync any messages added during the run
            // (e.g., tool outputs, injected messages, or other async additions).
            // The delay ensures finalization completes before history replaces messages.
            Task {
                try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 second delay
                await loadGatewayHistory()
            }
            
        case .error(_, let message, let seq):
            guard shouldProcessGatewayFinalSeq(seq) else { return }
            guard gatewayResponseContinuation != nil else { return }
            let errorMessage = "Error: \(message)"
            addMessage(errorMessage, isUser: false)
            if inputMode == .voice {
                incrementalTTS.appendText(errorMessage)
                incrementalTTS.flush()
            }
            processingState = .idle
            isGatewayToolExecuting = false
            
            finalizeGatewayStreamingMessage()
            Task {
                await gatewayChatClient.clearRunState()
            }
            finishGatewayResponse()
            
        case .agentStatus:
            break
        }
    }
    
    /// Finalize the current gateway streaming message and persist it.
    private func finalizeGatewayStreamingMessage() {
        defer {
            streamingMessage = nil
        }

        if var completedMessage = streamingMessage, !completedMessage.text.isEmpty {
            // Filter out heartbeat-only responses
            if isHeartbeatOnlyResponse(completedMessage.text) {
                return
            }
            
            completedMessage.isStreaming = false
            messages.append(completedMessage)
            
            Task {
                await MessagePersistenceManager.shared.saveMessage(completedMessage)
            }
        } else if !gatewayFullText.isEmpty {
            // Filter out heartbeat-only responses
            if !isHeartbeatOnlyResponse(gatewayFullText) {
                addMessage(gatewayFullText, isUser: false)
            }
        }
    }
    
    /// Handle a gateway disconnect while a response is streaming.
    private func handleGatewayDisconnection(reason: String) {
        guard streamingMessage?.isStreaming == true || !streamingResponseText.isEmpty else { return }
        guard !suppressGatewayFinalization else { return }
        
        incrementalTTS.stop()
        finalizeCancelledStreamingMessage(marker: "[connection lost]")
        suppressGatewayFinalization = true
        gatewayFullText = ""
        lastGatewaySeq = nil
        isGatewayToolExecuting = false
        streamingMessage = nil
        streamingResponseText = ""
        processingState = .idle
        finishGatewayResponse()
        
        // Dual connection manager handles reconnection automatically
        // No need to explicitly trigger reconnect here
    }
    
    /// Send command using Gateway mode via Clawdbot bridge.
    /// Uses the chat.* methods provided by the gateway.
    /// - Parameters:
    ///   - command: The text command to send
    ///   - images: Optional array of image attachments to include for visual analysis
    private func sendCommandWithGateway(_ command: String, images: [ImageAttachment] = []) async {
        // Check gateway connection and attempt to reconnect if needed
        // Need chat capability (operator connection) to send messages
        if !gatewayDualConnectionManager.status.hasChatCapability {
            let offlineMessage = "Gateway not connected. Attempting to reconnect..."
            addMessage(offlineMessage, isUser: false)
            
            // Attempt to reconnect
            await gatewayDualConnectionManager.connectIfNeeded()
            // Wait briefly for connection
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if !gatewayDualConnectionManager.status.hasChatCapability {
                let failMessage = "Failed to connect to gateway. Please check settings."
                addMessage(failMessage, isUser: false)
                if inputMode == .voice {
                    incrementalTTS.appendText("Gateway connection failed. Please check your settings.")
                    incrementalTTS.flush()
                }
                if !images.isEmpty {
                    pendingImages = images
                }
                return
            }
        }
        
        // Reset state for new response
        suppressGatewayFinalization = false
        streamingResponseText = ""
        streamingMessage = nil
        gatewayFullText = ""
        lastGatewaySeq = nil
        isGatewayToolExecuting = false
        if inputMode == .voice {
            incrementalTTS.reset()
        }
        processingState = .thinking
        
        async let responseWait: Void = waitForGatewayResponse()
        
        do {
            // Send message via gateway chat client
            _ = try await gatewayChatClient.sendMessage(
                text: command,
                images: images,
                thinking: "low"
            )
            
            // Wait for streaming completion signaled by gateway events
            await responseWait
            
        } catch {
            // Ensure any pending response wait is released
            finishGatewayResponse()
            await responseWait
            
            // Handle gateway errors
            await handleGatewayError(error)
            
            // Restore text and images for retry
            if !command.isEmpty {
                textInput = command
            }
            if !images.isEmpty {
                pendingImages = images
                showToast("Failed to send. Tap send to retry.")
            }
            
            streamingMessage = nil
            processingState = .idle
        }
    }
    
    /// Handle gateway errors with user-friendly messages
    private func handleGatewayError(_ error: Error) async {
        let errorDescription = error.localizedDescription.lowercased()
        
        if errorDescription.contains("not connected") {
            addMessage("Gateway connection lost. Attempting to reconnect...", isUser: false)
            if inputMode == .voice {
                incrementalTTS.appendText("Connection lost. I'm trying to reconnect.")
                incrementalTTS.flush()
            }
            // Trigger reconnection in background - dual connection manager handles reconnect automatically
            Task {
                await gatewayDualConnectionManager.connectIfNeeded()
            }
        } else if errorDescription.contains("vpn") {
            addMessage("VPN is not connected. Please connect to your VPN.", isUser: false)
            if inputMode == .voice {
                incrementalTTS.appendText("VPN is not connected. Please connect to your VPN.")
                incrementalTTS.flush()
            }
        } else {
            addMessage("Error: \(error.localizedDescription)", isUser: false)
            if inputMode == .voice {
                incrementalTTS.appendText("Sorry, something went wrong. Please try again.")
                incrementalTTS.flush()
            }
        }
    }
    
    // MARK: - Text Truncation Helpers
    
    /// Truncate a string to a maximum number of words, adding "..." if truncated.
    /// - Parameters:
    ///   - text: The text to truncate (optional, returns nil if input is nil)
    ///   - maxWords: Maximum number of words to keep
    /// - Returns: Truncated text with "..." suffix if truncated, or original text if within limit
    private func truncateToWords(_ text: String?, maxWords: Int) -> String? {
        guard let text = text else { return nil }
        
        let words = text.split(separator: " ", omittingEmptySubsequences: true)
        
        if words.count <= maxWords {
            return text
        }
        
        let truncatedWords = words.prefix(maxWords)
        return truncatedWords.joined(separator: " ") + "..."
    }

    /// Stop any ongoing speech
    func stopSpeaking() {
        incrementalTTS.stop()
    }
    
    /// Abort the current response generation (cancel mid-response)
    func abortGeneration() {
        guard !isAborting else { return }
        
        isAborting = true
        
        Task {
            // Stop speech immediately for responsive feedback
            incrementalTTS.stop()
            
            // Persist the partial response with a cancellation marker (if any)
            finalizeCancelledStreamingMessage(marker: "[Response cancelled]")
            
            // Send abort signal to the gateway
            suppressGatewayFinalization = true
            gatewayFullText = ""
            lastGatewaySeq = nil
            isGatewayToolExecuting = false
            finishGatewayResponse()
            try? await gatewayChatClient.abort()
            
            streamingMessage = nil
            streamingResponseText = ""
            processingState = .idle
            isAborting = false
        }
    }

    private func addMessage(_ text: String, isUser: Bool) {
        let message = TranscriptMessage(text: text, isUser: isUser)
        messages.append(message)
        
        // Persist the message to local storage for history across app restarts
        Task {
            await MessagePersistenceManager.shared.saveMessage(message)
        }
    }
    
    /// Add a message with image attachment references
    /// - Parameters:
    ///   - text: The message text
    ///   - isUser: Whether this is a user message
    ///   - imageAttachmentIds: UUIDs of attached images (stored in ImageAttachmentStore)
    private func addMessageWithImages(_ text: String, isUser: Bool, imageAttachmentIds: [UUID]) {
        let message = TranscriptMessage(
            text: text,
            isUser: isUser,
            imageAttachmentIds: imageAttachmentIds
        )
        messages.append(message)
        
        // Persist the message to local storage for history across app restarts
        // Note: imageAttachmentIds are NOT persisted (session-only) by TranscriptMessage's Codable
        Task {
            await MessagePersistenceManager.shared.saveMessage(message)
        }
    }

    func connect() async {
        // Apply session key from settings before connecting
        if let credentials = KeychainManager.shared.loadGatewayCredentials() {
            gatewayDualConnectionManager.chatSessionKey = credentials.sessionKey
            print("[ClawdyViewModel] Using session key: \(credentials.sessionKey)")
        }

        // Reflect current gateway dual connection status before attempting to connect.
        let status = gatewayDualConnectionManager.status
        switch status {
        case .disconnected:
            if gatewayDualConnectionManager.authTokenMissing {
                connectionStatus = .disconnected(reason: "Auth token required")
            } else {
                connectionStatus = .disconnected(reason: "Not connected")
            }
        case .connecting:
            connectionStatus = .connecting
        case .partialOperator:
            let name = gatewayDualConnectionManager.serverName ?? "gateway"
            connectionStatus = .partialOperator(serverName: name, nodeStatus: .disconnected)
        case .partialNode:
            connectionStatus = .partialNode(chatStatus: .disconnected)
        case .connected:
            let name = gatewayDualConnectionManager.serverName ?? "gateway"
            connectionStatus = .connected(serverName: name)
        case .pairingPendingOperator:
            connectionStatus = .partialNode(chatStatus: .pairingPending)
        case .pairingPendingNode:
            let name = gatewayDualConnectionManager.serverName ?? "gateway"
            connectionStatus = .partialOperator(serverName: name, nodeStatus: .pairingPending)
        case .pairingPendingBoth:
            connectionStatus = .pairingPending(chatStatus: .pairingPending, nodeStatus: .pairingPending)
        }

        // Gateway mode - connect via GatewayDualConnectionManager
        // The dual connection manager handles VPN-aware auto-connect for both operator and node roles
        await gatewayDualConnectionManager.connectIfNeeded()
        // Status will be updated via the published status binding

        // Request notification permissions on first gateway connect
        // This is needed for chat.push notifications when app is backgrounded
        Task {
            await NotificationManager.shared.requestAuthorization()
        }
    }

    func disconnect() {
        Task {
            await gatewayDualConnectionManager.disconnect()
        }
        connectionStatus = .disconnected(reason: "Disconnected")
        isReconnecting = false
    }
    
    /// Trigger a reconnection attempt with UI feedback.
    /// This forces a full reconnection, cleaning up any stale connection state.
    func triggerReconnection() async {
        guard !isReconnecting else { return }
        
        isReconnecting = true
        connectionStatus = .connecting
        
        // Use forceReconnect to ensure we clean up stale connections
        await gatewayDualConnectionManager.forceReconnect()
        
        // Wait briefly for connection
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        
        let status = gatewayDualConnectionManager.status
        switch status {
        case .connected:
            connectionStatus = .connected(serverName: serverName)
        case .partialOperator:
            connectionStatus = .partialOperator(serverName: serverName, nodeStatus: .disconnected)
        case .partialNode:
            connectionStatus = .partialNode(chatStatus: .disconnected)
        case .pairingPendingOperator:
            connectionStatus = .partialNode(chatStatus: .pairingPending)
        case .pairingPendingNode:
            connectionStatus = .partialOperator(serverName: serverName, nodeStatus: .pairingPending)
        case .pairingPendingBoth:
            connectionStatus = .pairingPending(chatStatus: .pairingPending, nodeStatus: .pairingPending)
        case .connecting, .disconnected:
            connectionStatus = .disconnected(reason: "Reconnection failed")
        }
        
        isReconnecting = false
    }

    func clearMessages() {
        messages.removeAll()
    }

    /// Clear session context (conversation history)
    /// This clears: local messages, message persistence, session context, and in gateway mode
    /// clears the gateway session. Also performs disconnect/reconnect for fresh state.
    func clearContext() {
        Task {
            // Clear local messages array and persisted message history
            messages.removeAll()
            await MessagePersistenceManager.shared.clearAllMessages()
            
            // Disconnect and reconnect to ensure fresh connection state
            await performDisconnectReconnect()
            
            // Show toast feedback
            showToast("Context cleared")
        }
    }
    
    /// Helper to show a toast message that auto-hides after 2 seconds
    func showToast(_ message: String) {
        toastMessage = message
        
        // Auto-hide after 2 seconds
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            // Only clear if it's still the same message (in case another toast was shown)
            if toastMessage == message {
                toastMessage = nil
            }
        }
    }
    
    /// Show camera flash feedback when a photo is captured via camera.snap
    /// This provides visual feedback similar to the iOS camera app
    func showCameraFlash() {
        showingCameraFlash = true
        
        // Auto-hide the flash after a brief duration
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 150_000_000) // 150ms
            showingCameraFlash = false
        }
    }
    
    /// Perform disconnect and reconnect cycle for fresh connection state
    private func performDisconnectReconnect() async {
        await gatewayDualConnectionManager.disconnect()
        connectionStatus = .disconnected(reason: "Reconnecting...")
        
        // Brief pause to ensure clean disconnect
        try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        
        // Reconnect
        await connect()
    }
    
    // MARK: - Node Capability Handlers
    
    /// Set up handlers for node capabilities that the gateway can invoke.
    /// This wires up chat.push, camera.*, location.*, and system.notify handlers.
    /// 
    /// Handlers are wired to `nodeCapabilityHandler` which is used by `GatewayDualConnectionManager.onInvoke`
    /// to handle invoke requests from the gateway via the unified WebSocket connection.
    private func setupNodeCapabilityHandlers() {
        // chat.push - Agent-initiated message delivery via node invoke.
        // This is called when the gateway wants to push a message to the device
        // without a user prompt (e.g., cron jobs, background tasks, async notifications).
        //
        // In the unified WebSocket architecture:
        // - All communication flows through a single WebSocket on port 18789
        // - chat.push is a node invoke command that delivers agent messages
        //
        // This handler:
        // - Appends the message to the local transcript
        // - Shows a push notification if the app is backgrounded
        // - Optionally speaks the message via TTS if requested
        let chatPushHandler: (String, Bool) async -> String? = { [weak self] text, speak in
            guard let self = self else { return nil }
            
            // Create a unique message ID for tracking
            let messageId = UUID()
            let messageIdString = messageId.uuidString
            
            // Check if app is in background
            let isBackground = await MainActor.run { UIApplication.shared.applicationState == .background }
            
            print("[chat.push] Received agent message: \"\(text.prefix(50))...\" speak=\(speak) isBackground=\(isBackground)")
            
            // Add as agent message (not user message)
            // This appends to the transcript and persists to local storage
            // The TranscriptScrollView will auto-scroll to the new message via its .onChange(of: messages.count) handler
            await MainActor.run {
                self.addMessage(text, isUser: false)
            }
            
            if isBackground {
                // App is backgrounded: show a push notification
                // This allows the user to see the message even when not in the app
                await NotificationManager.shared.scheduleChatPushNotification(
                    text: text,
                    messageId: messageIdString
                )
            } else {
                // App is active: provide haptic feedback to notify the user of the incoming message
                // Medium impact provides a noticeable but not jarring notification
                await MainActor.run {
                    let impact = UIImpactFeedbackGenerator(style: .medium)
                    impact.impactOccurred()
                    
                    // Speak the message via TTS if requested
                    // Uses the same incremental TTS pipeline as streaming responses
                    if speak {
                        // Feed the text to the incremental TTS manager
                        // It will handle sentence buffering and speak using the user's preferred TTS engine
                        self.incrementalTTS.appendText(text)
                        self.incrementalTTS.flush()
                    }
                }
            }
            
            return messageIdString
        }
        nodeCapabilityHandler.onChatPush = chatPushHandler
        
        // camera.list - Return available cameras
        // Uses CameraCapabilityService to discover actual device cameras
        let cameraListHandler: () async -> CameraListResult = {
            return await CameraCapabilityService.shared.listCameras()
        }
        nodeCapabilityHandler.onCameraList = cameraListHandler
        
        // camera.snap - Capture a photo using CameraCapabilityService
        // Returns base64-encoded JPEG image with dimensions
        // Shows HUD flash feedback when photo is captured
        let cameraSnapHandler: (CameraSnapParams) async -> CameraSnapResult = { [weak self] params in
            guard let self = self else {
                return CameraSnapResult(
                    format: nil,
                    base64: nil,
                    width: nil,
                    height: nil,
                    error: "ViewModel deallocated"
                )
            }
            
            do {
                // Show flash feedback before capture (on main thread)
                await MainActor.run {
                    self.showCameraFlash()
                }
                
                // Capture photo using CameraCapabilityService
                let result = try await CameraCapabilityService.shared.snap(
                    facing: params.facingValue,
                    maxWidth: params.maxWidth,
                    quality: params.quality,
                    delayMs: params.delayMs
                )
                
                return result
            } catch {
                return CameraSnapResult(
                    format: nil,
                    base64: nil,
                    width: nil,
                    height: nil,
                    error: error.localizedDescription
                )
            }
        }
        nodeCapabilityHandler.onCameraSnap = cameraSnapHandler
        
        // camera.clip - Record a video clip using CameraCapabilityService
        // Returns base64-encoded MP4 video with duration info
        // Shows recording feedback while capturing
        let cameraClipHandler: (CameraClipParams) async -> CameraClipResult = { params in
            do {
                // Record video clip using CameraCapabilityService
                let result = try await CameraCapabilityService.shared.clip(
                    facing: params.facingValue,
                    durationMs: params.durationMs,
                    includeAudio: params.includeAudio ?? true
                )
                
                return result
            } catch {
                return CameraClipResult(
                    format: nil,
                    base64: nil,
                    durationMs: nil,
                    hasAudio: nil,
                    error: error.localizedDescription
                )
            }
        }
        nodeCapabilityHandler.onCameraClip = cameraClipHandler
        
        // location.get - Get current location
        let locationGetHandler: (LocationGetParams) async -> LocationGetResult = { params in
            print("[NodeCapabilityHandler] location.get invoked with params: \(params)")
            return await LocationCapabilityService.shared.getLocation(params: params)
        }
        nodeCapabilityHandler.onLocationGet = locationGetHandler
        
        // system.notify - Show a notification (without adding to chat)
        let systemNotifyHandler: (SystemNotifyParams) async -> SystemNotifyResult = { params in
            print("[NodeCapabilityHandler] system.notify invoked - title: \(params.title)")
            let result = await NotificationManager.shared.scheduleSystemNotification(
                title: params.title,
                body: params.body,
                sound: params.sound ?? true,
                priority: params.priority ?? "active"
            )
            
            switch result {
            case .success:
                return .success
            case .permissionDenied:
                return .permissionDenied
            case .failed(let error):
                return .failed(error.localizedDescription)
            }
        }
        nodeCapabilityHandler.onSystemNotify = systemNotifyHandler
    }
}
