import Foundation
import AVFoundation

/// Protocol defining the interface for text-to-speech providers.
/// Both system TTS (AVSpeechSynthesizer) and Kokoro TTS implement this protocol.
protocol TTSProvider {
    /// Speak the given text asynchronously
    /// - Parameter text: The text to speak
    func speak(_ text: String) async throws
    
    /// Stop any ongoing speech
    func stop() async
    
    /// Whether the provider is currently speaking
    var isSpeaking: Bool { get async }
    
    /// Whether the provider is ready to use (e.g., model downloaded for Kokoro)
    var isReady: Bool { get async }
    
    /// Human-readable name of the provider
    var providerName: String { get }
}

/// Unified TTS manager that abstracts over Kokoro and system TTS.
/// Automatically falls back to system TTS if Kokoro is unavailable.
/// Integrates with IncrementalTTSManager pattern for streaming responses.
@MainActor
class UnifiedTTSManager: ObservableObject {
    
    // MARK: - Singleton
    
    static let shared = UnifiedTTSManager()
    
    // MARK: - Published State
    
    @Published private(set) var isSpeaking = false
    @Published private(set) var currentProvider: TTSEngine = .system
    @Published private(set) var lastError: String?
    
    // MARK: - Dependencies
    
    private let voiceSettings = VoiceSettingsManager.shared
    private let kokoroManager = KokoroTTSManager.shared
    private let systemSynthesizer = AVSpeechSynthesizer()
    
    /// Delegate for system TTS completion callbacks
    private var systemDelegate: SystemTTSDelegateHandler?
    
    /// Continuation for async system TTS completion
    private var systemSpeechContinuation: CheckedContinuation<Void, Never>?
    
    /// Flag to track system TTS speaking state
    private var systemIsSpeaking = false
    
    // MARK: - Initialization
    
    private init() {
        systemDelegate = SystemTTSDelegateHandler { [weak self] in
            self?.handleSystemSpeechFinished()
        }
        systemSynthesizer.delegate = systemDelegate
    }
    
    // MARK: - Public API
    
    /// The preferred TTS engine from user settings
    var preferredEngine: TTSEngine {
        voiceSettings.settings.ttsEngine
    }
    
    /// Whether the preferred engine is ready to use
    var isPreferredEngineReady: Bool {
        get async {
            switch preferredEngine {
            case .system, .elevenLabs:
                return true // System and ElevenLabs TTS are always available
            case .kokoro:
                return await kokoroManager.modelDownloaded
            }
        }
    }
    
    /// Speak text using the preferred TTS engine, with automatic fallback.
    /// - Parameter text: The text to speak
    /// - Throws: Error if speech fails and no fallback is available
    func speak(_ text: String) async throws {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        
        lastError = nil
        
        switch preferredEngine {
        case .kokoro:
            do {
                try await speakWithKokoro(text)
            } catch {
                // Fall back to system TTS
                print("[UnifiedTTSManager] Kokoro failed, falling back to system TTS: \(error.localizedDescription)")
                lastError = "Kokoro unavailable, using system TTS"
                try await speakWithSystem(text)
            }
        case .system, .elevenLabs:
            // ElevenLabs is handled by IncrementalTTSManager; fall through to system TTS here
            try await speakWithSystem(text)
        }
    }
    
    /// Stop any ongoing speech from either engine.
    func stop() async {
        // Stop Kokoro
        await kokoroManager.stopPlayback()
        
        // Stop system TTS
        if systemSynthesizer.isSpeaking {
            systemSynthesizer.stopSpeaking(at: .immediate)
        }
        
        systemIsSpeaking = false
        isSpeaking = false
        
        // Resume any waiting continuation
        systemSpeechContinuation?.resume()
        systemSpeechContinuation = nil
        
        BackgroundAudioManager.shared.audioEnded()
    }
    
    /// Preview the selected voice for the current engine
    func previewVoice() async throws {
        let previewText = "Hello, this is a voice preview."
        try await speak(previewText)
    }
    
    // MARK: - Kokoro TTS
    
    private func speakWithKokoro(_ text: String) async throws {
        guard await kokoroManager.modelDownloaded else {
            throw UnifiedTTSError.kokoroNotDownloaded
        }
        
        currentProvider = .kokoro
        isSpeaking = true
        BackgroundAudioManager.shared.audioStarted()
        
        defer {
            Task { @MainActor in
                isSpeaking = false
                BackgroundAudioManager.shared.audioEnded()
            }
        }
        
        let speed = voiceSettings.settings.speechRate
        try await kokoroManager.speakText(text, speed: speed)
    }
    
    // MARK: - System TTS
    
    private func speakWithSystem(_ text: String) async throws {
        currentProvider = .system
        isSpeaking = true
        systemIsSpeaking = true
        
        // Configure audio session
        configureAudioSession()
        
        // Create utterance
        let utterance = AVSpeechUtterance(string: text)
        
        // Configure voice
        if let voice = selectSystemVoice() {
            utterance.voice = voice
        }
        
        // Configure rate
        let rateMultiplier = voiceSettings.settings.speechRate
        utterance.rate = AVSpeechUtteranceDefaultSpeechRate * rateMultiplier * 0.92
        utterance.pitchMultiplier = 0.95
        utterance.volume = 1.0
        utterance.preUtteranceDelay = 0.15
        utterance.postUtteranceDelay = 0.05
        
        BackgroundAudioManager.shared.audioStarted()
        
        // Wait for speech to complete
        await withCheckedContinuation { continuation in
            systemSpeechContinuation = continuation
            systemSynthesizer.speak(utterance)
        }
        
        isSpeaking = false
        BackgroundAudioManager.shared.audioEnded()
        deactivateAudioSession()
    }
    
    private func handleSystemSpeechFinished() {
        systemIsSpeaking = false
        systemSpeechContinuation?.resume()
        systemSpeechContinuation = nil
    }
    
    private func selectSystemVoice() -> AVSpeechSynthesisVoice? {
        if let identifier = voiceSettings.settings.voiceIdentifier,
           let voice = AVSpeechSynthesisVoice(identifier: identifier) {
            return voice
        }
        return SpeechSynthesizer.findBestVoice()
    }
    
    private func configureAudioSession() {
        do {
            let audioSession = AVAudioSession.sharedInstance()
            try audioSession.setCategory(
                .playback,
                mode: .voicePrompt,
                options: [.duckOthers, .interruptSpokenAudioAndMixWithOthers]
            )
            try audioSession.setActive(true)
        } catch {
            print("[UnifiedTTSManager] Audio session error: \(error)")
        }
    }
    
    private func deactivateAudioSession() {
        do {
            try AVAudioSession.sharedInstance().setActive(
                false,
                options: .notifyOthersOnDeactivation
            )
        } catch {
            print("[UnifiedTTSManager] Audio session deactivation error: \(error)")
        }
    }
    
    // MARK: - Errors
    
    enum UnifiedTTSError: LocalizedError {
        case kokoroNotDownloaded
        case speakFailed(String)
        
        var errorDescription: String? {
            switch self {
            case .kokoroNotDownloaded:
                return "Kokoro TTS model is not downloaded"
            case .speakFailed(let reason):
                return "Speech failed: \(reason)"
            }
        }
    }
}

// MARK: - System TTS Delegate Handler

/// Non-isolated delegate handler for AVSpeechSynthesizer callbacks
private class SystemTTSDelegateHandler: NSObject, AVSpeechSynthesizerDelegate {
    private let onFinished: @MainActor () -> Void
    
    init(onFinished: @escaping @MainActor () -> Void) {
        self.onFinished = onFinished
        super.init()
    }
    
    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
        Task { @MainActor in
            onFinished()
        }
    }
    
    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didCancel utterance: AVSpeechUtterance) {
        Task { @MainActor in
            onFinished()
        }
    }
}

// MARK: - TTSProvider Conformance for System TTS

/// Wrapper to make AVSpeechSynthesizer conform to TTSProvider
@MainActor
class SystemTTSProvider: TTSProvider {
    private let synthesizer = AVSpeechSynthesizer()
    private let voiceSettings = VoiceSettingsManager.shared
    private var delegate: SystemTTSProviderDelegate?
    private var continuation: CheckedContinuation<Void, Never>?
    
    var providerName: String { "System TTS" }
    
    var isSpeaking: Bool {
        synthesizer.isSpeaking
    }
    
    var isReady: Bool { true }
    
    init() {
        delegate = SystemTTSProviderDelegate { [weak self] in
            self?.continuation?.resume()
            self?.continuation = nil
        }
        synthesizer.delegate = delegate
    }
    
    func speak(_ text: String) async throws {
        let utterance = AVSpeechUtterance(string: text)
        
        if let identifier = voiceSettings.settings.voiceIdentifier,
           let voice = AVSpeechSynthesisVoice(identifier: identifier) {
            utterance.voice = voice
        } else {
            utterance.voice = SpeechSynthesizer.findBestVoice()
        }
        
        let rate = voiceSettings.settings.speechRate
        utterance.rate = AVSpeechUtteranceDefaultSpeechRate * rate * 0.92
        
        await withCheckedContinuation { cont in
            continuation = cont
            synthesizer.speak(utterance)
        }
    }
    
    func stop() async {
        synthesizer.stopSpeaking(at: .immediate)
        continuation?.resume()
        continuation = nil
    }
}

/// Delegate for SystemTTSProvider
private class SystemTTSProviderDelegate: NSObject, AVSpeechSynthesizerDelegate {
    private let onFinished: @MainActor () -> Void
    
    init(onFinished: @escaping @MainActor () -> Void) {
        self.onFinished = onFinished
        super.init()
    }
    
    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
        Task { @MainActor in onFinished() }
    }
    
    func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didCancel utterance: AVSpeechUtterance) {
        Task { @MainActor in onFinished() }
    }
}

// MARK: - TTSProvider Conformance for Kokoro

/// Wrapper to make KokoroTTSManager conform to TTSProvider
@MainActor
class KokoroTTSProvider: TTSProvider {
    private let manager = KokoroTTSManager.shared
    private let voiceSettings = VoiceSettingsManager.shared
    
    var providerName: String { "Kokoro TTS" }
    
    var isSpeaking: Bool {
        get async {
            let state = await manager.state
            if case .generating = state { return true }
            return false
        }
    }
    
    var isReady: Bool {
        get async {
            await manager.modelDownloaded
        }
    }
    
    func speak(_ text: String) async throws {
        let speed = voiceSettings.settings.speechRate
        try await manager.speakText(text, speed: speed)
    }
    
    func stop() async {
        await manager.stopPlayback()
    }
}
