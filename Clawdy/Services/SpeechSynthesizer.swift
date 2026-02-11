import Foundation
import AVFoundation
import OSLog

/// Speech synthesizer for text-to-speech output using AVSpeechSynthesizer.
/// Provides Siri-like voice output for Claude's responses.
/// Uses VoiceSettingsManager for configurable speech rate and voice selection.
@MainActor
class SpeechSynthesizer: NSObject, ObservableObject {
    private static let logger = Logger(subsystem: "com.clawdy", category: "speech-synth")
    @Published var isSpeaking = false

    private let synthesizer = AVSpeechSynthesizer()
    private var completionHandler: (() -> Void)?
    private let voiceSettings = VoiceSettingsManager.shared

    override init() {
        super.init()
        synthesizer.delegate = self
    }

    /// Speak the given text using text-to-speech.
    /// - Parameters:
    ///   - text: The text to speak
    ///   - summarize: If true, extracts and speaks only the first sentence or key points (for long responses)
    func speak(_ text: String, summarize: Bool = false) {
        // Stop any ongoing speech
        if synthesizer.isSpeaking {
            synthesizer.stopSpeaking(at: .immediate)
        }

        let textToSpeak: String
        if summarize && text.count > 200 {
            textToSpeak = extractSummary(from: text)
        } else {
            textToSpeak = text
        }

        guard !textToSpeak.isEmpty else { return }

        // Configure audio session for playback
        configureAudioSession()

        let utterance = AVSpeechUtterance(string: textToSpeak)

        // Use configured voice or auto-select best available
        if let voice = selectVoice() {
            utterance.voice = voice
        }

        // Apply configured speech rate
        // For premium/enhanced voices, a slightly slower rate sounds more natural
        let rateMultiplier = voiceSettings.settings.speechRate
        utterance.rate = AVSpeechUtteranceDefaultSpeechRate * rateMultiplier * 0.92
        
        // Pitch slightly lower for a warmer, more natural sound
        utterance.pitchMultiplier = 0.95
        utterance.volume = 1.0

        // Small pause before speaking for natural feel
        utterance.preUtteranceDelay = 0.15
        utterance.postUtteranceDelay = 0.05

        isSpeaking = true
        BackgroundAudioManager.shared.audioStarted()
        synthesizer.speak(utterance)
    }

    /// Stop any ongoing speech
    func stop() {
        if synthesizer.isSpeaking {
            synthesizer.stopSpeaking(at: .immediate)
        }
        isSpeaking = false
        BackgroundAudioManager.shared.audioEnded()
    }

    /// Wait for speech to complete
    func speakAndWait(_ text: String, summarize: Bool = false) async {
        await withCheckedContinuation { continuation in
            completionHandler = {
                continuation.resume()
            }
            speak(text, summarize: summarize)
        }
    }

    // MARK: - Private Helpers

    /// Select the voice based on user settings or auto-select the best available
    private func selectVoice() -> AVSpeechSynthesisVoice? {
        // If user has selected a specific voice, use it
        if let identifier = voiceSettings.settings.voiceIdentifier,
           let voice = AVSpeechSynthesisVoice(identifier: identifier) {
            return voice
        }

        // Auto-select: Get the best available voice
        return Self.findBestVoice()
    }
    
    /// Find the best available voice, preferring premium/enhanced Siri-like voices
    /// The quality hierarchy is: Premium > Enhanced > Default
    /// Premium voices sound the most natural and Siri-like
    static func findBestVoice() -> AVSpeechSynthesisVoice? {
        let voices = AVSpeechSynthesisVoice.speechVoices()
        let englishVoices = voices.filter { $0.language.starts(with: "en-US") || $0.language.starts(with: "en-GB") }
        
        // Priority 1: Premium quality voices (best quality, most natural)
        // These are the newest Siri-quality voices
        if let premiumVoice = englishVoices.first(where: { $0.quality == .premium }) {
            Self.logger.debug("Using premium voice: \(premiumVoice.name, privacy: .public) (\(premiumVoice.identifier, privacy: .public))")
            return premiumVoice
        }
        
        // Priority 2: Enhanced quality voices (good quality)
        // Prefer specific enhanced voices known to sound good
        let preferredEnhanced = [
            "com.apple.voice.enhanced.en-US.Zoe",      // Very natural female
            "com.apple.voice.enhanced.en-US.Evan",     // Very natural male
            "com.apple.voice.enhanced.en-US.Samantha", // Classic Siri voice
            "com.apple.voice.enhanced.en-GB.Daniel",   // British male
            "com.apple.voice.enhanced.en-AU.Karen",    // Australian female
        ]
        
        for identifier in preferredEnhanced {
            if let voice = AVSpeechSynthesisVoice(identifier: identifier) {
                Self.logger.debug("Using preferred enhanced voice: \(voice.name, privacy: .public)")
                return voice
            }
        }
        
        // Any enhanced voice
        if let enhancedVoice = englishVoices.first(where: { $0.quality == .enhanced }) {
            Self.logger.debug("Using enhanced voice: \(enhancedVoice.name, privacy: .public)")
            return enhancedVoice
        }
        
        // Priority 3: Default quality (robotic, last resort)
        Self.logger.warning("No premium/enhanced voices available. Using default voice. Tip: Download better voices in Settings > Accessibility > Spoken Content > Voices")
        return AVSpeechSynthesisVoice(language: "en-US")
    }
    
    /// List all available voices for debugging
    static func listAvailableVoices() {
        let voices = AVSpeechSynthesisVoice.speechVoices()
        let englishVoices = voices.filter { $0.language.starts(with: "en") }
        
        Self.logger.info("Available English voices:")
        for voice in englishVoices.sorted(by: { $0.quality.rawValue > $1.quality.rawValue }) {
            let qualityStr: String
            switch voice.quality {
            case .premium: qualityStr = "⭐ Premium"
            case .enhanced: qualityStr = "✓ Enhanced"
            default: qualityStr = "○ Default"
            }
            Self.logger.info("  \(qualityStr, privacy: .public) - \(voice.name, privacy: .public) [\(voice.language, privacy: .public)] id: \(voice.identifier, privacy: .public)")
        }
    }

    /// Configure audio session for speech playback including background audio support
    private func configureAudioSession() {
        do {
            let audioSession = AVAudioSession.sharedInstance()
            // Use .playback category to enable background audio continuation
            // .duckOthers lowers other audio while speaking
            // .interruptSpokenAudioAndMixWithOthers allows mixing with other apps while interrupting spoken content
            try audioSession.setCategory(
                .playback,
                mode: .voicePrompt,
                options: [.duckOthers, .interruptSpokenAudioAndMixWithOthers]
            )
            try audioSession.setActive(true)
        } catch {
            Self.logger.error("Audio session error: \(error.localizedDescription)")
        }
    }

    /// Deactivate audio session when speech is complete
    private func deactivateAudioSession() {
        do {
            try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        } catch {
            Self.logger.warning("Audio session deactivation error: \(error.localizedDescription)")
        }
    }

    /// Extract a summary from long text - returns first sentence or first 150 characters
    private func extractSummary(from text: String) -> String {
        // Try to get the first sentence
        let sentences = text.components(separatedBy: CharacterSet(charactersIn: ".!?"))
        if let firstSentence = sentences.first, !firstSentence.isEmpty {
            let trimmed = firstSentence.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.count > 10 {
                return trimmed + "."
            }
        }

        // Fall back to first 150 characters
        let maxLength = 150
        if text.count <= maxLength {
            return text
        }

        let index = text.index(text.startIndex, offsetBy: maxLength)
        let truncated = String(text[..<index])

        // Try to break at a word boundary
        if let lastSpace = truncated.lastIndex(of: " ") {
            return String(truncated[..<lastSpace]) + "..."
        }

        return truncated + "..."
    }
}

// MARK: - AVSpeechSynthesizerDelegate

extension SpeechSynthesizer: AVSpeechSynthesizerDelegate {
    nonisolated func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didFinish utterance: AVSpeechUtterance) {
        Task { @MainActor in
            isSpeaking = false
            BackgroundAudioManager.shared.audioEnded()
            completionHandler?()
            completionHandler = nil

            // Deactivate audio session when done speaking
            deactivateAudioSession()
        }
    }

    nonisolated func speechSynthesizer(_ synthesizer: AVSpeechSynthesizer, didCancel utterance: AVSpeechUtterance) {
        Task { @MainActor in
            isSpeaking = false
            BackgroundAudioManager.shared.audioEnded()
            completionHandler?()
            completionHandler = nil

            // Deactivate audio session when speech is cancelled
            deactivateAudioSession()
        }
    }
}
