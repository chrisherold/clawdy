import Foundation
import AVFoundation
import OSLog

private let voiceLogger = Logger(subsystem: "com.clawdy", category: "voice-settings")

/// TTS engine selection
enum TTSEngine: String, Codable, CaseIterable {
    case system = "system"
    case kokoro = "kokoro"
    case elevenLabs = "elevenlabs"

    var displayName: String {
        switch self {
        case .system: return "System (Built-in)"
        case .kokoro: return "Kokoro (Neural)"
        case .elevenLabs: return "ElevenLabs (Cloud)"
        }
    }

    var description: String {
        switch self {
        case .system: return "Uses Apple's built-in voices"
        case .kokoro: return "High-quality neural TTS (~150MB download)"
        case .elevenLabs: return "Premium cloud voices (requires API key)"
        }
    }
}

/// Voice settings for text-to-speech configuration.
/// Stored in UserDefaults since these are not sensitive data.
struct VoiceSettings: Codable, Equatable {
    /// Selected TTS engine (system or Kokoro)
    var ttsEngine: TTSEngine
    
    /// Speech rate multiplier (0.5 = half speed, 1.0 = normal, 2.0 = double speed)
    var speechRate: Float

    /// The identifier of the selected voice (nil = auto-select best voice)
    /// Used for system TTS voices
    var voiceIdentifier: String?

    /// Display name of the selected voice (for UI)
    /// Used for system TTS voices
    var voiceDisplayName: String?
    
    /// Selected Kokoro voice identifier
    var kokoroVoiceId: String?

    /// Display name of the selected Kokoro voice
    var kokoroVoiceDisplayName: String?

    /// ElevenLabs API key (stored in Keychain separately for security)
    /// This is just a flag to indicate if API key is configured
    var elevenLabsConfigured: Bool

    /// ElevenLabs voice ID
    var elevenLabsVoiceId: String?

    /// ElevenLabs voice display name
    var elevenLabsVoiceDisplayName: String?

    /// Default settings
    static let `default` = VoiceSettings(
        ttsEngine: .system,
        speechRate: 1.0,
        voiceIdentifier: nil,
        voiceDisplayName: nil,
        kokoroVoiceId: "af_heart",
        kokoroVoiceDisplayName: "Heart (Warm female)",
        elevenLabsConfigured: false,
        elevenLabsVoiceId: "EXAVITQu4vr4xnSDxMaL", // Sarah - default voice
        elevenLabsVoiceDisplayName: "Sarah"
    )

    /// Minimum speech rate (half speed)
    static let minRate: Float = 0.5

    /// Maximum speech rate (double speed)
    static let maxRate: Float = 2.0
}

/// Available voice option for the picker
struct VoiceOption: Identifiable, Hashable {
    let id: String // voice identifier
    let name: String
    let language: String
    let quality: AVSpeechSynthesisVoiceQuality

    var qualityLabel: String {
        switch quality {
        case .enhanced:
            return "Enhanced"
        case .premium:
            return "Premium"
        default:
            return "Default"
        }
    }

    var displayName: String {
        if quality == .enhanced || quality == .premium {
            return "\(name) (\(qualityLabel))"
        }
        return name
    }
}

/// Manager for loading and saving voice settings
class VoiceSettingsManager: ObservableObject {
    static let shared = VoiceSettingsManager()

    private let userDefaultsKey = "com.clawdy.voiceSettings"

    @Published var settings: VoiceSettings {
        didSet {
            save()
        }
    }

    private init() {
        self.settings = VoiceSettingsManager.load()
    }

    /// Load settings from UserDefaults
    private static func load() -> VoiceSettings {
        guard let data = UserDefaults.standard.data(forKey: "com.clawdy.voiceSettings"),
              let settings = try? JSONDecoder().decode(VoiceSettings.self, from: data) else {
            return .default
        }
        return settings
    }

    /// Save settings to UserDefaults
    private func save() {
        if let data = try? JSONEncoder().encode(settings) {
            UserDefaults.standard.set(data, forKey: userDefaultsKey)
        }
    }

    /// Get all available English voices sorted by quality
    func availableVoices() -> [VoiceOption] {
        let voices = AVSpeechSynthesisVoice.speechVoices()
        
        // Log all voices for debugging
        voiceLogger.info("All available voices:")
        for voice in voices.filter({ $0.language.starts(with: "en") }).sorted(by: { $0.identifier < $1.identifier }) {
            let qualityStr: String
            switch voice.quality {
            case .premium: qualityStr = "Premium"
            case .enhanced: qualityStr = "Enhanced"
            default: qualityStr = "Default"
            }
            voiceLogger.info("  [\(qualityStr, privacy: .public)] \(voice.name, privacy: .public) - \(voice.identifier, privacy: .public)")
        }

        return voices
            .filter { $0.language.starts(with: "en") }
            .map { voice in
                VoiceOption(
                    id: voice.identifier,
                    name: voice.name,
                    language: voice.language,
                    quality: voice.quality
                )
            }
            .sorted { v1, v2 in
                // Sort by quality (premium/enhanced first), then by name
                if v1.quality != v2.quality {
                    return v1.quality.rawValue > v2.quality.rawValue
                }
                return v1.name < v2.name
            }
    }

    /// Reset to default settings
    func reset() {
        settings = .default
    }
}
