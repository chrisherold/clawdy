import Foundation
import AVFoundation

/// ElevenLabs TTS Manager for high-quality cloud-based text-to-speech
actor ElevenLabsTTSManager {
    static let shared = ElevenLabsTTSManager()

    private let keychainKey = "com.clawdy.elevenLabsApiKey"
    private var audioPlayer: AVAudioPlayer?
    private var audioEngine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?

    // Popular ElevenLabs voices
    static let popularVoices: [(id: String, name: String, description: String)] = [
        ("EXAVITQu4vr4xnSDxMaL", "Sarah", "Warm, friendly female voice"),
        ("21m00Tcm4TlvDq8ikWAM", "Rachel", "Clear, professional female voice"),
        ("AZnzlk1XvdvUeBnXmlld", "Domi", "Strong, confident female voice"),
        ("IKne3meq5aSn9XLyUdCD", "Charlie", "Natural, casual male voice"),
        ("TX3LPaxmHKxFdv7VOQHJ", "Liam", "Young, energetic male voice"),
        ("pNInz6obpgDQGcFmaJgB", "Adam", "Deep, authoritative male voice"),
        ("ThT5KcBeYPX3keUQqHPh", "Dorothy", "Warm, soothing female voice"),
        ("VR6AewLTigWG4xSOukaG", "Arnold", "Strong, confident male voice"),
    ]

    // MARK: - API Key Management

    func saveApiKey(_ key: String) {
        let data = key.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey,
            kSecValueData as String: data
        ]

        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)

        // Update voice settings flag
        Task { @MainActor in
            VoiceSettingsManager.shared.settings.elevenLabsConfigured = true
        }
    }

    func getApiKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let key = String(data: data, encoding: .utf8) else {
            return nil
        }

        return key
    }

    func deleteApiKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainKey
        ]
        SecItemDelete(query as CFDictionary)

        Task { @MainActor in
            VoiceSettingsManager.shared.settings.elevenLabsConfigured = false
        }
    }

    var isConfigured: Bool {
        getApiKey() != nil
    }

    // MARK: - Text-to-Speech

    /// Generate audio from text using ElevenLabs API
    func generateAudio(text: String, voiceId: String, speed: Float = 1.0) async throws -> Data {
        guard let apiKey = getApiKey() else {
            throw ElevenLabsError.notConfigured
        }

        let url = URL(string: "https://api.elevenlabs.io/v1/text-to-speech/\(voiceId)")!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "xi-api-key")
        request.timeoutInterval = 30

        let body: [String: Any] = [
            "text": text,
            "model_id": "eleven_turbo_v2_5",
            "voice_settings": [
                "stability": 0.5,
                "similarity_boost": 0.75,
                "style": 0.0,
                "use_speaker_boost": true
            ]
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw ElevenLabsError.invalidResponse
        }

        guard httpResponse.statusCode == 200 else {
            if let errorJson = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let detail = errorJson["detail"] as? [String: Any],
               let message = detail["message"] as? String {
                throw ElevenLabsError.apiError(message)
            }
            throw ElevenLabsError.apiError("HTTP \(httpResponse.statusCode)")
        }

        return data
    }

    /// Speak text using ElevenLabs
    func speak(text: String, voiceId: String, speed: Float = 1.0) async throws {
        let audioData = try await generateAudio(text: text, voiceId: voiceId, speed: speed)
        try await playAudioData(audioData)
    }

    /// Play audio data
    private func playAudioData(_ data: Data) async throws {
        print("[ElevenLabs] Playing audio data: \(data.count) bytes")

        return try await withCheckedThrowingContinuation { continuation in
            do {
                // Configure audio session for playback
                let audioSession = AVAudioSession.sharedInstance()
                try audioSession.setCategory(.playback, mode: .voicePrompt,
                    options: [.duckOthers, .interruptSpokenAudioAndMixWithOthers])
                try audioSession.setActive(true)

                // Create audio player
                let player = try AVAudioPlayer(data: data)
                self.audioPlayer = player

                print("[ElevenLabs] Audio duration: \(player.duration) seconds")

                // Set up completion handler using a delegate wrapper
                let delegate = AudioPlayerDelegate {
                    print("[ElevenLabs] Playback finished via delegate")
                    continuation.resume()
                }
                player.delegate = delegate

                // Keep delegate alive
                objc_setAssociatedObject(player, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)

                player.play()
                print("[ElevenLabs] Started playback")
            } catch {
                print("[ElevenLabs] Playback error: \(error)")
                continuation.resume(throwing: error)
            }
        }
    }

    /// Stop current playback
    func stop() {
        audioPlayer?.stop()
        audioPlayer = nil
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }
}

// MARK: - Errors

enum ElevenLabsError: LocalizedError {
    case notConfigured
    case invalidResponse
    case apiError(String)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "ElevenLabs API key not configured"
        case .invalidResponse:
            return "Invalid response from ElevenLabs API"
        case .apiError(let message):
            return "ElevenLabs API error: \(message)"
        }
    }
}

// MARK: - Audio Player Delegate

private class AudioPlayerDelegate: NSObject, AVAudioPlayerDelegate {
    let onFinish: () -> Void

    init(onFinish: @escaping () -> Void) {
        self.onFinish = onFinish
    }

    func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        onFinish()
    }

    func audioPlayerDecodeErrorDidOccur(_ player: AVAudioPlayer, error: Error?) {
        onFinish()
    }
}
