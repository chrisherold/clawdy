import Foundation
import Speech
import AVFoundation

enum SpeechRecognizerError: LocalizedError {
    case notAuthorized
    case notAvailable
    case audioSessionError(Error)
    case recognitionError(Error)

    var errorDescription: String? {
        switch self {
        case .notAuthorized:
            return "Speech recognition not authorized. Please enable in Settings."
        case .notAvailable:
            return "Speech recognition not available on this device."
        case .audioSessionError(let error):
            return "Audio session error: \(error.localizedDescription)"
        case .recognitionError(let error):
            return "Recognition error: \(error.localizedDescription)"
        }
    }
}

@MainActor
class SpeechRecognizer: ObservableObject {
    @Published var transcribedText = ""
    @Published var isAuthorized = false

    private let speechRecognizer: SFSpeechRecognizer?
    private var recognitionRequest: SFSpeechAudioBufferRecognitionRequest?
    private var recognitionTask: SFSpeechRecognitionTask?
    private let audioEngine = AVAudioEngine()

    // Silence detection for continuous mode
    private var silenceTimer: Timer?
    private var lastTranscriptionTime: Date?
    var onSilenceDetected: (() -> Void)?
    var onRecognitionStopped: (() -> Void)? // called when recognition ends unexpectedly (error or isFinal)
    private var isDeliberatelyStopping = false // suppress onRecognitionStopped during deliberate stops
    var silenceThreshold: TimeInterval = 1.5 // seconds of silence before auto-send

    // 1-minute timeout handling (Apple's limit per recognition task)
    private var recognitionStartTime: Date?
    private var timeoutTimer: Timer?
    private let maxRecognitionDuration: TimeInterval = 55 // restart before 60s limit
    var onTimeoutRestart: (() -> Void)? // callback to restart recognition

    init() {
        speechRecognizer = SFSpeechRecognizer(locale: Locale(identifier: "en-US"))
        checkAuthorization()
    }

    private func checkAuthorization() {
        SFSpeechRecognizer.requestAuthorization { [weak self] status in
            DispatchQueue.main.async {
                self?.isAuthorized = (status == .authorized)
            }
        }
    }

    func startRecording() async throws {
        isDeliberatelyStopping = false

        guard let speechRecognizer = speechRecognizer, speechRecognizer.isAvailable else {
            throw SpeechRecognizerError.notAvailable
        }

        guard isAuthorized else {
            throw SpeechRecognizerError.notAuthorized
        }

        // Cancel any ongoing task
        recognitionTask?.cancel()
        recognitionTask = nil

        // Configure audio session
        let audioSession = AVAudioSession.sharedInstance()
        do {
            try audioSession.setCategory(.record, mode: .measurement, options: .duckOthers)
            try audioSession.setActive(true, options: .notifyOthersOnDeactivation)
        } catch {
            throw SpeechRecognizerError.audioSessionError(error)
        }

        // Create recognition request
        recognitionRequest = SFSpeechAudioBufferRecognitionRequest()
        guard let recognitionRequest = recognitionRequest else {
            throw SpeechRecognizerError.notAvailable
        }

        recognitionRequest.shouldReportPartialResults = true

        // Configure on-device recognition if available (for privacy)
        if #available(iOS 13, *) {
            recognitionRequest.requiresOnDeviceRecognition = false
        }

        // Start recognition task
        recognitionTask = speechRecognizer.recognitionTask(with: recognitionRequest) { [weak self] result, error in
            guard let self = self else { return }

            if let result = result {
                DispatchQueue.main.async {
                    let newText = result.bestTranscription.formattedString
                    if newText != self.transcribedText {
                        self.transcribedText = newText
                        self.lastTranscriptionTime = Date()
                        self.resetSilenceTimer()
                    }
                }
            }

            if error != nil || result?.isFinal == true {
                self.audioEngine.stop()
                self.audioEngine.inputNode.removeTap(onBus: 0)
                DispatchQueue.main.async {
                    guard !self.isDeliberatelyStopping else { return }
                    self.onRecognitionStopped?()
                }
            }
        }

        // Configure audio input
        let inputNode = audioEngine.inputNode
        inputNode.removeTap(onBus: 0) // Remove any existing tap to avoid duplicate tap crash
        let recordingFormat = inputNode.outputFormat(forBus: 0)

        inputNode.installTap(onBus: 0, bufferSize: 1024, format: recordingFormat) { buffer, _ in
            self.recognitionRequest?.append(buffer)
        }

        audioEngine.prepare()
        try audioEngine.start()

        transcribedText = ""

        // Start 1-minute timeout timer
        recognitionStartTime = Date()
        startTimeoutTimer()
    }

    // MARK: - Timeout Handling

    private func startTimeoutTimer() {
        timeoutTimer?.invalidate()
        timeoutTimer = Timer.scheduledTimer(withTimeInterval: maxRecognitionDuration, repeats: false) { [weak self] _ in
            DispatchQueue.main.async {
                self?.handleTimeout()
            }
        }
    }

    private func stopTimeoutTimer() {
        timeoutTimer?.invalidate()
        timeoutTimer = nil
    }

    private func handleTimeout() {
        // Recognition task is approaching 60s limit - need to restart
        // Save current transcription
        let currentText = transcribedText

        // Stop current recognition (deliberate - don't trigger onRecognitionStopped)
        isDeliberatelyStopping = true
        audioEngine.stop()
        audioEngine.inputNode.removeTap(onBus: 0)
        recognitionRequest?.endAudio()
        recognitionTask?.cancel()
        recognitionRequest = nil
        recognitionTask = nil

        // If we have text, trigger silence detection to send it
        if !currentText.isEmpty {
            onSilenceDetected?()
        } else {
            // No text, just restart
            onTimeoutRestart?()
        }
    }

    func stopRecording() -> String {
        isDeliberatelyStopping = true
        stopSilenceTimer()
        stopTimeoutTimer()
        audioEngine.stop()
        audioEngine.inputNode.removeTap(onBus: 0)
        audioEngine.reset()
        recognitionRequest?.endAudio()
        recognitionTask?.cancel()

        recognitionRequest = nil
        recognitionTask = nil
        recognitionStartTime = nil

        // Deactivate audio session
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)

        return transcribedText
    }

    // MARK: - Silence Detection

    private func resetSilenceTimer() {
        silenceTimer?.invalidate()
        silenceTimer = Timer.scheduledTimer(withTimeInterval: silenceThreshold, repeats: false) { [weak self] _ in
            DispatchQueue.main.async {
                self?.handleSilenceDetected()
            }
        }
    }

    private func stopSilenceTimer() {
        silenceTimer?.invalidate()
        silenceTimer = nil
    }

    private func handleSilenceDetected() {
        // Only trigger if we have some transcribed text
        guard !transcribedText.isEmpty else { return }
        onSilenceDetected?()
    }

    /// Start silence detection manually (for continuous mode)
    func startSilenceDetection() {
        lastTranscriptionTime = Date()
        resetSilenceTimer()
    }
}
