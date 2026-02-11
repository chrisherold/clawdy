import SwiftUI
import AVFoundation
import Combine
import OSLog

private let settingsLogger = Logger(subsystem: "com.clawdy", category: "settings")

/// Settings screen for configuring gateway connection and voice preferences.
/// Stores credentials securely in iOS Keychain.
struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel = SettingsViewModel()
    @StateObject private var voiceSettings = VoiceSettingsManager.shared
    @StateObject private var kokoroTTS = KokoroTTSObservable()
    
    /// Keep synthesizer alive for test voice playback
    @State private var testSynthesizer: AVSpeechSynthesizer?

    /// Optional callback to clear session context
    var onClearContext: (() -> Void)?

    var body: some View {
        NavigationView {
            Form {
                // Gateway configuration
                Section {
                    TextField("Hostname or IP", text: $viewModel.gatewayHost)
                        .textContentType(.URL)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()

                    SecureField("Auth Token", text: $viewModel.gatewayAuthToken)
                        .textContentType(.password)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()

                    Toggle("Use TLS", isOn: $viewModel.gatewayTLS)

                    TextField("Session Key", text: $viewModel.sessionKey)
                        .textContentType(.none)
                        .autocapitalization(.none)
                        .autocorrectionDisabled()
                } header: {
                    Text("Gateway")
                } footer: {
                    Text("Session key separates conversations. Use a unique key (e.g., 'iphone') to keep this device's chat separate from other clients.")
                }
                
                // TTS Engine Selection
                Section {
                    // Engine picker
                    Picker("TTS Engine", selection: $voiceSettings.settings.ttsEngine) {
                        ForEach(TTSEngine.allCases, id: \.self) { engine in
                            Text(engine.displayName).tag(engine)
                        }
                    }
                    .pickerStyle(.segmented)
                    
                    // Kokoro model status (only show when Kokoro is selected or downloading)
                    if voiceSettings.settings.ttsEngine == .kokoro || kokoroTTS.isDownloading {
                        KokoroModelStatusView(kokoroTTS: kokoroTTS)
                    }
                } header: {
                    Text("TTS Engine")
                } footer: {
                    Text(voiceSettings.settings.ttsEngine.description)
                }
                
                // Voice settings
                Section {
                    // Speech rate slider
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Speech Rate")
                            Spacer()
                            Text(speechRateLabel(voiceSettings.settings.speechRate))
                                .foregroundColor(.secondary)
                        }
                        HStack {
                            Image(systemName: "tortoise")
                                .foregroundColor(.secondary)
                            Slider(
                                value: $voiceSettings.settings.speechRate,
                                in: VoiceSettings.minRate...VoiceSettings.maxRate,
                                step: 0.1
                            )
                            Image(systemName: "hare")
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.vertical, 4)

                    // Voice selection - show different picker based on engine
                    switch voiceSettings.settings.ttsEngine {
                    case .system:
                        NavigationLink {
                            VoiceSelectionView(voiceSettings: voiceSettings)
                        } label: {
                            HStack {
                                Text("Voice")
                                Spacer()
                                Text(voiceSettings.settings.voiceDisplayName ?? "Auto")
                                    .foregroundColor(.secondary)
                            }
                        }
                    case .kokoro:
                        NavigationLink {
                            KokoroVoiceSelectionView(voiceSettings: voiceSettings, kokoroTTS: kokoroTTS)
                        } label: {
                            HStack {
                                Text("Voice")
                                Spacer()
                                Text(voiceSettings.settings.kokoroVoiceDisplayName ?? "Heart")
                                    .foregroundColor(.secondary)
                            }
                        }
                        .disabled(kokoroTTS.state != .ready)
                    case .elevenLabs:
                        NavigationLink {
                            ElevenLabsSettingsView(voiceSettings: voiceSettings)
                        } label: {
                            HStack {
                                Text("ElevenLabs Settings")
                                Spacer()
                                Text(voiceSettings.settings.elevenLabsVoiceDisplayName ?? "Sarah")
                                    .foregroundColor(.secondary)
                            }
                        }
                    }

                    // Test voice button
                    Button {
                        testVoice()
                    } label: {
                        HStack {
                            Image(systemName: "speaker.wave.2")
                            Text("Test Voice")
                        }
                    }
                    .disabled(voiceSettings.settings.ttsEngine == .kokoro && kokoroTTS.state != .ready)
                } header: {
                    Text("Voice")
                } footer: {
                    Text("Adjust how Claude speaks responses back to you")
                }

                // Session context
                if onClearContext != nil {
                    Section {
                        Button(role: .destructive) {
                            viewModel.showingClearContextConfirmation = true
                        } label: {
                            Text("Clear Session Context")
                        }
                    } header: {
                        Text("Session")
                    } footer: {
                        Text("Clears conversation history. Claude will start fresh without memory of previous messages.")
                    }
                }

                // Clear credentials
                Section {
                    Button(role: .destructive) {
                        viewModel.showingClearConfirmation = true
                    } label: {
                        Text("Clear All Credentials")
                    }
                }
                
                // Connection & Pairing Status
                Section {
                    // Operator role status
                    HStack {
                        RolePairingStatusIcon(status: viewModel.operatorPairingStatus)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Operator (Chat)")
                                .fontWeight(.medium)
                            Text(viewModel.operatorPairingStatus.displayText)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        if viewModel.operatorPairingStatus.isPaired && viewModel.operatorPairingStatus != .connected {
                            Button(role: .destructive) {
                                viewModel.clearTokenForRole("operator")
                            } label: {
                                Image(systemName: "trash")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    
                    // Node role status
                    HStack {
                        RolePairingStatusIcon(status: viewModel.nodePairingStatus)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Node (Camera/Location)")
                                .fontWeight(.medium)
                            Text(viewModel.nodePairingStatus.displayText)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        if viewModel.nodePairingStatus.isPaired && viewModel.nodePairingStatus != .connected {
                            Button(role: .destructive) {
                                viewModel.clearTokenForRole("node")
                            } label: {
                                Image(systemName: "trash")
                                    .font(.caption)
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    
                    // Test connection button
                    Button {
                        Task {
                            await viewModel.testGatewayConnection()
                        }
                    } label: {
                        HStack {
                            if viewModel.isTestingGateway {
                                ProgressView()
                                    .padding(.trailing, 8)
                            }
                            Text(viewModel.isTestingGateway ? "Testing..." : "Test Connection")
                        }
                    }
                    .disabled(!viewModel.canTestGateway || viewModel.isTestingGateway)
                    
                    if let result = viewModel.gatewayTestResult {
                        HStack {
                            Image(systemName: result.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundColor(result.success ? .green : .red)
                            Text(result.message)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    
                    // Action buttons
                    if viewModel.isPairingPending {
                        Button(role: .destructive) {
                            viewModel.cancelPairing()
                        } label: {
                            Text("Cancel Pairing")
                        }
                    } else if !viewModel.isDevicePaired {
                        Button {
                            Task {
                                await viewModel.startPairing()
                            }
                        } label: {
                            Text("Start Pairing")
                        }
                        .disabled(!viewModel.canStartPairing)
                    }
                } header: {
                    Text("Connection")
                } footer: {
                    if viewModel.isPairingPending {
                        Text("Waiting for approval on gateway. Run 'clawdbot devices list' then 'clawdbot devices approve <id>' on the server. Both roles need separate approval.")
                    } else if viewModel.isFullyConnected {
                        Text("Both roles connected. Chat and device capabilities are active.")
                    } else if viewModel.isDevicePaired {
                        Text("Both roles paired. Connect to activate.")
                    } else {
                        Text("Device needs pairing for both operator (chat) and node (camera/location) roles.")
                    }
                }
                
                // Debug section
                Section {
                    Toggle("Verbose Gateway Logging", isOn: $viewModel.verboseLogging)
                    
                    Button(role: .destructive) {
                        viewModel.showingClearKeychainConfirmation = true
                    } label: {
                        HStack {
                            Image(systemName: "key.slash")
                            Text("Clear Device Identity & Tokens")
                        }
                    }
                    
                    if viewModel.keychainCleared {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("Keychain cleared. Restart app to generate new identity.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                } header: {
                    Text("Debug")
                } footer: {
                    Text("Verbose logging prints all gateway messages to console. Clear identity to test fresh pairing flow (requires app restart).")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Save") {
                        viewModel.save()
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(!viewModel.canSave)
                }
            }
            .alert("Clear Credentials", isPresented: $viewModel.showingClearConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Clear", role: .destructive) {
                    viewModel.clearCredentials()
                }
            } message: {
                Text("This will remove all server credentials from your device. You'll need to reconfigure them to use the app.")
            }
            .alert("Clear Session Context", isPresented: $viewModel.showingClearContextConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Clear", role: .destructive) {
                    onClearContext?()
                }
            } message: {
                Text("This will clear the conversation history. Claude will not remember previous messages from this session.")
            }
            .alert("Clear Device Identity", isPresented: $viewModel.showingClearKeychainConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Clear", role: .destructive) {
                    viewModel.clearKeychainForFreshInstall()
                }
            } message: {
                Text("This will delete your device identity and all device tokens. You'll need to re-pair with the gateway after restarting the app.")
            }
        }
    }

    // MARK: - Voice Settings Helpers

    /// Convert speech rate to user-friendly label
    private func speechRateLabel(_ rate: Float) -> String {
        switch rate {
        case 0.5: return "0.5x (Slow)"
        case 1.0: return "1.0x (Normal)"
        case 1.5: return "1.5x (Fast)"
        case 2.0: return "2.0x (Very Fast)"
        default: return String(format: "%.1fx", rate)
        }
    }

    /// Play a test phrase with current voice settings
    private func testVoice() {
        switch voiceSettings.settings.ttsEngine {
        case .kokoro:
            testKokoroVoice()
        case .elevenLabs:
            testElevenLabsVoice()
        case .system:
            testSystemVoice()
        }
    }

    /// Test the ElevenLabs TTS voice
    private func testElevenLabsVoice() {
        Task {
            do {
                let voiceId = voiceSettings.settings.elevenLabsVoiceId ?? "EXAVITQu4vr4xnSDxMaL"
                try await ElevenLabsTTSManager.shared.speak(
                    text: "Hello, I'm ready to help you with your tasks.",
                    voiceId: voiceId
                )
            } catch {
                settingsLogger.error("TestVoice ElevenLabs error: \(error.localizedDescription)")
            }
        }
    }
    
    /// Test the system TTS voice
    private func testSystemVoice() {
        // Stop any existing speech
        testSynthesizer?.stopSpeaking(at: .immediate)
        
        // Create and retain the synthesizer
        let synthesizer = AVSpeechSynthesizer()
        testSynthesizer = synthesizer
        
        let utterance = AVSpeechUtterance(string: "Hello, I'm ready to help you with your tasks.")

        // Apply current settings
        if let identifier = voiceSettings.settings.voiceIdentifier,
           let voice = AVSpeechSynthesisVoice(identifier: identifier) {
            utterance.voice = voice
            settingsLogger.debug("TestVoice using voice: \(voice.name, privacy: .public), quality: \(voice.quality.rawValue, privacy: .public)")
        } else if let voice = SpeechSynthesizer.findBestVoice() {
            utterance.voice = voice
            settingsLogger.debug("TestVoice using auto-selected voice: \(voice.name, privacy: .public), quality: \(voice.quality.rawValue, privacy: .public)")
        } else {
            utterance.voice = AVSpeechSynthesisVoice(language: "en-US")
            settingsLogger.debug("TestVoice using fallback en-US voice")
        }

        // Match the settings used in IncrementalTTSManager
        utterance.rate = AVSpeechUtteranceDefaultSpeechRate * voiceSettings.settings.speechRate * 0.92
        utterance.pitchMultiplier = 0.95
        
        // Configure audio session
        do {
            let audioSession = AVAudioSession.sharedInstance()
            try audioSession.setCategory(.playback, mode: .voicePrompt)
            try audioSession.setActive(true)
        } catch {
            settingsLogger.error("TestVoice audio session error: \(error.localizedDescription)")
        }

        synthesizer.speak(utterance)
    }
    
    /// Test the Kokoro TTS voice
    private func testKokoroVoice() {
        Task {
            do {
                try await kokoroTTS.speak(
                    text: "Hello, I'm ready to help you with your tasks.",
                    speed: voiceSettings.settings.speechRate
                )
            } catch {
                settingsLogger.error("TestVoice Kokoro error: \(error.localizedDescription)")
            }
        }
    }
}

// MARK: - Role Pairing Status Icon

/// Icon indicating pairing status for a specific role
struct RolePairingStatusIcon: View {
    let status: SettingsViewModel.RolePairingStatus
    
    var body: some View {
        switch status {
        case .unknown:
            Image(systemName: "questionmark.circle")
                .foregroundColor(.secondary)
        case .notPaired:
            Image(systemName: "xmark.circle")
                .foregroundColor(.secondary)
        case .pairingPending:
            ProgressView()
                .scaleEffect(0.8)
        case .paired:
            Image(systemName: "checkmark.circle")
                .foregroundColor(.orange)
        case .connected:
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
        }
    }
}

// MARK: - Voice Selection View

/// View for selecting a TTS voice from available options
struct VoiceSelectionView: View {
    @ObservedObject var voiceSettings: VoiceSettingsManager
    @Environment(\.dismiss) private var dismiss

    private var availableVoices: [VoiceOption] {
        voiceSettings.availableVoices()
    }

    var body: some View {
        List {
            // Auto option (system default)
            Section {
                Button {
                    voiceSettings.settings.voiceIdentifier = nil
                    voiceSettings.settings.voiceDisplayName = nil
                } label: {
                    HStack {
                        Text("Auto (Best Available)")
                        Spacer()
                        if voiceSettings.settings.voiceIdentifier == nil {
                            Image(systemName: "checkmark")
                                .foregroundColor(.accentColor)
                        }
                    }
                }
                .foregroundColor(.primary)
            } footer: {
                Text("Automatically selects the highest quality voice available on your device")
            }

            // Enhanced/Premium voices
            let premiumVoices = availableVoices.filter { $0.quality == .enhanced || $0.quality == .premium }
            if !premiumVoices.isEmpty {
                Section {
                    ForEach(premiumVoices) { voice in
                        VoiceRow(
                            voice: voice,
                            isSelected: voiceSettings.settings.voiceIdentifier == voice.id,
                            onSelect: {
                                selectVoice(voice)
                            }
                        )
                    }
                } header: {
                    Text("Enhanced Voices")
                }
            }

            // Standard voices
            let standardVoices = availableVoices.filter { $0.quality != .enhanced && $0.quality != .premium }
            if !standardVoices.isEmpty {
                Section {
                    ForEach(standardVoices) { voice in
                        VoiceRow(
                            voice: voice,
                            isSelected: voiceSettings.settings.voiceIdentifier == voice.id,
                            onSelect: {
                                selectVoice(voice)
                            }
                        )
                    }
                } header: {
                    Text("Standard Voices")
                }
            }
        }
        .navigationTitle("Select Voice")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func selectVoice(_ voice: VoiceOption) {
        voiceSettings.settings.voiceIdentifier = voice.id
        voiceSettings.settings.voiceDisplayName = voice.name
        settingsLogger.info("Selected voice: \(voice.name, privacy: .public), id: \(voice.id, privacy: .public), quality: \(voice.quality.rawValue, privacy: .public)")
    }
}

// MARK: - Voice Row

/// Individual row for a voice option with preview functionality
struct VoiceRow: View {
    let voice: VoiceOption
    let isSelected: Bool
    let onSelect: () -> Void

    @State private var isSpeaking = false

    var body: some View {
        HStack {
            Button {
                onSelect()
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(voice.name)
                            .foregroundColor(.primary)
                        Text(voice.language)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    if isSelected {
                        Image(systemName: "checkmark")
                            .foregroundColor(.accentColor)
                    }
                }
            }

            // Preview button
            Button {
                previewVoice()
            } label: {
                Image(systemName: isSpeaking ? "speaker.wave.3.fill" : "speaker.wave.2")
                    .foregroundColor(.accentColor)
                    .frame(width: 44, height: 44)
            }
            .buttonStyle(.borderless)
        }
    }

    private func previewVoice() {
        guard !isSpeaking else { return }

        isSpeaking = true
        let synthesizer = AVSpeechSynthesizer()
        let utterance = AVSpeechUtterance(string: "Hello, this is \(voice.name).")

        if let voiceObj = AVSpeechSynthesisVoice(identifier: voice.id) {
            utterance.voice = voiceObj
        }

        synthesizer.speak(utterance)

        // Reset speaking state after estimated duration
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            isSpeaking = false
        }
    }
}

// MARK: - Kokoro Model Status View

/// Shows the current status of the Kokoro TTS model with download/delete controls
struct KokoroModelStatusView: View {
    @ObservedObject var kokoroTTS: KokoroTTSObservable
    @State private var showingDeleteConfirmation = false
    @State private var modelSize: String = ""
    @State private var hasEnoughSpace: Bool = true
    @State private var availableSpace: String = ""
    @State private var neededSpace: String = ""
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            switch kokoroTTS.state {
            case .notDownloaded:
                // Check disk space and show appropriate UI
                if hasEnoughSpace {
                    // Show download button
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Model not downloaded")
                                .font(.subheadline)
                            Text("~150 MB required")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("Download") {
                            kokoroTTS.startDownload()
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                } else {
                    // Show low disk space warning
                    LowDiskSpaceWarningView(
                        availableSpace: availableSpace,
                        neededSpace: neededSpace,
                        onRefresh: { await checkDiskSpace() }
                    )
                }
                
            case .downloading(let progress):
                // Show download progress
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text("Downloading...")
                            .font(.subheadline)
                        Spacer()
                        Text("\(Int(progress * 100))%")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    ProgressView(value: progress)
                        .progressViewStyle(.linear)
                    
                    HStack {
                        Spacer()
                        Button("Cancel") {
                            Task {
                                await kokoroTTS.cancelDownload()
                            }
                        }
                        .font(.caption)
                        .foregroundColor(.red)
                    }
                }
                
            case .ready:
                // Show downloaded status with delete option
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Model downloaded")
                            .font(.subheadline)
                        Text(modelSize)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button(role: .destructive) {
                        showingDeleteConfirmation = true
                    } label: {
                        Image(systemName: "trash")
                    }
                    .buttonStyle(.borderless)
                }
                .task {
                    modelSize = await kokoroTTS.formattedTotalStorage
                }
                
            case .generating:
                // Show generating status
                HStack {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Generating audio...")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                
            case .error(let message):
                // Check if this is a disk space error
                if message.contains("disk space") || message.contains("Not enough") {
                    LowDiskSpaceWarningView(
                        availableSpace: availableSpace,
                        neededSpace: neededSpace,
                        onRefresh: { await checkDiskSpace() }
                    )
                } else {
                    // Show generic error with retry option
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                            Text("Error")
                                .font(.subheadline)
                        }
                        Text(message)
                            .font(.caption)
                            .foregroundColor(.secondary)
                        
                        Button("Retry Download") {
                            kokoroTTS.startDownload()
                        }
                        .font(.caption)
                    }
                }
            }
        }
        .padding(.vertical, 4)
        .task {
            await checkDiskSpace()
        }
        .alert("Delete Model", isPresented: $showingDeleteConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                Task {
                    try? await kokoroTTS.deleteModel()
                }
            }
        } message: {
            Text("This will delete the Kokoro TTS model and free up ~150 MB of storage. You can re-download it later.")
        }
    }
    
    /// Check if there's enough disk space for the download
    private func checkDiskSpace() async {
        hasEnoughSpace = await kokoroTTS.hasEnoughDiskSpace
        availableSpace = await kokoroTTS.formattedAvailableSpace
        neededSpace = await kokoroTTS.formattedAdditionalSpaceNeeded
    }
}

// MARK: - Low Disk Space Warning View

/// Displays a warning when there isn't enough disk space to download the model
struct LowDiskSpaceWarningView: View {
    let availableSpace: String
    let neededSpace: String
    let onRefresh: () async -> Void
    
    @State private var isRefreshing = false
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "externaldrive.badge.exclamationmark")
                    .foregroundColor(.orange)
                    .font(.title3)
                
                VStack(alignment: .leading, spacing: 2) {
                    Text("Not Enough Storage")
                        .font(.subheadline)
                        .fontWeight(.medium)
                    Text("Free up \(neededSpace) to download")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            // Storage details
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("Available:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text(availableSpace)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                HStack {
                    Text("Required:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Text("~250 MB")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(Color(.tertiarySystemBackground))
            .cornerRadius(6)
            
            // Tips for freeing space
            Text("Tip: Delete unused apps, photos, or clear Safari cache to free up space.")
                .font(.caption2)
                .foregroundColor(.secondary)
                .padding(.top, 2)
            
            // Refresh button
            HStack {
                Spacer()
                Button {
                    Task {
                        isRefreshing = true
                        await onRefresh()
                        isRefreshing = false
                    }
                } label: {
                    HStack(spacing: 4) {
                        if isRefreshing {
                            ProgressView()
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "arrow.clockwise")
                        }
                        Text("Check Again")
                    }
                    .font(.caption)
                }
                .disabled(isRefreshing)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Kokoro Voice Selection View

/// View for selecting a Kokoro TTS voice
struct KokoroVoiceSelectionView: View {
    @ObservedObject var voiceSettings: VoiceSettingsManager
    @ObservedObject var kokoroTTS: KokoroTTSObservable
    @Environment(\.dismiss) private var dismiss
    @State private var voices: [KokoroTTSManager.KokoroVoice] = []
    
    var body: some View {
        List {
            Section {
                ForEach(voices) { voice in
                    KokoroVoiceRow(
                        voice: voice,
                        isSelected: voiceSettings.settings.kokoroVoiceId == voice.id,
                        kokoroTTS: kokoroTTS,
                        speechRate: voiceSettings.settings.speechRate,
                        onSelect: {
                            selectVoice(voice)
                        }
                    )
                }
            } header: {
                Text("Kokoro Neural Voices")
            } footer: {
                Text("High-quality neural voices powered by Kokoro TTS")
            }
        }
        .navigationTitle("Select Voice")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            voices = await kokoroTTS.availableVoices
        }
    }
    
    private func selectVoice(_ voice: KokoroTTSManager.KokoroVoice) {
        voiceSettings.settings.kokoroVoiceId = voice.id
        voiceSettings.settings.kokoroVoiceDisplayName = voice.displayName
        
        Task {
            await kokoroTTS.setVoice(voice)
        }
        
        settingsLogger.info("Selected Kokoro voice: \(voice.name, privacy: .public), id: \(voice.id, privacy: .public)")
    }
}

// MARK: - Kokoro Voice Row

/// Individual row for a Kokoro voice option with preview functionality
struct KokoroVoiceRow: View {
    let voice: KokoroTTSManager.KokoroVoice
    let isSelected: Bool
    let kokoroTTS: KokoroTTSObservable
    let speechRate: Float
    let onSelect: () -> Void
    
    @State private var isPreviewing = false
    
    var body: some View {
        HStack {
            Button {
                onSelect()
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(voice.name)
                            .foregroundColor(.primary)
                        Text(voice.style)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    if isSelected {
                        Image(systemName: "checkmark")
                            .foregroundColor(.accentColor)
                    }
                }
            }
            
            // Preview button
            Button {
                previewVoice()
            } label: {
                if isPreviewing {
                    ProgressView()
                        .scaleEffect(0.8)
                        .frame(width: 44, height: 44)
                } else {
                    Image(systemName: "speaker.wave.2")
                        .foregroundColor(.accentColor)
                        .frame(width: 44, height: 44)
                }
            }
            .buttonStyle(.borderless)
            .disabled(isPreviewing)
        }
    }
    
    private func previewVoice() {
        guard !isPreviewing else { return }

        isPreviewing = true

        Task {
            do {
                try await kokoroTTS.previewVoice(voice, speed: speechRate)
            } catch {
                settingsLogger.error("Kokoro voice preview error: \(error.localizedDescription)")
            }
            isPreviewing = false
        }
    }
}

// MARK: - ElevenLabs Settings View

/// Settings view for ElevenLabs TTS configuration
struct ElevenLabsSettingsView: View {
    @ObservedObject var voiceSettings: VoiceSettingsManager
    @State private var apiKey: String = ""
    @State private var isConfigured: Bool = false
    @State private var isTesting: Bool = false
    @State private var testResult: String?

    var body: some View {
        Form {
            Section {
                SecureField("API Key", text: $apiKey)
                    .textContentType(.password)
                    .autocapitalization(.none)

                if isConfigured {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("API Key configured")
                            .foregroundColor(.secondary)
                    }
                }

                Button(apiKey.isEmpty ? "Save API Key" : "Update API Key") {
                    saveApiKey()
                }
                .disabled(apiKey.isEmpty)

                if isConfigured {
                    Button("Remove API Key", role: .destructive) {
                        removeApiKey()
                    }
                }
            } header: {
                Text("API Key")
            } footer: {
                Text("Get your API key from elevenlabs.io")
            }

            Section {
                ForEach(ElevenLabsTTSManager.popularVoices, id: \.id) { voice in
                    Button {
                        selectVoice(id: voice.id, name: voice.name)
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(voice.name)
                                    .foregroundColor(.primary)
                                Text(voice.description)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            Spacer()
                            if voiceSettings.settings.elevenLabsVoiceId == voice.id {
                                Image(systemName: "checkmark")
                                    .foregroundColor(.accentColor)
                            }
                        }
                    }
                }
            } header: {
                Text("Voice")
            }

            Section {
                Button {
                    testVoice()
                } label: {
                    HStack {
                        if isTesting {
                            ProgressView()
                                .scaleEffect(0.8)
                        } else {
                            Image(systemName: "speaker.wave.2")
                        }
                        Text("Test Voice")
                    }
                }
                .disabled(!isConfigured || isTesting)

                if let result = testResult {
                    Text(result)
                        .font(.caption)
                        .foregroundColor(result.contains("Error") ? .red : .green)
                }
            } header: {
                Text("Test")
            }
        }
        .navigationTitle("ElevenLabs")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await checkConfiguration()
        }
    }

    private func checkConfiguration() async {
        isConfigured = await ElevenLabsTTSManager.shared.isConfigured
    }

    private func saveApiKey() {
        Task {
            await ElevenLabsTTSManager.shared.saveApiKey(apiKey)
            isConfigured = true
            apiKey = "" // Clear for security
            testResult = "API Key saved"
        }
    }

    private func removeApiKey() {
        Task {
            await ElevenLabsTTSManager.shared.deleteApiKey()
            isConfigured = false
            testResult = nil
        }
    }

    private func selectVoice(id: String, name: String) {
        voiceSettings.settings.elevenLabsVoiceId = id
        voiceSettings.settings.elevenLabsVoiceDisplayName = name
    }

    private func testVoice() {
        guard isConfigured else { return }

        isTesting = true
        testResult = nil

        Task {
            do {
                let voiceId = voiceSettings.settings.elevenLabsVoiceId ?? "EXAVITQu4vr4xnSDxMaL"
                try await ElevenLabsTTSManager.shared.speak(
                    text: "Hello! This is a test of the ElevenLabs voice.",
                    voiceId: voiceId
                )
                testResult = "Voice test successful"
            } catch {
                testResult = "Error: \(error.localizedDescription)"
            }
            isTesting = false
        }
    }
}

// MARK: - Settings View Model

@MainActor
class SettingsViewModel: ObservableObject {
    // Gateway Settings
    @Published var gatewayHost: String = ""
    @Published var gatewayAuthToken: String = ""
    @Published var gatewayTLS: Bool = false
    @Published var sessionKey: String = "main"

    @Published var showingClearConfirmation = false
    @Published var showingClearContextConfirmation = false
    @Published var showingClearKeychainConfirmation = false
    @Published var keychainCleared = false
    
    // Debug Settings
    private static let verboseLoggingKey = "com.clawdy.debug.verboseLogging"
    @Published var verboseLogging: Bool = UserDefaults.standard.bool(forKey: SettingsViewModel.verboseLoggingKey) {
        didSet {
            UserDefaults.standard.set(verboseLogging, forKey: Self.verboseLoggingKey)
            GatewayConnection.verboseLogging = verboseLogging
        }
    }
    
    // Dual-role pairing state
    @Published var operatorPairingStatus: RolePairingStatus = .unknown
    @Published var nodePairingStatus: RolePairingStatus = .unknown
    private var connectionStatusObserver: AnyCancellable?
    
    /// Per-role pairing status
    enum RolePairingStatus: Equatable {
        case unknown
        case notPaired
        case pairingPending
        case paired
        case connected
        
        var displayText: String {
            switch self {
            case .unknown: return "Unknown"
            case .notPaired: return "Not Paired"
            case .pairingPending: return "Pairing Pending..."
            case .paired: return "Paired"
            case .connected: return "Connected"
            }
        }
        
        var isPaired: Bool {
            self == .paired || self == .connected
        }
        
        var isPending: Bool {
            self == .pairingPending
        }
    }
    
    // Computed properties for backward compatibility
    var isPairingPending: Bool {
        operatorPairingStatus.isPending || nodePairingStatus.isPending
    }
    
    var isDevicePaired: Bool {
        operatorPairingStatus.isPaired && nodePairingStatus.isPaired
    }
    
    var isFullyConnected: Bool {
        operatorPairingStatus == .connected && nodePairingStatus == .connected
    }
    
    // Gateway test state
    @Published var isTestingGateway = false
    @Published var gatewayTestResult: TestResult?

    struct TestResult {
        let success: Bool
        let message: String
    }

    private let keychain = KeychainManager.shared

    init() {
        loadCredentials()
        setupConnectionStatusObserver()
        checkPairingStatus()
    }
    
    private func setupConnectionStatusObserver() {
        connectionStatusObserver = GatewayDualConnectionManager.shared.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in
                self?.updatePairingStatusFromConnection(status)
            }
    }
    
    /// Update pairing status based on dual connection manager status
    private func updatePairingStatusFromConnection(_ status: DualConnectionStatus) {
        switch status {
        case .connected:
            operatorPairingStatus = .connected
            nodePairingStatus = .connected
        case .partialOperator:
            operatorPairingStatus = .connected
            // Node is not connected - check if it has a token (paired but disconnected)
            nodePairingStatus = checkStoredTokenStatus(role: "node")
        case .partialNode:
            nodePairingStatus = .connected
            // Operator is not connected - check if it has a token
            operatorPairingStatus = checkStoredTokenStatus(role: "operator")
        case .pairingPendingOperator:
            operatorPairingStatus = .pairingPending
            nodePairingStatus = checkStoredTokenStatus(role: "node")
        case .pairingPendingNode:
            operatorPairingStatus = checkStoredTokenStatus(role: "operator")
            nodePairingStatus = .pairingPending
        case .pairingPendingBoth:
            operatorPairingStatus = .pairingPending
            nodePairingStatus = .pairingPending
        case .connecting:
            // Don't change status during connecting
            break
        case .disconnected:
            // Check stored tokens to determine if paired but disconnected
            operatorPairingStatus = checkStoredTokenStatus(role: "operator")
            nodePairingStatus = checkStoredTokenStatus(role: "node")
        }
    }
    
    /// Check if we have a stored token for a role (indicates previous successful pairing)
    private func checkStoredTokenStatus(role: String) -> RolePairingStatus {
        let identity = DeviceIdentityStore.loadOrCreate()
        if DeviceAuthStore.loadToken(deviceId: identity.deviceId, role: role) != nil {
            return .paired
        }
        return .notPaired
    }
    
    private func checkPairingStatus() {
        // Check stored tokens for each role
        operatorPairingStatus = checkStoredTokenStatus(role: "operator")
        nodePairingStatus = checkStoredTokenStatus(role: "node")
        
        // Also check current connection status
        updatePairingStatusFromConnection(GatewayDualConnectionManager.shared.status)
    }

    var canSave: Bool {
        !gatewayHost.isEmpty
    }

    var canTestGateway: Bool {
        !gatewayHost.isEmpty
    }
    
    var canStartPairing: Bool {
        !gatewayHost.isEmpty && !isPairingPending
    }
    
    /// Start the pairing process by connecting to the gateway
    func startPairing() async {
        // Save current settings first
        save()
        
        // Trigger a connection attempt which will start pairing if needed
        await GatewayDualConnectionManager.shared.connectIfNeeded()
        
        // Update pairing status
        await MainActor.run {
            checkPairingStatus()
        }
    }
    
    /// Cancel the ongoing pairing process
    func cancelPairing() {
        Task {
            await GatewayDualConnectionManager.shared.disconnect()
        }
        operatorPairingStatus = checkStoredTokenStatus(role: "operator")
        nodePairingStatus = checkStoredTokenStatus(role: "node")
    }
    
    /// Clear stored token for a specific role to force re-pairing
    func clearTokenForRole(_ role: String) {
        let identity = DeviceIdentityStore.loadOrCreate()
        DeviceAuthStore.clearToken(deviceId: identity.deviceId, role: role)
        settingsLogger.info("Cleared token for role: \(role, privacy: .public)")
        checkPairingStatus()
    }

    /// Load existing credentials from Keychain
    private func loadCredentials() {
        // Load Gateway credentials
        if let gatewayCredentials = keychain.loadGatewayCredentials() {
            gatewayHost = gatewayCredentials.host
            gatewayAuthToken = gatewayCredentials.authToken ?? ""
            gatewayTLS = gatewayCredentials.useTLS
            // Extract display name from session key (e.g., "agent:main:iphone" -> "iphone")
            let parts = gatewayCredentials.sessionKey.split(separator: ":")
            if parts.count == 3 {
                sessionKey = String(parts[2])
            } else {
                sessionKey = gatewayCredentials.sessionKey
            }
        }
    }

    /// Save credentials to Keychain
    func save() {
        // Normalize session key before saving
        let normalizedSessionKey = KeychainManager.normalizeSessionKey(sessionKey)

        // Save Gateway credentials
        let gatewayCredentials = KeychainManager.GatewayCredentials(
            host: gatewayHost,
            port: KeychainManager.GatewayCredentials.defaultPort,
            authToken: gatewayAuthToken.isEmpty ? nil : gatewayAuthToken,
            useTLS: gatewayTLS,
            sessionKey: normalizedSessionKey
        )

        do {
            try keychain.saveGatewayCredentials(gatewayCredentials)
            settingsLogger.info("Gateway credentials saved successfully (session: \(normalizedSessionKey, privacy: .public))")
        } catch {
            settingsLogger.error("Failed to save Gateway credentials: \(error.localizedDescription)")
        }
    }

    /// Test the Gateway connection with current credentials
    func testGatewayConnection() async {
        isTestingGateway = true
        gatewayTestResult = nil

        // Save credentials first
        save()

        // Build credentials for test
        let normalizedSessionKey = KeychainManager.normalizeSessionKey(sessionKey)
        let credentials = KeychainManager.GatewayCredentials(
            host: gatewayHost,
            port: KeychainManager.GatewayCredentials.defaultPort,
            authToken: gatewayAuthToken.isEmpty ? nil : gatewayAuthToken,
            useTLS: gatewayTLS,
            sessionKey: normalizedSessionKey
        )
        
        do {
            let serverName = try await GatewayDualConnectionManager.shared.testConnection(credentials: credentials)
            gatewayTestResult = TestResult(success: true, message: "Connected to \(serverName)")
        } catch {
            gatewayTestResult = TestResult(success: false, message: error.localizedDescription)
        }

        isTestingGateway = false
    }

    /// Clear all stored credentials
    func clearCredentials() {
        // Clear Gateway credentials
        keychain.deleteGatewayCredentials()
        gatewayHost = ""
        gatewayAuthToken = ""
        gatewayTLS = false
        sessionKey = "main"
        gatewayTestResult = nil
    }
    
    /// Clear device identity and tokens for fresh pairing test
    func clearKeychainForFreshInstall() {
        // Get current device ID before clearing identity
        let identity = DeviceIdentityStore.loadOrCreate()
        let deviceId = identity.deviceId
        
        // Clear device tokens for this device
        DeviceAuthStore.clearAllTokens(deviceId: deviceId)
        settingsLogger.info("Cleared device tokens for deviceId: \(deviceId.prefix(8), privacy: .public)...")
        
        // Clear device identity (forces new keypair generation on next app launch)
        DeviceIdentityStore.clear()
        settingsLogger.info("Cleared device identity")
        
        keychainCleared = true
    }
}

#Preview {
    SettingsView()
}
