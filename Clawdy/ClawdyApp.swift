import SwiftUI
import UIKit

@main
struct ClawdyApp: App {
    @StateObject private var authManager = AuthenticationManager.shared
    @StateObject private var backgroundAudioManager = BackgroundAudioManager.shared
    @Environment(\.scenePhase) private var scenePhase
    
    /// Observer for memory warnings
    private let memoryWarningObserver = MemoryWarningObserver()

    init() {
        // Log available voices on startup for debugging
        #if DEBUG
        SpeechSynthesizer.listAvailableVoices()
        #endif

        // Warm up Kokoro TTS in the background if it's the preferred engine
        // This eliminates the delay on the first TTS request
        warmUpKokoroIfNeeded()
    }

    var body: some Scene {
        WindowGroup {
            Group {
                if authManager.isAuthenticated {
                    ContentView()
                } else {
                    LockScreenView(authManager: authManager)
                }
            }
            .onChange(of: scenePhase) { _, newPhase in
                handleScenePhaseChange(newPhase)
            }
        }
    }

    /// Handle app lifecycle changes for security and connection management
    private func handleScenePhaseChange(_ phase: ScenePhase) {
        // Notify gateway dual connection manager of lifecycle changes
        let gatewayPhase: AppLifecyclePhase
        switch phase {
        case .active:
            gatewayPhase = .active
        case .inactive:
            gatewayPhase = .inactive
        case .background:
            gatewayPhase = .background
        @unknown default:
            gatewayPhase = .inactive
        }
        GatewayDualConnectionManager.shared.handleLifecycleChange(gatewayPhase)
        
        switch phase {
        case .background:
            // Re-enable idle timer when backgrounded (screen lock doesn't matter in background)
            UIApplication.shared.isIdleTimerDisabled = false

            // Handle Kokoro backgrounding first - stop GPU work to prevent crashes
            // GPU work from background is NOT allowed before iOS 26
            Task {
                await KokoroTTSManager.shared.handleBackgrounding()
            }
            
            // Only lock app when entering background if audio is not playing
            // This allows TTS to continue in background until complete
            if backgroundAudioManager.shouldLockOnBackground {
                authManager.lock()
                
                // Unload Kokoro engine when going to background (if not playing audio)
                // This frees significant memory (~300MB+) while app is backgrounded
                Task {
                    await KokoroTTSManager.shared.unloadEngine()
                }
            }
        case .inactive:
            // Could optionally lock here too for stricter security
            break
        case .active:
            // Warm up Kokoro when app becomes active (in case settings changed)
            warmUpKokoroIfNeeded()
        @unknown default:
            break
        }
    }
    
    /// Warm up Kokoro TTS in the background if conditions are met:
    /// 1. Kokoro is the preferred TTS engine
    /// 2. The model is downloaded
    /// 3. The model hasn't already been warmed up
    private func warmUpKokoroIfNeeded() {
        let voiceSettings = VoiceSettingsManager.shared
        
        // Only warm up if Kokoro is the preferred engine
        guard voiceSettings.settings.ttsEngine == .kokoro else {
            return
        }
        
        // Warm up in a background task to not block app launch
        Task.detached(priority: .utility) {
            let manager = KokoroTTSManager.shared
            
            // Check if model is downloaded and not already warmed up
            let isDownloaded = await manager.modelDownloaded
            let isWarmedUp = await manager.isWarmedUp
            
            guard isDownloaded && !isWarmedUp else {
                return
            }
            
            // Warm up WITH inference to fully prime the neural network.
            // With optimized MLX memory limits (50MB cache, 900MB limit), this is
            // now safe to run on launch. The first TTS request will be much faster
            // since all lazy MLX operations are already initialized.
            let success = await manager.warmUp(runInference: true)
            
            if success {
                print("[ClawdyApp] Kokoro TTS warmed up (model loaded, inference deferred)")
            }
        }
    }
}

// MARK: - Memory Warning Observer

/// Observes system memory warnings and app termination to free resources:
/// - Clears image attachments (temp files and in-memory cache)
/// - Notifies Kokoro TTS to free model resources
/// - Cleans up temp directory on app termination
final class MemoryWarningObserver {
    /// Track consecutive memory warnings to escalate response
    private var warningCount = 0
    private var lastWarningTime: Date?
    
    init() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleMemoryWarning),
            name: UIApplication.didReceiveMemoryWarningNotification,
            object: nil
        )
        
        // Note: We intentionally do NOT observe willTerminateNotification.
        // iOS automatically cleans up the temp directory, and observing this
        // notification was causing issues when presenting system UI (photo picker)
        // due to SwiftUI App struct lifecycle quirks.
    }
    
    deinit {
        NotificationCenter.default.removeObserver(self)
    }
    
    @objc private func handleMemoryWarning() {
        let now = Date()
        
        // Track consecutive warnings (within 30 seconds = related pressure event)
        if let lastTime = lastWarningTime, now.timeIntervalSince(lastTime) < 30 {
            warningCount += 1
        } else {
            warningCount = 1
        }
        lastWarningTime = now
        
        print("[MemoryWarningObserver] Received memory warning #\(warningCount) from system")
        
        // Handle memory warning in KokoroTTSManager
        // On repeated warnings, force unload even if generating (rare edge case)
        let forceUnload = warningCount >= 2
        
        Task { @MainActor in
            // Clear all image attachments on memory pressure.
            // This frees temp files on disk and in-memory attachment references.
            // Images are session-only, so users can re-attach if needed.
            let imageCount = ImageAttachmentStore.shared.count
            if imageCount > 0 {
                print("[MemoryWarningObserver] Clearing \(imageCount) image attachments due to memory pressure")
                ImageAttachmentStore.shared.clearAll()
            }
        }
        
        Task {
            if forceUnload {
                // Critical memory pressure - force unload regardless of state
                print("[MemoryWarningObserver] Critical memory pressure - force unloading Kokoro")
                await KokoroTTSManager.shared.unloadEngine()
            } else {
                await KokoroTTSManager.shared.handleMemoryWarning(unloadIfIdle: true)
            }
        }
    }
}
