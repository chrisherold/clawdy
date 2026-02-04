import Foundation
import AVFoundation
import CryptoKit
import KokoroSwift
import MLX
import MLXUtilsLibrary

/// Manages on-device neural TTS using the Kokoro model.
/// Provides high-quality, natural-sounding speech synthesis without network connectivity.
///
/// Usage:
/// ```swift
/// let manager = KokoroTTSManager.shared
/// try await manager.downloadModelIfNeeded()
/// let audio = try await manager.generateAudio(text: "Hello world")
/// ```
actor KokoroTTSManager {
    
    // MARK: - Singleton
    
    static let shared = KokoroTTSManager()
    
    // MARK: - State
    
    enum State: Equatable {
        case notDownloaded
        case downloading(progress: Double)
        case ready
        case generating
        case error(message: String)
        
        static func == (lhs: State, rhs: State) -> Bool {
            switch (lhs, rhs) {
            case (.notDownloaded, .notDownloaded): return true
            case (.downloading(let p1), .downloading(let p2)): return p1 == p2
            case (.ready, .ready): return true
            case (.generating, .generating): return true
            case (.error(let m1), .error(let m2)): return m1 == m2
            default: return false
            }
        }
    }
    
    private(set) var state: State = .notDownloaded
    
    // MARK: - Model Configuration
    
    /// Model variant to use
    /// Note: KokoroSwift does NOT support quantized models (4-bit, 6-bit, 8-bit).
    /// Only bf16 (bfloat16) format works with the standard weight loading.
    enum ModelVariant: String, CaseIterable {
        case bf16 = "kokoro-v1_0-bf16"
        
        var displayName: String {
            switch self {
            case .bf16: return "Standard (~312 MB)"
            }
        }
        
        var fileExtension: String { "safetensors" }
        
        var expectedSize: Int64 {
            switch self {
            case .bf16: return 327_115_152
            }
        }
        
        /// SHA256 checksum of the model file for integrity verification.
        /// Retrieved from HuggingFace LFS metadata.
        var expectedChecksum: String? {
            switch self {
            case .bf16:
                // SHA256 of mlx-community/Kokoro-82M-bf16 kokoro-v1_0.safetensors
                return "4e9ecdf03b8b6cf906070390237feda473dc13327cb8d56a43deaa374c02acd8"
            }
        }
        
        /// Download URL for this model variant
        var downloadURL: URL {
            switch self {
            case .bf16:
                return URL(string: "https://huggingface.co/mlx-community/Kokoro-82M-bf16/resolve/main/kokoro-v1_0.safetensors")!
            }
        }
    }
    
    /// Current model variant (bf16 is the only supported format)
    let modelVariant: ModelVariant = .bf16
    
    // MARK: - Storage Paths
    
    /// Directory for storing Kokoro TTS files
    private var kokoroDirectory: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport.appendingPathComponent("KokoroTTS", isDirectory: true)
    }
    
    /// Path to the model file
    private var modelPath: URL {
        kokoroDirectory.appendingPathComponent("\(modelVariant.rawValue).\(modelVariant.fileExtension)")
    }
    
    // MARK: - Bundled Voices
    
    /// Voice files are bundled with the app in the Resources/Voices folder.
    /// Each voice is a .safetensors file containing the voice embedding.
    /// Voices are loaded from the app bundle at runtime - no download needed.
    
    /// List of bundled voice file names (without extension)
    private static let bundledVoiceIds = [
        "af_heart", "af_nova", "af_bella", "af_sarah",
        "am_adam", "am_michael",
        "bf_emma", "bm_george"
    ]
    
    // MARK: - Download URLs
    
    /// URL for model download (uses the model variant's URL)
    private var modelDownloadURL: URL {
        modelVariant.downloadURL
    }
    
    // MARK: - TTS Engine
    
    /// The Kokoro TTS engine instance (loaded lazily when model is ready)
    private var ttsEngine: KokoroTTS?
    
    /// Loaded voice embeddings
    private var voices: [String: MLXArray] = [:]
    
    /// Currently selected voice identifier
    private var selectedVoiceId: String = "af_heart"
    
    // MARK: - Audio Engine
    
    private var audioEngine: AVAudioEngine?
    private var playerNode: AVAudioPlayerNode?
    
    // MARK: - Warm-up State
    
    /// Whether the model has been warmed up (engine loaded and ready)
    private(set) var isWarmedUp: Bool = false
    
    /// Whether a warm-up operation is in progress
    private(set) var isWarmingUp: Bool = false
    
    // MARK: - Idle Unload State
    
    /// Task for automatic engine unloading after idle timeout
    private var idleUnloadTask: Task<Void, Never>?
    
    /// Time in seconds before unloading engine due to inactivity (2 minutes)
    private static let idleUnloadTimeout: TimeInterval = 120
    
    // MARK: - Initialization
    
    private init() {
        // Configure MLX memory limits for iOS
        // Set a conservative cache limit to prevent memory accumulation
        // 64MB cache is enough for buffer reuse while preventing runaway growth
        configureMLXMemoryLimits()
        
        // Check if model is already downloaded
        Task {
            await checkModelStatus()
        }
    }
    
    /// Configure MLX memory limits appropriate for iOS devices.
    /// This prevents the MLX buffer cache from growing unbounded.
    /// Note: nonisolated because it only sets static MLX properties.
    ///
    /// Based on community findings (mlalma/kokoro-ios issues #5, #7):
    /// - Lower cache limit (50MB) prevents runaway buffer pool growth
    /// - Lower memory limit (900MB) keeps iOS memory management happy
    /// - Higher values (e.g., 1.5GB) cause crashes on iPhone 12/13/15
    nonisolated private func configureMLXMemoryLimits() {
        // Set cache limit to 50MB - community-tested value that prevents
        // multi-GB cache growth while allowing efficient buffer reuse
        let cacheLimitMB = 50
        MLX.Memory.cacheLimit = cacheLimitMB * 1024 * 1024
        
        // Set overall memory limit to 900MB - tested stable on iPhone 13/15
        // Higher values (1.5GB+) cause memory pressure and crashes
        let memoryLimitMB = 900
        MLX.Memory.memoryLimit = memoryLimitMB * 1024 * 1024
        
        print("[KokoroTTSManager] Configured MLX memory: cache=\(cacheLimitMB)MB, limit=\(memoryLimitMB)MB")
    }
    
    // MARK: - Public Interface: Model Handling
    
    /// Check if the model file exists on disk
    var modelDownloaded: Bool {
        FileManager.default.fileExists(atPath: modelPath.path)
    }
    
    /// Get the size of the model file on disk
    var modelSizeOnDisk: Int64 {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: modelPath.path),
              let size = attrs[.size] as? Int64 else {
            return 0
        }
        return size
    }
    
    /// Check model status and update state
    private func checkModelStatus() {
        if modelDownloaded {
            state = .ready
        } else {
            state = .notDownloaded
        }
    }
    
    /// Download the model file if needed. Voice files are bundled with the app.
    /// - Throws: Error if download fails, is cancelled, or insufficient disk space
    func downloadModelIfNeeded() async throws {
        guard !modelDownloaded else {
            // Model already downloaded, ensure engine is loaded
            try await loadEngineIfNeeded()
            return
        }
        
        // Check if download is already in progress
        if case .downloading = state {
            throw KokoroError.downloadFailed("Download already in progress")
        }
        
        // Check available disk space before starting download
        if !hasEnoughDiskSpace {
            let needed = additionalSpaceNeeded
            let neededFormatted = ByteCountFormatter.string(fromByteCount: needed, countStyle: .file)
            throw KokoroError.insufficientDiskSpace(neededBytes: needed, message: "Need \(neededFormatted) more free space")
        }
        
        state = .downloading(progress: 0)
        
        do {
            // Create directory if needed
            try FileManager.default.createDirectory(at: kokoroDirectory, withIntermediateDirectories: true)
            
            // Download model file only - voices are bundled with the app
            try await downloadFile(from: modelDownloadURL, to: modelPath, progressWeight: 1.0)
            
            state = .ready
            
            // Load the engine
            try await loadEngineIfNeeded()
            
            print("[KokoroTTSManager] Model download and initialization complete")
        } catch is CancellationError {
            state = .notDownloaded
            print("[KokoroTTSManager] Download was cancelled")
            throw CancellationError()
        } catch {
            state = .error(message: error.localizedDescription)
            print("[KokoroTTSManager] Download failed: \(error)")
            throw error
        }
    }
    
    /// Start downloading the model in the background
    /// Returns a task that can be cancelled
    func startDownload() -> Task<Void, Error> {
        let task = Task {
            try await downloadModelIfNeeded()
        }
        activeDownloadTask = task
        return task
    }
    
    // MARK: - Download Management
    
    /// Active download task for cancellation support
    private var activeDownloadTask: Task<Void, Error>?
    
    /// Download a file with progress tracking using efficient chunked download
    private func downloadFile(from url: URL, to destination: URL, progressWeight: Double, baseProgress: Double = 0) async throws {
        // Check for existing partial download for resume capability
        let tempDestination = destination.appendingPathExtension("download")
        var existingBytes: Int64 = 0
        
        if FileManager.default.fileExists(atPath: tempDestination.path) {
            if let attrs = try? FileManager.default.attributesOfItem(atPath: tempDestination.path),
               let size = attrs[.size] as? Int64 {
                existingBytes = size
            }
        }
        
        // Create request with Range header for resume
        var request = URLRequest(url: url)
        if existingBytes > 0 {
            request.setValue("bytes=\(existingBytes)-", forHTTPHeaderField: "Range")
            print("[KokoroTTSManager] Resuming download from byte \(existingBytes)")
        }
        
        // Use URLSession with progress tracking
        let (asyncBytes, response) = try await URLSession.shared.bytes(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw KokoroError.downloadFailed("Invalid response type")
        }
        
        // Check for successful response (200 = full download, 206 = partial/resume)
        guard httpResponse.statusCode == 200 || httpResponse.statusCode == 206 else {
            throw KokoroError.downloadFailed("HTTP \(httpResponse.statusCode)")
        }
        
        // Calculate expected length
        var expectedTotalLength: Int64
        if httpResponse.statusCode == 206 {
            // Partial content - add existing bytes to content length
            expectedTotalLength = existingBytes + response.expectedContentLength
        } else {
            // Full download - might need to restart
            expectedTotalLength = response.expectedContentLength
            existingBytes = 0
            // Remove any partial download if we're starting fresh
            try? FileManager.default.removeItem(at: tempDestination)
        }
        
        // Open file handle for writing (append if resuming)
        if !FileManager.default.fileExists(atPath: tempDestination.path) {
            FileManager.default.createFile(atPath: tempDestination.path, contents: nil)
        }
        
        let fileHandle = try FileHandle(forWritingTo: tempDestination)
        
        // Seek to end for resume
        if existingBytes > 0 {
            try fileHandle.seekToEnd()
        }
        
        defer {
            try? fileHandle.close()
        }
        
        var receivedLength = existingBytes
        var buffer = Data()
        let bufferSize = 64 * 1024 // 64KB buffer for efficient I/O
        var lastProgressUpdate = Date()
        let progressUpdateInterval: TimeInterval = 0.1 // Update progress max 10x per second
        
        for try await byte in asyncBytes {
            // Check for task cancellation
            try Task.checkCancellation()
            
            buffer.append(byte)
            
            // Flush buffer when full
            if buffer.count >= bufferSize {
                try fileHandle.write(contentsOf: buffer)
                receivedLength += Int64(buffer.count)
                buffer.removeAll(keepingCapacity: true)
                
                // Throttle progress updates for UI performance
                let now = Date()
                if now.timeIntervalSince(lastProgressUpdate) >= progressUpdateInterval {
                    let fileProgress = expectedTotalLength > 0 ? Double(receivedLength) / Double(expectedTotalLength) : 0
                    let totalProgress = baseProgress + (fileProgress * progressWeight)
                    state = .downloading(progress: min(totalProgress, baseProgress + progressWeight))
                    lastProgressUpdate = now
                }
            }
        }
        
        // Flush remaining buffer
        if !buffer.isEmpty {
            try fileHandle.write(contentsOf: buffer)
            receivedLength += Int64(buffer.count)
        }
        
        // Close file handle before verification
        try fileHandle.close()
        
        // Verify checksum before moving to final destination
        if let expectedChecksum = modelVariant.expectedChecksum {
            print("[KokoroTTSManager] Verifying model checksum...")
            let computedChecksum = try await computeSHA256Checksum(of: tempDestination)
            
            if computedChecksum.lowercased() != expectedChecksum.lowercased() {
                // Checksum mismatch - delete the corrupted file
                try? FileManager.default.removeItem(at: tempDestination)
                throw KokoroError.checksumMismatch(expected: expectedChecksum, actual: computedChecksum)
            }
            print("[KokoroTTSManager] Checksum verified successfully")
        } else {
            print("[KokoroTTSManager] Skipping checksum verification (no expected checksum)")
        }
        
        // Move temp file to final destination
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.moveItem(at: tempDestination, to: destination)
        
        // Final progress update
        let finalProgress = baseProgress + progressWeight
        state = .downloading(progress: finalProgress)
        
        print("[KokoroTTSManager] Downloaded \(destination.lastPathComponent): \(receivedLength) bytes")
    }
    
    /// Cancel any active download and clean up partial files
    func cancelDownload() {
        activeDownloadTask?.cancel()
        activeDownloadTask = nil
        
        // Clean up partial download files
        cleanupPartialDownloads()
        
        state = .notDownloaded
        print("[KokoroTTSManager] Download cancelled and partial files cleaned up")
    }
    
    /// Clean up any partial download files (.download extension)
    private func cleanupPartialDownloads() {
        let tempModelPath = modelPath.appendingPathExtension("download")
        
        if FileManager.default.fileExists(atPath: tempModelPath.path) {
            try? FileManager.default.removeItem(at: tempModelPath)
            print("[KokoroTTSManager] Cleaned up partial model download")
        }
    }
    
    /// Delete the downloaded model to free up space. Voice files are bundled and cannot be deleted.
    func deleteModel() async throws {
        // Stop any ongoing generation
        ttsEngine = nil
        voices = [:]
        
        // Clear GPU memory
        MLX.Memory.clearCache()
        
        // Reset warm-up state since engine is unloaded
        resetWarmUpState()
        
        // Delete model file only - voices are bundled with the app
        try? FileManager.default.removeItem(at: modelPath)
        
        // Also clean up any partial downloads
        cleanupPartialDownloads()
        
        state = .notDownloaded
        print("[KokoroTTSManager] Model and partial downloads deleted")
    }
    
    /// Unload the TTS engine to free memory while the model remains downloaded.
    /// Call this when the app receives a memory warning or when TTS is not needed.
    /// The engine will be reloaded automatically on the next generateAudio call.
    func unloadEngine() {
        guard ttsEngine != nil else { return }
        
        // Cancel any pending idle unload since we're unloading now
        idleUnloadTask?.cancel()
        idleUnloadTask = nil
        
        ttsEngine = nil
        voices = [:]
        
        // Clear all MLX GPU caches
        MLX.Memory.clearCache()
        
        // Reset warm-up state
        resetWarmUpState()
        
        print("[KokoroTTSManager] Engine unloaded to free memory")
    }
    
    /// Schedule automatic engine unloading after idle timeout.
    /// Called after each audio generation to start/reset the idle timer.
    private func scheduleIdleUnload() {
        // Cancel any existing idle unload task
        idleUnloadTask?.cancel()
        
        // Schedule new unload task
        idleUnloadTask = Task {
            do {
                try await Task.sleep(for: .seconds(Self.idleUnloadTimeout))
                
                // Only unload if not generating
                if state != .generating {
                    unloadEngine()
                    print("[KokoroTTSManager] Engine unloaded due to inactivity")
                }
            } catch {
                // Task was cancelled, which is expected
            }
        }
    }
    
    /// Cancel any pending idle unload (call when starting new generation)
    private func cancelIdleUnload() {
        idleUnloadTask?.cancel()
        idleUnloadTask = nil
    }
    
    /// Handle memory warning by clearing caches and optionally unloading the engine.
    /// - Parameter unloadIfIdle: If true, unloads the engine entirely if not currently generating
    func handleMemoryWarning(unloadIfIdle: Bool = true) {
        // Always clear MLX caches first - this is safe even during generation
        MLX.Memory.clearCache()
        
        // Unload engine if not actively generating
        if unloadIfIdle && state != .generating {
            unloadEngine()
            print("[KokoroTTSManager] Handled memory warning, unloaded engine")
        } else {
            print("[KokoroTTSManager] Handled memory warning, cleared caches (engine in use)")
        }
        
        // Force a garbage collection hint by autoreleasing any temporary objects
        autoreleasepool { }
    }
    
    /// Handle app backgrounding gracefully.
    /// GPU work from background is NOT allowed before iOS 26 and will crash.
    /// This method stops any in-progress generation and clears caches.
    func handleBackgrounding() {
        print("[KokoroTTSManager] App entering background, stopping GPU work")
        
        // Stop any audio playback
        playerNode?.stop()
        audioEngine?.stop()
        
        // Clear all MLX caches to free GPU memory
        MLX.Memory.clearCache()
        
        // Note: We don't unload the engine here because the app might return
        // quickly. The engine will be unloaded by:
        // 1. The idle timeout if app stays backgrounded
        // 2. Memory pressure handler if iOS needs the memory
        // 3. Explicit unloadEngine() call in ClawdyApp when audio is not playing
        
        print("[KokoroTTSManager] Cleared GPU caches for background")
    }
    
    // MARK: - Storage Management
    
    /// Minimum required disk space buffer (100 MB beyond model size)
    private static let minimumDiskSpaceBuffer: Int64 = 100_000_000
    
    /// Total storage used by Kokoro TTS (model + any partials). Voice files are bundled with the app.
    var totalStorageUsed: Int64 {
        var total: Int64 = 0
        let fm = FileManager.default
        
        // Add model file size
        if let attrs = try? fm.attributesOfItem(atPath: modelPath.path),
           let size = attrs[.size] as? Int64 {
            total += size
        }
        
        // Add any partial download files
        let tempModelPath = modelPath.appendingPathExtension("download")
        
        if let attrs = try? fm.attributesOfItem(atPath: tempModelPath.path),
           let size = attrs[.size] as? Int64 {
            total += size
        }
        
        return total
    }
    
    /// Get available disk space on device
    var availableDiskSpace: Int64 {
        guard let attrs = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory()),
              let freeSpace = attrs[.systemFreeSize] as? Int64 else {
            return 0
        }
        return freeSpace
    }
    
    /// Check if there's enough disk space to download the model
    /// - Returns: True if there's enough space, false otherwise
    var hasEnoughDiskSpace: Bool {
        let required = modelVariant.expectedSize + Self.minimumDiskSpaceBuffer
        return availableDiskSpace >= required
    }
    
    /// Get the amount of disk space needed for download (accounting for what's already downloaded)
    var additionalSpaceNeeded: Int64 {
        let required = modelVariant.expectedSize + Self.minimumDiskSpaceBuffer
        let available = availableDiskSpace
        
        if available >= required {
            return 0
        }
        return required - available
    }
    
    // MARK: - Public API: Voice Selection
    
    /// Available voice options
    struct KokoroVoice: Identifiable, Hashable {
        let id: String
        let name: String
        let language: KokoroSwift.Language
        let style: String
        
        var displayName: String {
            "\(name) (\(style))"
        }
    }
    
    /// Get list of available voices
    var availableVoices: [KokoroVoice] {
        // Return curated selection of voices
        return [
            KokoroVoice(id: "af_heart", name: "Heart", language: .enUS, style: "Warm female"),
            KokoroVoice(id: "af_nova", name: "Nova", language: .enUS, style: "Energetic female"),
            KokoroVoice(id: "af_bella", name: "Bella", language: .enUS, style: "Calm female"),
            KokoroVoice(id: "af_sarah", name: "Sarah", language: .enUS, style: "Clear female"),
            KokoroVoice(id: "am_adam", name: "Adam", language: .enUS, style: "Natural male"),
            KokoroVoice(id: "am_michael", name: "Michael", language: .enUS, style: "Warm male"),
            KokoroVoice(id: "bf_emma", name: "Emma", language: .enGB, style: "British female"),
            KokoroVoice(id: "bm_george", name: "George", language: .enGB, style: "British male"),
        ]
    }
    
    /// Get the currently selected voice
    var selectedVoice: KokoroVoice {
        availableVoices.first { $0.id == selectedVoiceId } ?? availableVoices[0]
    }
    
    /// Set the selected voice
    func setSelectedVoice(_ voice: KokoroVoice) {
        selectedVoiceId = voice.id
    }
    
    // MARK: - Public API: Audio Generation
    
    // MARK: - Text Chunking Configuration
    
    /// Maximum characters per chunk for memory-safe generation.
    /// Shorter chunks reduce peak memory usage during inference.
    /// ~100 chars produces ~4-6 seconds of audio, keeping memory under ~500MB per chunk.
    private static let maxChunkLength = 100
    
    /// Generate audio from text
    /// - Parameters:
    ///   - text: The text to synthesize
    ///   - speed: Speech speed multiplier (1.0 = normal, >1.0 = faster)
    /// - Returns: Audio buffer ready for playback
    func generateAudio(text: String, speed: Float = 1.0) async throws -> AVAudioPCMBuffer {
        guard state == .ready else {
            throw KokoroError.modelNotReady
        }
        
        // Cancel any pending idle unload since we're about to use the engine
        cancelIdleUnload()
        
        try await loadEngineIfNeeded()
        
        guard let engine = ttsEngine else {
            throw KokoroError.engineNotInitialized
        }
        
        guard let voiceEmbedding = voices[selectedVoiceId] else {
            throw KokoroError.voiceNotFound(selectedVoiceId)
        }
        
        let previousState = state
        state = .generating
        
        defer {
            state = previousState
            // Always clear GPU cache after generation to prevent memory accumulation
            MLX.Memory.clearCache()
            // Schedule idle unload for later
            scheduleIdleUnload()
        }
        
        print("[KokoroTTSManager] Generating audio for: \(text.prefix(50))...")
        
        // Split text into chunks to reduce peak memory usage
        let chunks = splitTextIntoChunks(text, maxLength: Self.maxChunkLength)
        
        if chunks.count == 1 {
            // Single chunk - generate directly
            let audioSamples: [Float] = try autoreleasepool {
                let (samples, _) = try engine.generateAudio(
                    voice: voiceEmbedding,
                    language: selectedVoice.language,
                    text: text,
                    speed: speed
                )
                return samples
            }
            
            // Clear cache immediately after generation to free GPU memory
            MLX.Memory.clearCache()
            
            let buffer = try createAudioBuffer(from: audioSamples)
            print("[KokoroTTSManager] Generated \(audioSamples.count) samples")
            return buffer
        }
        
        // Multiple chunks - generate each and concatenate
        print("[KokoroTTSManager] Splitting into \(chunks.count) chunks for memory efficiency")
        var allSamples: [Float] = []
        
        for (index, chunk) in chunks.enumerated() {
            let chunkSamples: [Float] = try autoreleasepool {
                let (samples, _) = try engine.generateAudio(
                    voice: voiceEmbedding,
                    language: selectedVoice.language,
                    text: chunk,
                    speed: speed
                )
                return samples
            }
            
            allSamples.append(contentsOf: chunkSamples)
            
            // Clear cache after each chunk to free memory
            MLX.Memory.clearCache()
            
            print("[KokoroTTSManager] Chunk \(index + 1)/\(chunks.count): \(chunkSamples.count) samples")
        }
        
        let buffer = try createAudioBuffer(from: allSamples)
        print("[KokoroTTSManager] Generated total \(allSamples.count) samples from \(chunks.count) chunks")
        return buffer
    }
    
    /// Generate audio as a stream of buffers, yielding each chunk as it's ready.
    /// This enables playback to start before the entire text is generated.
    /// - Parameters:
    ///   - text: The text to synthesize
    ///   - speed: Speech speed multiplier (1.0 = normal, >1.0 = faster)
    /// - Returns: AsyncThrowingStream that yields audio buffers as chunks complete
    func generateAudioStreaming(text: String, speed: Float = 1.0) -> AsyncThrowingStream<AVAudioPCMBuffer, Error> {
        AsyncThrowingStream { continuation in
            Task {
                do {
                    guard state == .ready else {
                        continuation.finish(throwing: KokoroError.modelNotReady)
                        return
                    }
                    
                    cancelIdleUnload()
                    try await loadEngineIfNeeded()
                    
                    guard let engine = ttsEngine else {
                        continuation.finish(throwing: KokoroError.engineNotInitialized)
                        return
                    }
                    
                    guard let voiceEmbedding = voices[selectedVoiceId] else {
                        continuation.finish(throwing: KokoroError.voiceNotFound(selectedVoiceId))
                        return
                    }
                    
                    let previousState = state
                    state = .generating
                    
                    defer {
                        state = previousState
                        MLX.Memory.clearCache()
                        scheduleIdleUnload()
                    }
                    
                    let chunks = splitTextIntoChunks(text, maxLength: Self.maxChunkLength)
                    print("[KokoroTTSManager] Streaming \(chunks.count) chunks for: \(text.prefix(50))...")
                    
                    for (index, chunk) in chunks.enumerated() {
                        // Check for cancellation
                        if Task.isCancelled {
                            continuation.finish()
                            return
                        }
                        
                        let chunkSamples: [Float] = try autoreleasepool {
                            let (samples, _) = try engine.generateAudio(
                                voice: voiceEmbedding,
                                language: selectedVoice.language,
                                text: chunk,
                                speed: speed
                            )
                            return samples
                        }
                        
                        MLX.Memory.clearCache()
                        
                        let buffer = try createAudioBuffer(from: chunkSamples)
                        print("[KokoroTTSManager] Streaming chunk \(index + 1)/\(chunks.count): \(chunkSamples.count) samples")
                        
                        continuation.yield(buffer)
                    }
                    
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
        }
    }
    
    /// Speak text with streaming playback - starts playing as soon as first chunk is ready.
    /// Schedules buffers sequentially, waiting for each to complete before scheduling the next.
    /// - Parameters:
    ///   - text: The text to synthesize
    ///   - speed: Speech speed multiplier (1.0 = normal, >1.0 = faster)
    func speakTextStreaming(_ text: String, speed: Float = 1.0) async throws {
        // Configure audio session
        #if os(iOS)
        do {
            let audioSession = AVAudioSession.sharedInstance()
            try audioSession.setCategory(.playback, mode: .voicePrompt, options: [.duckOthers])
            try audioSession.setActive(true)
        } catch {
            print("[KokoroTTSManager] Audio session error: \(error)")
        }
        #endif
        
        // Create audio engine if needed
        if audioEngine == nil {
            audioEngine = AVAudioEngine()
            playerNode = AVAudioPlayerNode()
            audioEngine?.attach(playerNode!)
        }
        
        guard let engine = audioEngine, let player = playerNode else {
            throw KokoroError.audioEngineError
        }
        
        let stream = generateAudioStreaming(text: text, speed: speed)
        var isFirstChunk = true
        
        for try await buffer in stream {
            if Task.isCancelled { break }
            
            // Connect and start on first chunk
            if isFirstChunk {
                engine.connect(player, to: engine.mainMixerNode, format: buffer.format)
                try engine.start()
                player.play()
                isFirstChunk = false
            }
            
            // Schedule buffer and wait for completion
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                player.scheduleBuffer(buffer, at: nil, options: []) {
                    continuation.resume()
                }
            }
        }
        
        // Deactivate audio session
        #if os(iOS)
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        #endif
    }
    
    /// Split text into chunks at sentence boundaries, respecting max length.
    /// Tries to split at sentence endings (.!?) first, then falls back to commas/spaces.
    private func splitTextIntoChunks(_ text: String, maxLength: Int) -> [String] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // If short enough, return as single chunk
        guard trimmed.count > maxLength else {
            return [trimmed]
        }
        
        var chunks: [String] = []
        var remaining = trimmed
        
        while !remaining.isEmpty {
            if remaining.count <= maxLength {
                chunks.append(remaining.trimmingCharacters(in: .whitespaces))
                break
            }
            
            // Find best split point within maxLength
            let searchRange = remaining.prefix(maxLength)
            var splitIndex: String.Index?
            
            // Priority 1: Split at sentence ending (.!?)
            if let lastSentenceEnd = searchRange.lastIndex(where: { ".!?".contains($0) }) {
                splitIndex = remaining.index(after: lastSentenceEnd)
            }
            // Priority 2: Split at comma or semicolon
            else if let lastComma = searchRange.lastIndex(where: { ",;".contains($0) }) {
                splitIndex = remaining.index(after: lastComma)
            }
            // Priority 3: Split at last space
            else if let lastSpace = searchRange.lastIndex(of: " ") {
                splitIndex = lastSpace
            }
            // Fallback: Hard split at maxLength
            else {
                splitIndex = remaining.index(remaining.startIndex, offsetBy: maxLength)
            }
            
            if let idx = splitIndex {
                let chunk = String(remaining[..<idx]).trimmingCharacters(in: .whitespaces)
                if !chunk.isEmpty {
                    chunks.append(chunk)
                }
                remaining = String(remaining[idx...]).trimmingCharacters(in: .whitespaces)
            } else {
                // Shouldn't happen, but safety fallback
                chunks.append(remaining)
                break
            }
        }
        
        return chunks
    }
    
    /// Generate audio and play it immediately
    func speakText(_ text: String, speed: Float = 1.0) async throws {
        let buffer = try await generateAudio(text: text, speed: speed)
        try await playAudioBuffer(buffer)
    }
    
    /// Preview a specific voice by generating and playing a sample phrase
    /// - Parameters:
    ///   - voiceId: The voice identifier to preview
    ///   - speed: Speech speed multiplier (1.0 = normal)
    func previewVoice(_ voiceId: String, speed: Float = 1.0) async throws {
        guard state == .ready else {
            throw KokoroError.modelNotReady
        }
        
        try await loadEngineIfNeeded()
        
        guard let engine = ttsEngine else {
            throw KokoroError.engineNotInitialized
        }
        
        guard let voiceEmbedding = voices[voiceId] else {
            throw KokoroError.voiceNotFound(voiceId)
        }
        
        // Find the voice to get the correct language
        let voice = availableVoices.first { $0.id == voiceId } ?? selectedVoice
        let previewText = "Hello, this is \(voice.name)."
        
        print("[KokoroTTSManager] Previewing voice: \(voice.name)")
        
        let previousState = state
        state = .generating
        
        defer {
            state = previousState
        }
        
        // Generate audio samples
        let (audioSamples, _) = try engine.generateAudio(
            voice: voiceEmbedding,
            language: voice.language,
            text: previewText,
            speed: speed
        )
        
        // Clear MLX caches to reduce memory pressure
        MLX.Memory.clearCache()
        
        // Convert to AVAudioPCMBuffer and play
        let buffer = try createAudioBuffer(from: audioSamples)
        try await playAudioBuffer(buffer)
    }
    
    /// Stop any ongoing audio playback and clean up resources
    func stopPlayback() {
        playerNode?.stop()
        audioEngine?.stop()

        // Reset and release audio engine to fully release the audio session
        if let engine = audioEngine {
            engine.reset()
        }
        audioEngine = nil
        playerNode = nil

        // Deactivate audio session
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)

        // Clear GPU cache to free any lingering MLX memory
        MLX.Memory.clearCache()
    }
    
    // MARK: - Private Helpers
    
    /// Load the TTS engine if not already loaded
    private func loadEngineIfNeeded() async throws {
        guard ttsEngine == nil else { return }
        
        guard modelDownloaded else {
            throw KokoroError.modelNotReady
        }
        
        print("[KokoroTTSManager] Loading TTS engine...")
        
        // Load the TTS engine
        ttsEngine = KokoroTTS(modelPath: modelPath)
        
        // Load voice embeddings from bundled safetensors files
        try loadBundledVoices()
        
        print("[KokoroTTSManager] Engine loaded successfully")
    }
    
    /// Load voice embeddings from bundled safetensors files in the app bundle.
    /// Each voice file is a .safetensors file containing the voice embedding tensor.
    private func loadBundledVoices() throws {
        print("[KokoroTTSManager] Loading bundled voices...")
        
        for voiceId in Self.bundledVoiceIds {
            // Look for the voice file in the app bundle
            guard let voiceURL = Bundle.main.url(forResource: voiceId, withExtension: "safetensors") else {
                print("[KokoroTTSManager] Warning: Voice file not found in bundle: \(voiceId).safetensors")
                continue
            }
            
            do {
                // Load the safetensors file using MLX
                let voiceData = try MLX.loadArrays(url: voiceURL)
                
                // The voice embedding is typically stored under a key like "weight" or the voice name
                // Try common key patterns
                if let embedding = voiceData["weight"] {
                    voices[voiceId] = embedding
                    print("[KokoroTTSManager] Loaded voice: \(voiceId)")
                } else if let embedding = voiceData.values.first {
                    // If there's only one array, use it
                    voices[voiceId] = embedding
                    print("[KokoroTTSManager] Loaded voice: \(voiceId) (using first array)")
                } else {
                    print("[KokoroTTSManager] Warning: No embedding found in \(voiceId).safetensors")
                }
            } catch {
                print("[KokoroTTSManager] Error loading voice \(voiceId): \(error)")
            }
        }
        
        print("[KokoroTTSManager] Loaded \(voices.count) voices from bundle")
        
        if voices.isEmpty {
            throw KokoroError.voiceNotFound("No voices loaded from bundle")
        }
    }
    
    /// Create an AVAudioPCMBuffer from audio samples
    private func createAudioBuffer(from samples: [Float]) throws -> AVAudioPCMBuffer {
        let sampleRate = Double(KokoroTTS.Constants.samplingRate)
        
        guard let format = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 1) else {
            throw KokoroError.audioFormatError
        }
        
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: AVAudioFrameCount(samples.count)) else {
            throw KokoroError.bufferCreationError
        }
        
        buffer.frameLength = buffer.frameCapacity
        
        guard let channelData = buffer.floatChannelData else {
            throw KokoroError.bufferCreationError
        }
        
        // Copy samples to buffer
        samples.withUnsafeBufferPointer { samplesPtr in
            guard let baseAddress = samplesPtr.baseAddress else { return }
            channelData[0].initialize(from: baseAddress, count: samples.count)
        }
        
        return buffer
    }
    
    /// Play an audio buffer.
    /// Exposed for pipeline parallelism - allows IncrementalTTSManager to play prefetched buffers.
    func playAudioBuffer(_ buffer: AVAudioPCMBuffer) async throws {
        // Configure audio session
        #if os(iOS)
        do {
            let audioSession = AVAudioSession.sharedInstance()
            try audioSession.setCategory(.playback, mode: .voicePrompt, options: [.duckOthers])
            try audioSession.setActive(true)
        } catch {
            print("[KokoroTTSManager] Audio session error: \(error)")
        }
        #endif
        
        // Create audio engine if needed
        if audioEngine == nil {
            audioEngine = AVAudioEngine()
            playerNode = AVAudioPlayerNode()
            audioEngine?.attach(playerNode!)
        }
        
        guard let engine = audioEngine, let player = playerNode else {
            throw KokoroError.audioEngineError
        }
        
        // Connect player to mixer
        engine.connect(player, to: engine.mainMixerNode, format: buffer.format)
        
        // Start engine
        try engine.start()
        
        // Play buffer and wait for completion
        await withCheckedContinuation { continuation in
            player.scheduleBuffer(buffer, at: nil, options: .interrupts) {
                continuation.resume()
            }
            player.play()
        }
        
        // Deactivate audio session
        #if os(iOS)
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        #endif
    }
    
    // MARK: - Checksum Verification
    
    /// Compute SHA256 checksum of a file using streaming to handle large files efficiently.
    /// - Parameter fileURL: URL of the file to compute checksum for
    /// - Returns: Hexadecimal string representation of the SHA256 hash
    /// - Throws: Error if file cannot be read
    private func computeSHA256Checksum(of fileURL: URL) async throws -> String {
        // Use a background thread for the CPU-intensive hashing
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    let fileHandle = try FileHandle(forReadingFrom: fileURL)
                    defer { try? fileHandle.close() }
                    
                    var hasher = SHA256()
                    let bufferSize = 1024 * 1024 // 1MB chunks for efficient hashing
                    
                    while autoreleasepool(invoking: {
                        guard let data = try? fileHandle.read(upToCount: bufferSize),
                              !data.isEmpty else {
                            return false
                        }
                        hasher.update(data: data)
                        return true
                    }) {}
                    
                    let digest = hasher.finalize()
                    let checksumString = digest.map { String(format: "%02x", $0) }.joined()
                    
                    continuation.resume(returning: checksumString)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    /// Verify the integrity of the downloaded model file.
    /// - Returns: True if the checksum matches or verification is skipped, false if mismatch
    func verifyModelIntegrity() async -> Bool {
        guard modelDownloaded else { return false }
        
        guard let expectedChecksum = modelVariant.expectedChecksum else {
            // No checksum to verify against - assume valid
            print("[KokoroTTSManager] No checksum available for verification, assuming valid")
            return true
        }
        
        do {
            let computedChecksum = try await computeSHA256Checksum(of: modelPath)
            let isValid = computedChecksum.lowercased() == expectedChecksum.lowercased()
            
            if isValid {
                print("[KokoroTTSManager] Model integrity verified successfully")
            } else {
                print("[KokoroTTSManager] Model integrity check FAILED - checksums don't match")
            }
            
            return isValid
        } catch {
            print("[KokoroTTSManager] Error verifying model integrity: \(error)")
            return false
        }
    }
    
    // MARK: - Performance Optimization (Model Warm-up)
    
    /// Warm up the TTS engine by pre-loading the model and voices.
    /// Call this on app launch when Kokoro is the preferred engine to eliminate
    /// the delay on the first TTS request.
    ///
    /// This method is safe to call multiple times - subsequent calls are no-ops
    /// if the model is already warmed up.
    ///
    /// - Parameter runInference: If true, runs a minimal inference pass to fully
    ///   initialize the neural network (recommended for best first-use performance)
    /// - Returns: True if warm-up succeeded, false otherwise
    @discardableResult
    func warmUp(runInference: Bool = true) async -> Bool {
        // Skip if already warmed up or not downloaded
        guard !isWarmedUp else {
            print("[KokoroTTSManager] Already warmed up, skipping")
            return true
        }
        
        guard modelDownloaded else {
            print("[KokoroTTSManager] Model not downloaded, cannot warm up")
            return false
        }
        
        guard !isWarmingUp else {
            print("[KokoroTTSManager] Warm-up already in progress")
            return false
        }
        
        isWarmingUp = true
        defer { isWarmingUp = false }
        
        let startTime = CFAbsoluteTimeGetCurrent()
        print("[KokoroTTSManager] Starting model warm-up...")
        
        do {
            // Load the TTS engine and voices
            try await loadEngineIfNeeded()
            
            let loadTime = CFAbsoluteTimeGetCurrent() - startTime
            print("[KokoroTTSManager] Engine loaded in \(String(format: "%.2f", loadTime))s")
            
            // Optionally run a minimal inference pass to fully initialize the model
            // This "primes" the neural network and any lazy MLX operations
            if runInference, let engine = ttsEngine, let voiceEmbedding = voices[selectedVoiceId] {
                let inferenceStart = CFAbsoluteTimeGetCurrent()
                
                // Generate a very short phrase - just enough to initialize the pipeline
                // Using "Hi" minimizes warm-up time while still exercising the full path
                let _ = try engine.generateAudio(
                    voice: voiceEmbedding,
                    language: selectedVoice.language,
                    text: "Hi",
                    speed: 1.0
                )
                
                // Clear MLX caches after warm-up to reduce memory footprint
                MLX.Memory.clearCache()
                
                let inferenceTime = CFAbsoluteTimeGetCurrent() - inferenceStart
                print("[KokoroTTSManager] Inference warm-up completed in \(String(format: "%.2f", inferenceTime))s")
            }
            
            let totalTime = CFAbsoluteTimeGetCurrent() - startTime
            print("[KokoroTTSManager] Model warm-up complete in \(String(format: "%.2f", totalTime))s")
            
            isWarmedUp = true
            return true
            
        } catch {
            print("[KokoroTTSManager] Warm-up failed: \(error.localizedDescription)")
            return false
        }
    }
    
    /// Reset the warm-up state (e.g., if the model is deleted)
    private func resetWarmUpState() {
        isWarmedUp = false
    }
    
    // MARK: - Errors
    
    enum KokoroError: LocalizedError {
        case modelNotReady
        case engineNotInitialized
        case voiceNotFound(String)
        case audioFormatError
        case bufferCreationError
        case audioEngineError
        case downloadFailed(String)
        case insufficientDiskSpace(neededBytes: Int64, message: String)
        case checksumMismatch(expected: String, actual: String)
        
        var errorDescription: String? {
            switch self {
            case .modelNotReady:
                return "Kokoro model is not downloaded. Please download it first."
            case .engineNotInitialized:
                return "TTS engine failed to initialize."
            case .voiceNotFound(let id):
                return "Voice '\(id)' not found in loaded voices."
            case .audioFormatError:
                return "Failed to create audio format."
            case .bufferCreationError:
                return "Failed to create audio buffer."
            case .audioEngineError:
                return "Failed to initialize audio engine."
            case .downloadFailed(let reason):
                return "Download failed: \(reason)"
            case .insufficientDiskSpace(_, let message):
                return "Not enough disk space: \(message)"
            case .checksumMismatch(let expected, let actual):
                return "Model file corrupted. Expected checksum: \(expected.prefix(16))..., got: \(actual.prefix(16))..."
            }
        }
        
        /// Whether this error is due to insufficient disk space
        var isInsufficientDiskSpace: Bool {
            if case .insufficientDiskSpace = self { return true }
            return false
        }
        
        /// Whether this error is due to checksum mismatch (corrupted download)
        var isChecksumMismatch: Bool {
            if case .checksumMismatch = self { return true }
            return false
        }
    }
}

// MARK: - Observable Wrapper for SwiftUI

/// Observable wrapper for KokoroTTSManager to use in SwiftUI views
@MainActor
class KokoroTTSObservable: ObservableObject {
    @Published var state: KokoroTTSManager.State = .notDownloaded
    @Published var downloadProgress: Double = 0
    @Published var selectedVoice: KokoroTTSManager.KokoroVoice
    @Published var errorMessage: String?
    
    private let manager = KokoroTTSManager.shared
    private var progressMonitorTask: Task<Void, Never>?
    private var downloadTask: Task<Void, Error>?
    
    var availableVoices: [KokoroTTSManager.KokoroVoice] {
        get async {
            await manager.availableVoices
        }
    }
    
    /// Whether a download is currently in progress
    var isDownloading: Bool {
        if case .downloading = state { return true }
        return false
    }
    
    init() {
        self.selectedVoice = KokoroTTSManager.KokoroVoice(
            id: "af_heart",
            name: "Heart",
            language: .enUS,
            style: "Warm female"
        )
        
        Task {
            await refreshState()
        }
    }
    
    /// Refresh the current state from the manager
    func refreshState() async {
        let currentState = await manager.state
        state = currentState
        
        if case .downloading(let progress) = currentState {
            downloadProgress = progress
        } else if case .error(let message) = currentState {
            errorMessage = message
        }
    }
    
    /// Start downloading the model with progress monitoring
    func startDownload() {
        guard !isDownloading else { return }
        
        errorMessage = nil
        
        // Start progress monitoring
        progressMonitorTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refreshState()
                try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
            }
        }
        
        // Start the download
        downloadTask = Task { [weak self] in
            do {
                try await self?.manager.downloadModelIfNeeded()
            } catch is CancellationError {
                // Download was cancelled, not an error
            } catch {
                await MainActor.run {
                    self?.errorMessage = error.localizedDescription
                }
            }
            
            // Stop progress monitoring when download completes
            self?.progressMonitorTask?.cancel()
            self?.progressMonitorTask = nil
            
            await self?.refreshState()
        }
    }
    
    /// Cancel any active download
    func cancelDownload() async {
        downloadTask?.cancel()
        downloadTask = nil
        progressMonitorTask?.cancel()
        progressMonitorTask = nil
        
        await manager.cancelDownload()
        await refreshState()
    }
    
    /// Download model using async/await (for programmatic use)
    func downloadModel() async throws {
        try await manager.downloadModelIfNeeded()
        await refreshState()
    }
    
    func deleteModel() async throws {
        // Cancel any active download first
        await cancelDownload()
        
        try await manager.deleteModel()
        await refreshState()
    }
    
    func generateAudio(text: String, speed: Float = 1.0) async throws -> AVAudioPCMBuffer {
        try await manager.generateAudio(text: text, speed: speed)
    }
    
    func speak(text: String, speed: Float = 1.0) async throws {
        try await manager.speakText(text, speed: speed)
    }
    
    /// Preview a specific voice by generating and playing a sample phrase
    /// - Parameters:
    ///   - voice: The voice to preview
    ///   - speed: Speech speed multiplier (1.0 = normal)
    func previewVoice(_ voice: KokoroTTSManager.KokoroVoice, speed: Float = 1.0) async throws {
        try await manager.previewVoice(voice.id, speed: speed)
    }
    
    func stopPlayback() async {
        await manager.stopPlayback()
    }
    
    func setVoice(_ voice: KokoroTTSManager.KokoroVoice) async {
        await manager.setSelectedVoice(voice)
        selectedVoice = voice
    }
    
    var modelDownloaded: Bool {
        get async {
            await manager.modelDownloaded
        }
    }
    
    var modelSizeOnDisk: Int64 {
        get async {
            await manager.modelSizeOnDisk
        }
    }
    
    /// Total storage used by Kokoro TTS (model + voices + any partials)
    var totalStorageUsed: Int64 {
        get async {
            await manager.totalStorageUsed
        }
    }
    
    /// Available disk space on device
    var availableDiskSpace: Int64 {
        get async {
            await manager.availableDiskSpace
        }
    }
    
    /// Whether there's enough disk space to download the model
    var hasEnoughDiskSpace: Bool {
        get async {
            await manager.hasEnoughDiskSpace
        }
    }
    
    /// Additional space needed to download (0 if enough space)
    var additionalSpaceNeeded: Int64 {
        get async {
            await manager.additionalSpaceNeeded
        }
    }
    
    /// Format the model size for display
    var formattedModelSize: String {
        get async {
            let size = await modelSizeOnDisk
            if size == 0 { return "Not downloaded" }
            return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
        }
    }
    
    /// Format total storage used for display (includes model + voices)
    var formattedTotalStorage: String {
        get async {
            let size = await totalStorageUsed
            if size == 0 { return "Not downloaded" }
            return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
        }
    }
    
    /// Format available disk space for display
    var formattedAvailableSpace: String {
        get async {
            let size = await availableDiskSpace
            return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
        }
    }
    
    /// Format additional space needed for display
    var formattedAdditionalSpaceNeeded: String {
        get async {
            let size = await additionalSpaceNeeded
            if size == 0 { return "None" }
            return ByteCountFormatter.string(fromByteCount: size, countStyle: .file)
        }
    }
    
    /// Format the download progress for display
    var formattedProgress: String {
        let percentage = Int(downloadProgress * 100)
        return "\(percentage)%"
    }
    
    /// Verify the integrity of the downloaded model file.
    /// - Returns: True if the checksum matches or verification is skipped, false if mismatch
    func verifyModelIntegrity() async -> Bool {
        await manager.verifyModelIntegrity()
    }
    
    // MARK: - Model Warm-up
    
    /// Whether the model has been warmed up and is ready for fast inference
    var isWarmedUp: Bool {
        get async {
            await manager.isWarmedUp
        }
    }
    
    /// Whether a warm-up operation is currently in progress
    var isWarmingUp: Bool {
        get async {
            await manager.isWarmingUp
        }
    }
    
    /// Warm up the TTS engine by pre-loading the model and voices.
    /// Call this on app launch when Kokoro is the preferred engine to eliminate
    /// the delay on the first TTS request.
    ///
    /// - Parameter runInference: If true, runs a minimal inference pass to fully
    ///   initialize the neural network (recommended for best first-use performance)
    /// - Returns: True if warm-up succeeded, false otherwise
    @discardableResult
    func warmUp(runInference: Bool = true) async -> Bool {
        await manager.warmUp(runInference: runInference)
    }
}
