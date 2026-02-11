import AVFoundation
import OSLog
import UIKit

/// Service for handling camera capabilities (list, snap, clip) for node invocations.
/// Uses AVFoundation for camera access and capture.
actor CameraCapabilityService {
    private let logger = Logger(subsystem: "com.clawdy", category: "camera")
    
    // MARK: - Errors
    
    enum CameraServiceError: LocalizedError {
        case cameraUnavailable
        case microphoneUnavailable
        case permissionDenied(String)
        case captureFailed(String)
        case exportFailed(String)
        case backgroundRestricted
        
        var errorDescription: String? {
            switch self {
            case .cameraUnavailable:
                return "Camera unavailable"
            case .microphoneUnavailable:
                return "Microphone unavailable"
            case .permissionDenied(let kind):
                return "\(kind) permission denied"
            case .captureFailed(let message):
                return message
            case .exportFailed(let message):
                return "Export failed: \(message)"
            case .backgroundRestricted:
                return "Camera requires app to be in foreground"
            }
        }
    }
    
    // MARK: - Singleton
    
    static let shared = CameraCapabilityService()
    
    private var activePhotoDelegate: PhotoCaptureDelegate?
    private var activeMovieDelegate: MovieRecordingDelegate?
    private let captureQueue = DispatchQueue(label: "com.clawdy.camera.capture")
    
    private init() {}
    
    // MARK: - Camera List
    
    /// List available cameras on the device.
    /// - Returns: Array of CameraInfo describing available cameras
    func listCameras() -> CameraListResult {
        let devices = Self.availableCameras()
        
        let cameras = devices.map { device in
            CameraInfo(
                id: device.uniqueID,
                name: device.localizedName,
                facing: Self.positionLabel(device.position),
                isDefault: device.position == .back // Back camera is typically the default
            )
        }
        
        return CameraListResult(cameras: cameras)
    }
    
    private func clearActivePhotoDelegate() {
        activePhotoDelegate = nil
    }

    private func clearActiveMovieDelegate() {
        activeMovieDelegate = nil
    }

    private func runOnCaptureQueue<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            captureQueue.async {
                do {
                    continuation.resume(returning: try work())
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func runOnCaptureQueue(_ work: @escaping () -> Void) async {
        await withCheckedContinuation { continuation in
            captureQueue.async {
                work()
                continuation.resume()
            }
        }
    }
    
    // MARK: - Camera Snap
    
    // MARK: - Size Limits
    
    /// Maximum payload size in bytes (before base64 encoding).
    /// Gateway has a 5MB limit, and base64 adds ~33% overhead, so we target ~3.5MB raw.
    private static let maxPayloadBytes = 3_500_000
    
    /// Default max width for photos (balances quality vs size)
    private static let defaultMaxWidth = 1280
    
    /// Default JPEG quality (0.7 produces good quality at reasonable size)
    private static let defaultQuality = 0.7
    
    /// Capture a photo using the specified camera.
    /// - Parameters:
    ///   - facing: Which camera to use (front/back)
    ///   - maxWidth: Maximum width in pixels (scales down if larger, default 1280)
    ///   - quality: JPEG quality 0.0-1.0 (default 0.7)
    ///   - delayMs: Delay before capture in milliseconds
    /// - Returns: CameraSnapResult with base64-encoded image data
    func snap(
        facing: CameraFacing,
        maxWidth: Int?,
        quality: Double?,
        delayMs: Int?
    ) async throws -> CameraSnapResult {
        // Ensure camera permission
        logger.debug("snap request: facing=\(String(describing: facing), privacy: .public) maxWidth=\(String(describing: maxWidth)) quality=\(String(describing: quality)) delayMs=\(String(describing: delayMs))")
        try await ensureAccess(for: .video)
        
        let normalizedMaxWidth = maxWidth ?? Self.defaultMaxWidth
        let normalizedQuality = Self.clampQuality(quality ?? Self.defaultQuality)
        let normalizedDelay = max(0, delayMs ?? 0)
        
        // Create capture session
        let session = AVCaptureSession()
        session.sessionPreset = .photo
        
        // Get camera device
        guard let device = Self.pickCamera(facing: facing) else {
            logger.error("snap failed: no camera for facing=\(String(describing: facing), privacy: .public)")
            throw CameraServiceError.cameraUnavailable
        }
        logger.debug("snap using device=\(device.localizedName, privacy: .public) id=\(device.uniqueID, privacy: .public)")
        
        // Add camera input/output on the main thread (AVCaptureSession is not thread-safe)
        let output = AVCapturePhotoOutput()
        try await runOnCaptureQueue {
            session.beginConfiguration()
            defer { session.commitConfiguration() }
            
            let input = try AVCaptureDeviceInput(device: device)
            guard session.canAddInput(input) else {
                logger.error("snap failed: cannot add camera input")
                throw CameraServiceError.captureFailed("Failed to add camera input")
            }
            session.addInput(input)
            
            guard session.canAddOutput(output) else {
                logger.error("snap failed: cannot add photo output")
                throw CameraServiceError.captureFailed("Failed to add photo output")
            }
            session.addOutput(output)
            output.maxPhotoQualityPrioritization = .quality
        }
        
        // Start session on capture queue
        await runOnCaptureQueue {
            session.startRunning()
            self.logger.debug("snap session running=\(session.isRunning)")
        }
        defer {
            Task {
                await self.runOnCaptureQueue {
                    session.stopRunning()
                    self.logger.debug("snap session stopped")
                }
            }
        }
        
        // Allow session to warm up
        await Self.warmUpCaptureSession()
        await waitForExposureAndWhiteBalance(device: device)
        
        // Apply delay if specified
        if normalizedDelay > 0 {
            let delayNs = UInt64(min(normalizedDelay, 10000)) * 1_000_000
            try? await Task.sleep(nanoseconds: delayNs)
        }
        
        // Configure photo settings
        let settings: AVCapturePhotoSettings = {
            if output.availablePhotoCodecTypes.contains(.jpeg) {
                return AVCapturePhotoSettings(format: [AVVideoCodecKey: AVVideoCodecType.jpeg])
            }
            return AVCapturePhotoSettings()
        }()
        settings.photoQualityPrioritization = .quality
        
        // Capture photo using delegate
        let imageData = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            let delegate = PhotoCaptureDelegate(
                continuation: continuation,
                onComplete: { [weak self] in
                    Task { await self?.clearActivePhotoDelegate() }
                }
            )
            // Keep delegate alive during capture
            activePhotoDelegate = delegate
            Task {
                await self.runOnCaptureQueue {
                    output.capturePhoto(with: settings, delegate: delegate)
                    self.logger.debug("snap capture requested")
                }
            }
        }
        
        // Process image: resize and compress with size limit
        guard let originalImage = UIImage(data: imageData) else {
            throw CameraServiceError.captureFailed("Failed to decode captured image")
        }
        
        // Resize if needed
        var processedImage: UIImage
        if originalImage.size.width > CGFloat(normalizedMaxWidth) {
            let scale = CGFloat(normalizedMaxWidth) / originalImage.size.width
            let newSize = CGSize(
                width: originalImage.size.width * scale,
                height: originalImage.size.height * scale
            )
            processedImage = originalImage.resized(to: newSize) ?? originalImage
        } else {
            processedImage = originalImage
        }
        
        // Convert to JPEG with adaptive quality to stay under size limit
        var currentQuality = normalizedQuality
        var jpegData = processedImage.jpegData(compressionQuality: currentQuality)
        
        // If still too large, progressively reduce quality
        while let data = jpegData, data.count > Self.maxPayloadBytes && currentQuality > 0.3 {
            currentQuality -= 0.1
            jpegData = processedImage.jpegData(compressionQuality: currentQuality)
            logger.debug("snap reducing quality to \(String(format: "%.1f", currentQuality)) (size: \(data.count) bytes)")
        }
        
        // If still too large after quality reduction, resize further
        while let data = jpegData, data.count > Self.maxPayloadBytes {
            let currentWidth = processedImage.size.width
            if currentWidth < 400 {
                // Don't go below 400px width
                logger.warning("snap: image still large at \(data.count) bytes after max compression")
                break
            }
            let newWidth = currentWidth * 0.75
            let newSize = CGSize(
                width: newWidth,
                height: processedImage.size.height * 0.75
            )
            if let resized = processedImage.resized(to: newSize) {
                processedImage = resized
                jpegData = processedImage.jpegData(compressionQuality: currentQuality)
                logger.debug("snap resizing to \(Int(newWidth))px (size: \(jpegData?.count ?? 0) bytes)")
            } else {
                break
            }
        }
        
        guard let finalData = jpegData else {
            throw CameraServiceError.captureFailed("Failed to encode image as JPEG")
        }
        
        logger.debug("snap final size: \(finalData.count) bytes, quality: \(String(format: "%.1f", currentQuality)), dimensions: \(Int(processedImage.size.width))x\(Int(processedImage.size.height))")
        
        // Provide haptic feedback for photo capture
        await MainActor.run {
            let feedback = UINotificationFeedbackGenerator()
            feedback.notificationOccurred(.success)
        }
        
        return CameraSnapResult(
            format: "jpg",
            base64: finalData.base64EncodedString(),
            width: Int(processedImage.size.width),
            height: Int(processedImage.size.height),
            error: nil
        )
    }
    
    // MARK: - Camera Clip
    
    /// Record a video clip using the specified camera.
    /// - Parameters:
    ///   - facing: Which camera to use (front/back)
    ///   - durationMs: Recording duration in milliseconds
    ///   - includeAudio: Whether to include audio
    /// - Returns: CameraClipResult with base64-encoded video data
    func clip(
        facing: CameraFacing,
        durationMs: Int?,
        includeAudio: Bool
    ) async throws -> CameraClipResult {
        // Ensure camera permission
        logger.debug("clip request: facing=\(String(describing: facing), privacy: .public) durationMs=\(String(describing: durationMs)) includeAudio=\(includeAudio)")
        try await ensureAccess(for: .video)
        
        // Ensure microphone permission if audio is requested
        if includeAudio {
            try await ensureAccess(for: .audio)
        }
        
        let normalizedDuration = Self.clampDurationMs(durationMs)
        
        // Create capture session
        let session = AVCaptureSession()
        session.sessionPreset = .high
        
        // Get camera device
        guard let camera = Self.pickCamera(facing: facing) else {
            logger.error("clip failed: no camera for facing=\(String(describing: facing), privacy: .public)")
            throw CameraServiceError.cameraUnavailable
        }
        logger.debug("clip using device=\(camera.localizedName, privacy: .public) id=\(camera.uniqueID, privacy: .public)")
        
        // Add inputs/outputs on capture queue (AVCaptureSession is not thread-safe)
        let output = AVCaptureMovieFileOutput()
        try await runOnCaptureQueue {
            session.beginConfiguration()
            defer { session.commitConfiguration() }
            
            let cameraInput = try AVCaptureDeviceInput(device: camera)
            guard session.canAddInput(cameraInput) else {
                throw CameraServiceError.captureFailed("Failed to add camera input")
            }
            session.addInput(cameraInput)
            
            if includeAudio {
                guard let mic = AVCaptureDevice.default(for: .audio) else {
                    throw CameraServiceError.microphoneUnavailable
                }
                let micInput = try AVCaptureDeviceInput(device: mic)
                guard session.canAddInput(micInput) else {
                    throw CameraServiceError.captureFailed("Failed to add microphone input")
                }
                session.addInput(micInput)
            }
            
            guard session.canAddOutput(output) else {
                throw CameraServiceError.captureFailed("Failed to add movie output")
            }
            session.addOutput(output)
            output.maxRecordedDuration = CMTime(value: Int64(normalizedDuration), timescale: 1000)
        }
        
        // Start session
        await runOnCaptureQueue {
            session.startRunning()
            self.logger.debug("clip session running=\(session.isRunning)")
        }
        defer {
            Task {
                await self.runOnCaptureQueue {
                    session.stopRunning()
                    self.logger.debug("clip session stopped")
                }
            }
        }
        
        // Allow session to warm up
        await Self.warmUpCaptureSession()
        
        // Create temp file for recording
        let tempMovURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdy-clip-\(UUID().uuidString).mov")
        defer {
            try? FileManager.default.removeItem(at: tempMovURL)
        }
        
        // Start recording using delegate
        let recordedURL = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            let delegate = MovieRecordingDelegate(
                continuation: continuation,
                onComplete: { [weak self] in
                    Task { await self?.clearActiveMovieDelegate() }
                }
            )
            activeMovieDelegate = delegate

            Task {
                await self.runOnCaptureQueue {
                    output.startRecording(to: tempMovURL, recordingDelegate: delegate)
                    self.logger.debug("clip recording started")
                }
            }

            Task {
                let timeoutNs = UInt64(max(1000, normalizedDuration + 1000)) * 1_000_000
                try? await Task.sleep(nanoseconds: timeoutNs)
                await self.runOnCaptureQueue {
                    if output.isRecording {
                        self.logger.debug("clip timeout reached, stopping recording")
                        output.stopRecording()
                    }
                }
            }
        }
        
        // Export to MP4
        let mp4URL = FileManager.default.temporaryDirectory
            .appendingPathComponent("clawdy-clip-\(UUID().uuidString).mp4")
        defer {
            try? FileManager.default.removeItem(at: mp4URL)
        }
        
        try await Self.exportToMP4(inputURL: recordedURL, outputURL: mp4URL)
        
        // Read file and encode as base64
        let videoData = try Data(contentsOf: mp4URL)
        
        // Provide haptic feedback for video recording completion
        await MainActor.run {
            let feedback = UINotificationFeedbackGenerator()
            feedback.notificationOccurred(.success)
        }
        
        return CameraClipResult(
            format: "mp4",
            base64: videoData.base64EncodedString(),
            durationMs: normalizedDuration,
            hasAudio: includeAudio,
            error: nil
        )
    }
    
    // MARK: - Permission Handling
    
    /// Ensure camera/microphone access is granted.
    private func ensureAccess(for mediaType: AVMediaType) async throws {
        let status = AVCaptureDevice.authorizationStatus(for: mediaType)
        let kind = mediaType == .video ? "Camera" : "Microphone"
        logger.debug("\(kind, privacy: .public) auth status: \(status.rawValue)")
        
        switch status {
        case .authorized:
            return
            
        case .notDetermined:
            let granted = await withCheckedContinuation { continuation in
                AVCaptureDevice.requestAccess(for: mediaType) { granted in
                    continuation.resume(returning: granted)
                }
            }
            if !granted {
                throw CameraServiceError.permissionDenied(kind)
            }
            
        case .denied, .restricted:
            throw CameraServiceError.permissionDenied(kind)
            
        @unknown default:
            throw CameraServiceError.permissionDenied(kind)
        }
    }
    
    // MARK: - Device Discovery
    
    /// Get all available camera devices.
    private nonisolated static func availableCameras() -> [AVCaptureDevice] {
        let discoverySession = AVCaptureDevice.DiscoverySession(
            deviceTypes: [
                .builtInWideAngleCamera,
                .builtInUltraWideCamera,
                .builtInTelephotoCamera,
                .builtInDualCamera,
                .builtInDualWideCamera,
                .builtInTripleCamera
            ],
            mediaType: .video,
            position: .unspecified
        )
        return discoverySession.devices
    }
    
    /// Pick a camera device based on facing direction.
    private nonisolated static func pickCamera(facing: CameraFacing) -> AVCaptureDevice? {
        let position: AVCaptureDevice.Position = (facing == .front) ? .front : .back
        
        // Try to get the default wide-angle camera for the position
        if let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: position) {
            return device
        }
        
        // Fall back to any available camera
        return AVCaptureDevice.default(for: .video)
    }
    
    /// Convert camera position to string label.
    private nonisolated static func positionLabel(_ position: AVCaptureDevice.Position) -> String {
        switch position {
        case .front: return "front"
        case .back: return "back"
        default: return "unspecified"
        }
    }
    
    // MARK: - Quality Normalization
    
    /// Clamp quality value to valid range (0.05 to 1.0).
    private nonisolated static func clampQuality(_ quality: Double) -> Double {
        return min(1.0, max(0.05, quality))
    }
    
    /// Clamp duration to valid range (250ms to 60s).
    private nonisolated static func clampDurationMs(_ ms: Int?) -> Int {
        let v = ms ?? 5000
        return min(60000, max(250, v))
    }
    
    // MARK: - Capture Session Helpers
    
    /// Allow capture session to warm up for better quality.
    private nonisolated static func warmUpCaptureSession() async {
        try? await Task.sleep(nanoseconds: 150_000_000) // 150ms
    }
    
    /// Wait for camera exposure and white balance to stabilize.
    private func waitForExposureAndWhiteBalance(device: AVCaptureDevice) async {
        let stepNs: UInt64 = 50_000_000 // 50ms
        let maxSteps = 30 // ~1.5s total
        
        for _ in 0..<maxSteps {
            if !(device.isAdjustingExposure || device.isAdjustingWhiteBalance) {
                return
            }
            try? await Task.sleep(nanoseconds: stepNs)
        }
    }
    
    // MARK: - Video Export
    
    /// Export recorded video to MP4 format.
    private nonisolated static func exportToMP4(inputURL: URL, outputURL: URL) async throws {
        let asset = AVURLAsset(url: inputURL)
        
        guard let exportSession = AVAssetExportSession(asset: asset, presetName: AVAssetExportPresetMediumQuality) else {
            throw CameraServiceError.exportFailed("Failed to create export session")
        }
        
        exportSession.shouldOptimizeForNetworkUse = true
        
        // Use the modern async throws API (iOS 18+)
        do {
            try await exportSession.export(to: outputURL, as: .mp4)
        } catch {
            throw CameraServiceError.exportFailed(error.localizedDescription)
        }
    }
}

// MARK: - Photo Capture Delegate

/// Delegate for handling AVCapturePhotoOutput capture callbacks.
private final class PhotoCaptureDelegate: NSObject, AVCapturePhotoCaptureDelegate {
    private let logger = Logger(subsystem: "com.clawdy", category: "camera")
    private var continuation: CheckedContinuation<Data, Error>?
    private let onComplete: (() -> Void)?
    private var didResume = false
    
    init(continuation: CheckedContinuation<Data, Error>, onComplete: (() -> Void)? = nil) {
        self.continuation = continuation
        self.onComplete = onComplete
        super.init()
    }
    
    private func finish(_ result: Result<Data, Error>) {
        guard !didResume, let continuation = continuation else { return }
        didResume = true
        self.continuation = nil
        onComplete?()
        continuation.resume(with: result)
    }
    
    func photoOutput(
        _ output: AVCapturePhotoOutput,
        didFinishProcessingPhoto photo: AVCapturePhoto,
        error: Error?
    ) {
        if let error = error {
            logger.error("snap processing error: \(error.localizedDescription)")
            finish(.failure(error))
            return
        }
        
        guard let data = photo.fileDataRepresentation() else {
            logger.error("snap failed: no photo data")
            finish(.failure(CameraCapabilityService.CameraServiceError.captureFailed("No photo data")))
            return
        }
        
        if data.isEmpty {
            logger.error("snap failed: photo data empty")
            finish(.failure(CameraCapabilityService.CameraServiceError.captureFailed("Photo data empty")))
            return
        }
        
        logger.debug("snap success bytes=\(data.count)")
        finish(.success(data))
    }
    
    func photoOutput(
        _ output: AVCapturePhotoOutput,
        didFinishCaptureFor resolvedSettings: AVCaptureResolvedPhotoSettings,
        error: Error?
    ) {
        guard let error = error else { return }
        logger.error("snap capture error: \(error.localizedDescription)")
        finish(.failure(error))
    }
}

// MARK: - Movie Recording Delegate

/// Delegate for handling AVCaptureMovieFileOutput recording callbacks.
private final class MovieRecordingDelegate: NSObject, AVCaptureFileOutputRecordingDelegate {
    private let logger = Logger(subsystem: "com.clawdy", category: "camera")
    private var continuation: CheckedContinuation<URL, Error>?
    private let onComplete: (() -> Void)?
    private var didResume = false
    
    init(continuation: CheckedContinuation<URL, Error>, onComplete: (() -> Void)? = nil) {
        self.continuation = continuation
        self.onComplete = onComplete
        super.init()
    }

    private func finish(_ result: Result<URL, Error>) {
        guard !didResume, let continuation = continuation else { return }
        didResume = true
        self.continuation = nil
        onComplete?()
        continuation.resume(with: result)
    }
    
    func fileOutput(
        _ output: AVCaptureFileOutput,
        didFinishRecordingTo outputFileURL: URL,
        from connections: [AVCaptureConnection],
        error: Error?
    ) {
        if let error = error {
            let nsError = error as NSError
            // Treat "maximum duration reached" as success (expected behavior)
            if nsError.domain == AVFoundationErrorDomain,
               nsError.code == AVError.maximumDurationReached.rawValue {
                finish(.success(outputFileURL))
                return
            }
            logger.error("clip recording error: \(error.localizedDescription)")
            finish(.failure(error))
            return
        }

        finish(.success(outputFileURL))
    }
}

// MARK: - UIImage Extension

private extension UIImage {
    /// Resize image to the specified size.
    func resized(to size: CGSize) -> UIImage? {
        UIGraphicsBeginImageContextWithOptions(size, false, 1.0)
        defer { UIGraphicsEndImageContext() }
        draw(in: CGRect(origin: .zero, size: size))
        return UIGraphicsGetImageFromCurrentImageContext()
    }
}
