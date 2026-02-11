import Foundation
import OSLog
import UIKit

/// Notification posted when all image attachments are cleared (e.g., due to memory pressure).
/// Observers (like ClawdyViewModel) should clear their local image references.
extension Notification.Name {
    static let imageAttachmentsCleared = Notification.Name("imageAttachmentsCleared")
}

/// In-memory store for image attachments during the current session.
/// Images are stored as temp files and are NOT persisted across app launches.
@MainActor
class ImageAttachmentStore: ObservableObject {
    private let logger = Logger(subsystem: "com.clawdy", category: "image-store")
    
    /// Shared singleton instance for app-wide access (memory pressure handling, etc.)
    static let shared = ImageAttachmentStore()
    
    /// Maximum allowed image size in bytes (50MB)
    /// Large images are compressed before SFTP upload, so we allow bigger files at selection time
    static let maxImageSize = 50 * 1024 * 1024
    
    /// All images for current session, keyed by UUID
    private var attachments: [UUID: ImageAttachment] = [:]
    
    /// Directory for storing temp image files
    private let imagesDirectory: URL
    
    init() {
        // Create temp directory for images
        let tempDir = FileManager.default.temporaryDirectory
        imagesDirectory = tempDir.appendingPathComponent("Clawdy/images", isDirectory: true)
        
        // Create directory if it doesn't exist
        try? FileManager.default.createDirectory(
            at: imagesDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
    }
    
    // MARK: - Public Methods
    
    /// Add image from raw data (from photo picker or camera).
    /// - Parameters:
    ///   - data: Raw image data
    ///   - mediaType: MIME type of the image (e.g., "image/jpeg")
    /// - Returns: The created ImageAttachment
    /// - Throws: ImageError if image is too large or cannot be saved
    func addImage(from data: Data, mediaType: String) throws -> ImageAttachment {
        // Validate size
        try validateSize(data)
        
        // Generate unique ID and file paths
        let id = UUID()
        let ext = ImageAttachment.fileExtension(for: mediaType)
        let fileURL = imagesDirectory.appendingPathComponent("\(id.uuidString).\(ext)")
        
        // Extract dimensions
        let dimensions = ImageAttachment.extractDimensions(from: data)
        
        // Save to temp file
        do {
            try data.write(to: fileURL)
        } catch {
            throw ImageError.loadFailed
        }
        
        // Create attachment
        let attachment = ImageAttachment(
            id: id,
            tempFileURL: fileURL,
            thumbnailURL: nil,
            mediaType: mediaType,
            originalSize: data.count,
            dimensions: dimensions
        )
        
        // Store in memory
        attachments[id] = attachment
        
        logger.debug("Added image: \(id, privacy: .public), size: \(data.count) bytes, type: \(mediaType, privacy: .public)")
        
        return attachment
    }
    
    /// Add image from clipboard.
    /// - Returns: The created ImageAttachment, or nil if no image on clipboard
    /// - Throws: ImageError if image is too large or cannot be processed
    func addImageFromClipboard() throws -> ImageAttachment? {
        guard let image = UIPasteboard.general.image else {
            return nil
        }
        
        // Convert to JPEG data (clipboard images don't have inherent format)
        guard let data = image.jpegData(compressionQuality: 1.0) else {
            throw ImageError.encodingFailed
        }
        
        return try addImage(from: data, mediaType: "image/jpeg")
    }
    
    /// Get attachment by UUID.
    /// - Parameter id: The attachment's unique identifier
    /// - Returns: The attachment if found, nil otherwise
    func attachment(for id: UUID) -> ImageAttachment? {
        return attachments[id]
    }
    
    /// Get multiple attachments by UUIDs.
    /// - Parameter ids: Array of attachment UUIDs
    /// - Returns: Array of attachments that were found (in order, skipping missing)
    func attachments(for ids: [UUID]) -> [ImageAttachment] {
        return ids.compactMap { attachments[$0] }
    }
    
    /// Remove a single attachment and delete its temp file.
    /// - Parameter id: The attachment's unique identifier
    func remove(_ id: UUID) {
        guard let attachment = attachments.removeValue(forKey: id) else { return }
        
        // Delete temp file
        try? FileManager.default.removeItem(at: attachment.tempFileURL)
        
        // Delete thumbnail if exists
        if let thumbnailURL = attachment.thumbnailURL {
            try? FileManager.default.removeItem(at: thumbnailURL)
        }
        
        logger.debug("Removed image: \(id, privacy: .public)")
    }
    
    /// Clear all attachments and delete all temp files.
    /// Called on app termination or memory pressure.
    /// Posts `imageAttachmentsCleared` notification so observers can update their state.
    func clearAll() {
        let count = attachments.count
        guard count > 0 else { return }
        
        // Delete all temp files
        for (_, attachment) in attachments {
            try? FileManager.default.removeItem(at: attachment.tempFileURL)
            if let thumbnailURL = attachment.thumbnailURL {
                try? FileManager.default.removeItem(at: thumbnailURL)
            }
        }
        
        // Clear dictionary
        attachments.removeAll()
        
        // Also clean up the entire images directory
        try? FileManager.default.removeItem(at: imagesDirectory)
        try? FileManager.default.createDirectory(
            at: imagesDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        
        logger.info("Cleared all \(count) images")
        
        // Notify observers (e.g., ClawdyViewModel) to clear their pending images
        NotificationCenter.default.post(name: .imageAttachmentsCleared, object: nil)
    }
    
    /// Number of stored attachments
    var count: Int {
        attachments.count
    }
    
    /// All stored attachment IDs
    var allIds: [UUID] {
        Array(attachments.keys)
    }
    
    // MARK: - Private Methods
    
    /// Validate that image data doesn't exceed size limit.
    /// - Parameter data: Image data to validate
    /// - Throws: ImageError.tooLarge if exceeds limit
    private func validateSize(_ data: Data) throws {
        if data.count > Self.maxImageSize {
            throw ImageError.tooLarge(size: data.count, limit: Self.maxImageSize)
        }
    }
}

// MARK: - ImageError

/// Errors that can occur during image handling
enum ImageError: LocalizedError {
    /// Image exceeds the maximum allowed size
    case tooLarge(size: Int, limit: Int)
    
    /// Image format is not supported
    case unsupportedFormat(String)
    
    /// Failed to load image from disk or memory
    case loadFailed
    
    /// Failed to encode image to required format
    case encodingFailed
    
    var errorDescription: String? {
        switch self {
        case .tooLarge(let size, let limit):
            let sizeMB = size / 1_000_000
            let limitMB = limit / 1_000_000
            return "Image is \(sizeMB)MB, exceeds \(limitMB)MB limit"
        case .unsupportedFormat(let format):
            return "Unsupported image format: \(format)"
        case .loadFailed:
            return "Failed to load image"
        case .encodingFailed:
            return "Failed to encode image"
        }
    }
}
