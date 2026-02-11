import Foundation
import OSLog
import UIKit
import ImageIO

private let imageLogger = Logger(subsystem: "com.clawdy", category: "image-attachment")

/// Represents an image attached to a message.
/// Images are stored as temp files and are session-only (not persisted across app launches).
///
/// Edge Case Handling:
/// - Very small images (<1KB): Allowed, no minimum size requirement
/// - Animated GIFs: First frame is extracted for static display (full GIF sent to Pi)
/// - EXIF orientation: UIImage automatically handles orientation; thumbnails respect it
/// - Photo picker cancellation: Preserves existing pendingImages (handled by ContentView)
struct ImageAttachment: Identifiable, Equatable {
    let id: UUID
    let tempFileURL: URL        // Path to full-size image in temp directory
    let thumbnailURL: URL?      // Path to generated thumbnail (lazy, may not exist yet)
    let mediaType: String       // MIME type: "image/jpeg", "image/png", etc.
    let originalSize: Int       // File size in bytes for validation
    let dimensions: CGSize      // Width x Height for layout calculations
    
    /// Maximum thumbnail size in points (will be 2x for retina)
    static let thumbnailMaxSize: CGFloat = 160
    
    /// Thumbnail JPEG quality
    static let thumbnailQuality: CGFloat = 0.8
    
    /// Initialize with all properties
    init(
        id: UUID = UUID(),
        tempFileURL: URL,
        thumbnailURL: URL? = nil,
        mediaType: String,
        originalSize: Int,
        dimensions: CGSize
    ) {
        self.id = id
        self.tempFileURL = tempFileURL
        self.thumbnailURL = thumbnailURL
        self.mediaType = mediaType
        self.originalSize = originalSize
        self.dimensions = dimensions
    }
    
    /// Load thumbnail image for display in UI (lazy loading).
    /// Returns cached thumbnail if available, or generates one on-demand.
    func loadThumbnail() -> UIImage? {
        // First try to load from cached thumbnail file
        if let thumbnailURL = thumbnailURL,
           FileManager.default.fileExists(atPath: thumbnailURL.path),
           let thumbnailData = try? Data(contentsOf: thumbnailURL),
           let thumbnail = UIImage(data: thumbnailData) {
            return thumbnail
        }
        
        // Fall back to generating thumbnail from full image
        guard let fullImage = loadFullImage() else { return nil }
        return generateThumbnail(from: fullImage)
    }
    
    /// Load full image for Quick Look or base64 encoding.
    /// For animated GIFs, this loads the first frame as a static UIImage.
    /// UIImage automatically handles EXIF orientation metadata.
    func loadFullImage() -> UIImage? {
        guard FileManager.default.fileExists(atPath: tempFileURL.path),
              let data = try? Data(contentsOf: tempFileURL) else {
            return nil
        }
        
        // For GIFs, extract the first frame to ensure we get a valid static image
        // (UIImage from GIF data may not render correctly in all contexts)
        if mediaType == "image/gif" {
            return Self.extractFirstFrame(from: data) ?? UIImage(data: data)
        }
        
        return UIImage(data: data)
    }
    
    /// Maximum dimension for images uploaded to Pi.
    /// 2048px is plenty for AI vision analysis while keeping file sizes reasonable.
    private static let maxDimensionForUpload: CGFloat = 2048
    
    /// JPEG quality for resized uploads
    private static let jpegUploadQuality: CGFloat = 0.85

    /// Target max payload size for uploads (~350 KB)
    private static let maxUploadBytes: Int = 350 * 1024
    
    /// Get image data for SFTP upload.
    /// Images larger than 2048px are resized and compressed to fit ~350 KB.
    /// Returns nil if the image cannot be loaded.
    func getDataForUpload() -> Data? {
        do {
            let originalData = try Data(contentsOf: tempFileURL)
            
            guard let image = UIImage(data: originalData) else {
                imageLogger.error("Failed to create UIImage from data")
                return originalData
            }
            
            let maxDim = max(image.size.width, image.size.height)
            let maxBytes = Self.maxUploadBytes

            if maxDim <= Self.maxDimensionForUpload && originalData.count <= maxBytes {
                return originalData
            }

            var workingImage = image

            if maxDim > Self.maxDimensionForUpload {
                let scale = Self.maxDimensionForUpload / maxDim
                let newSize = CGSize(width: image.size.width * scale, height: image.size.height * scale)

                let renderer = UIGraphicsImageRenderer(size: newSize)
                workingImage = renderer.image { _ in
                    image.draw(in: CGRect(origin: .zero, size: newSize))
                }
            }

            if let compressed = compressToTarget(workingImage, maxBytes: maxBytes) {
                return compressed
            }

            return originalData
            
        } catch {
            return nil
        }
    }
    
    /// Generate base64 data string for RPC payload.
    /// Returns nil if the image cannot be loaded or encoded.
    func toBase64() -> String? {
        guard let data = getDataForUpload() else {
            return nil
        }
        let base64 = data.base64EncodedString()
        imageLogger.debug("Encoded: \(data.count) bytes -> \(base64.count) base64 chars")
        return base64
    }
    
    private func compressToTarget(_ image: UIImage, maxBytes: Int) -> Data? {
        let qualities: [CGFloat] = [0.85, 0.75, 0.65, 0.55, 0.45, 0.35, 0.25, 0.2]
        var bestData: Data?

        for quality in qualities {
            if let data = image.jpegData(compressionQuality: quality) {
                bestData = data
                if data.count <= maxBytes {
                    return data
                }
            }
        }

        return bestData
    }

    /// Generate a thumbnail from the full image.
    /// Scales image to fit within thumbnailMaxSize while maintaining aspect ratio.
    /// UIGraphicsImageRenderer automatically respects UIImage's imageOrientation,
    /// so EXIF-rotated images will render correctly in thumbnails.
    private func generateThumbnail(from image: UIImage) -> UIImage? {
        let maxSize = Self.thumbnailMaxSize * UIScreen.main.scale // Account for retina
        
        let originalWidth = image.size.width
        let originalHeight = image.size.height
        
        // Handle very small images (< 1KB) - allow them without upscaling
        // Small images are valid and useful (e.g., icons, small screenshots)
        guard originalWidth > 0 && originalHeight > 0 else { return nil }
        
        // Calculate scale to fit within max size
        let widthRatio = maxSize / originalWidth
        let heightRatio = maxSize / originalHeight
        let scale = min(widthRatio, heightRatio, 1.0) // Don't upscale
        
        let newSize = CGSize(
            width: originalWidth * scale,
            height: originalHeight * scale
        )
        
        // Use UIGraphicsImageRenderer which properly handles:
        // - EXIF orientation metadata (auto-applied by UIImage)
        // - High DPI/retina display
        // - Color space management
        let renderer = UIGraphicsImageRenderer(size: newSize)
        let thumbnail = renderer.image { _ in
            image.draw(in: CGRect(origin: .zero, size: newSize))
        }
        
        return thumbnail
    }
    
    /// Save thumbnail to disk and return updated attachment with thumbnail URL.
    /// Returns self if thumbnail generation fails.
    func withSavedThumbnail() -> ImageAttachment {
        guard thumbnailURL == nil,
              let fullImage = loadFullImage(),
              let thumbnail = generateThumbnail(from: fullImage),
              let thumbnailData = thumbnail.jpegData(compressionQuality: Self.thumbnailQuality) else {
            return self
        }
        
        // Generate thumbnail URL
        let directory = tempFileURL.deletingLastPathComponent()
        let baseName = tempFileURL.deletingPathExtension().lastPathComponent
        let ext = tempFileURL.pathExtension
        let newThumbnailURL = directory.appendingPathComponent("\(baseName)_thumb.\(ext)")
        
        do {
            try thumbnailData.write(to: newThumbnailURL)
            return ImageAttachment(
                id: id,
                tempFileURL: tempFileURL,
                thumbnailURL: newThumbnailURL,
                mediaType: mediaType,
                originalSize: originalSize,
                dimensions: dimensions
            )
        } catch {
            imageLogger.error("Failed to save thumbnail: \(error.localizedDescription)")
            return self
        }
    }
    
    // MARK: - Equatable
    
    static func == (lhs: ImageAttachment, rhs: ImageAttachment) -> Bool {
        lhs.id == rhs.id
    }
}

// MARK: - GIF Frame Extraction

extension ImageAttachment {
    /// Extract the first frame from an animated GIF.
    /// This ensures we have a valid static image for display and thumbnail generation.
    /// - Parameter data: The raw GIF data
    /// - Returns: The first frame as a UIImage, or nil if extraction fails
    static func extractFirstFrame(from data: Data) -> UIImage? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil) else {
            return nil
        }
        
        // Get the first frame (index 0)
        guard CGImageSourceGetCount(source) > 0,
              let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil) else {
            return nil
        }
        
        return UIImage(cgImage: cgImage)
    }
}

// MARK: - Media Type Detection

extension ImageAttachment {
    /// Detect media type from raw image data by checking magic bytes.
    /// Returns "image/jpeg" as default if format cannot be determined.
    static func detectMediaType(from data: Data) -> String {
        guard data.count >= 12 else { return "image/jpeg" }
        
        var bytes = [UInt8](repeating: 0, count: 12)
        data.copyBytes(to: &bytes, count: 12)
        
        // JPEG: FF D8 FF
        if bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF {
            return "image/jpeg"
        }
        
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47 {
            return "image/png"
        }
        
        // GIF: 47 49 46 38 (GIF8)
        if bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x38 {
            return "image/gif"
        }
        
        // WebP: RIFF....WEBP
        if bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && bytes[3] == 0x46 &&
           bytes[8] == 0x57 && bytes[9] == 0x45 && bytes[10] == 0x42 && bytes[11] == 0x50 {
            return "image/webp"
        }
        
        // Default to JPEG if unknown
        return "image/jpeg"
    }
    
    /// Get file extension for a given media type.
    static func fileExtension(for mediaType: String) -> String {
        switch mediaType {
        case "image/jpeg": return "jpg"
        case "image/png": return "png"
        case "image/gif": return "gif"
        case "image/webp": return "webp"
        default: return "jpg"
        }
    }
}

// MARK: - Dimensions Helper

extension ImageAttachment {
    /// Extract dimensions from image data without fully loading the image.
    /// Properly handles EXIF orientation metadata to return the correct user-visible dimensions.
    /// Falls back to CGSize.zero if dimensions cannot be determined.
    static func extractDimensions(from data: Data) -> CGSize {
        guard let imageSource = CGImageSourceCreateWithData(data as CFData, nil),
              let properties = CGImageSourceCopyPropertiesAtIndex(imageSource, 0, nil) as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? CGFloat,
              let height = properties[kCGImagePropertyPixelHeight] as? CGFloat else {
            // Fallback: load image to get size (UIImage handles EXIF orientation)
            if let image = UIImage(data: data) {
                return image.size
            }
            return .zero
        }
        
        // Check EXIF orientation to determine if width/height should be swapped.
        // Orientations 5-8 have the image rotated 90° or 270°, swapping width and height.
        // See: https://developer.apple.com/documentation/imageio/cgimagepropertyorientation
        if let orientation = properties[kCGImagePropertyOrientation] as? Int {
            // Orientations 5, 6, 7, 8 are rotated 90° or 270° (width/height swapped)
            if orientation >= 5 && orientation <= 8 {
                return CGSize(width: height, height: width)
            }
        }
        
        return CGSize(width: width, height: height)
    }
}
