import Foundation
import AVFoundation
import OSLog
import Photos
import UIKit

/// Coordinates image picker UI state and permission handling.
/// Manages action sheet display, photo library picker, and camera access.
@MainActor
class ImagePickerCoordinator: ObservableObject {
    private let logger = Logger(subsystem: "com.clawdy", category: "image-picker")
    
    /// Whether to show the photo library picker
    @Published var showingPhotoPicker = false
    
    /// Whether to show the camera view
    @Published var showingCamera = false
    
    /// Permission alert to display, if any
    @Published var permissionAlert: PermissionAlertType? = nil
    
    /// Types of permission alerts that can be shown
    enum PermissionAlertType: Identifiable {
        case camera
        case photos
        
        var id: Self { self }
        
        var title: String {
            switch self {
            case .camera:
                return "Camera Access Required"
            case .photos:
                return "Photo Library Access Required"
            }
        }
        
        var message: String {
            switch self {
            case .camera:
                return "Please enable camera access in Settings to take photos."
            case .photos:
                return "Please enable photo library access in Settings to select images."
            }
        }
    }
    
    // MARK: - Public Methods
    
    /// Handle user's selection from the image source menu.
    /// - Parameter selection: The image source selected (photo library or camera)
    func handleMenuSelection(_ selection: ImageSource) {
        switch selection {
        case .photoLibrary:
            checkPhotoPermission()
        case .camera:
            checkCameraPermission()
        }
    }
    
    // MARK: - Private Methods
    
    /// Check and request photo library permission, then show picker if authorized.
    private func checkPhotoPermission() {
        let status = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        
        switch status {
        case .authorized, .limited:
            showingPhotoPicker = true
            
        case .notDetermined:
            Task {
                let newStatus = await PHPhotoLibrary.requestAuthorization(for: .readWrite)
                await MainActor.run {
                    switch newStatus {
                    case .authorized, .limited:
                        showingPhotoPicker = true
                    case .denied, .restricted:
                        permissionAlert = .photos
                    case .notDetermined:
                        break
                    @unknown default:
                        break
                    }
                }
            }
            
        case .denied, .restricted:
            permissionAlert = .photos
            
        @unknown default:
            break
        }
    }
    
    /// Check and request camera permission, then show camera if authorized.
    private func checkCameraPermission() {
        // First check if camera is available
        guard UIImagePickerController.isSourceTypeAvailable(.camera) else {
            // Camera not available (e.g., Simulator)
            logger.warning("Camera not available on this device")
            return
        }
        
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        
        switch status {
        case .authorized:
            // Already have access, show camera
            showingCamera = true
            
        case .notDetermined:
            // Request permission
            Task {
                let granted = await AVCaptureDevice.requestAccess(for: .video)
                await MainActor.run {
                    if granted {
                        showingCamera = true
                    } else {
                        permissionAlert = .camera
                    }
                }
            }
            
        case .denied, .restricted:
            // Permission denied, show alert
            permissionAlert = .camera
            
        @unknown default:
            break
        }
    }
}

// MARK: - ImageSource

/// Source options for selecting images
enum ImageSource {
    case photoLibrary
    case camera
}
