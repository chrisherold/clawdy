import Foundation
import Network
import OSLog
import Combine

/// VPN connection status
enum VPNStatus: Equatable {
    case connected(interfaceName: String)
    case disconnected
    case unknown

    var isConnected: Bool {
        if case .connected = self {
            return true
        }
        return false
    }

    var displayText: String {
        switch self {
        case .connected(let interfaceName):
            return "VPN: \(interfaceName)"
        case .disconnected:
            return "VPN Disconnected"
        case .unknown:
            return "VPN Unknown"
        }
    }
}

/// Monitors VPN connection status by checking for VPN-related network interfaces.
/// Uses Network framework's NWPathMonitor to detect interface changes.
@MainActor
class VPNStatusMonitor: ObservableObject {
    static let shared = VPNStatusMonitor()
    private let logger = Logger(subsystem: "com.clawdy", category: "vpn-monitor")

    @Published private(set) var status: VPNStatus = .unknown

    private var pathMonitor: NWPathMonitor?
    private let monitorQueue = DispatchQueue(label: "com.clawdy.vpnmonitor")

    /// Common VPN interface name prefixes
    private let vpnInterfacePrefixes = [
        "utun",     // macOS/iOS VPN tunnels (WireGuard, Tailscale, etc.)
        "ipsec",    // IPSec VPN
        "ppp",      // Point-to-Point Protocol VPN
        "tun",      // TUN/TAP interfaces
        "tap"       // TAP interfaces
    ]

    /// Known VPN service interface patterns
    private let vpnServicePatterns = [
        "tailscale",    // Tailscale VPN
        "wireguard",    // WireGuard VPN
        "nordvpn",      // NordVPN
        "expressvpn"    // ExpressVPN
    ]

    private init() {
        startMonitoring()
    }

    // Note: deinit not used since this is a singleton with @MainActor

    /// Start monitoring network path for VPN interface changes
    func startMonitoring() {
        guard pathMonitor == nil else { return }

        pathMonitor = NWPathMonitor()
        pathMonitor?.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                self?.updateVPNStatus(from: path)
            }
        }
        pathMonitor?.start(queue: monitorQueue)

        logger.info("Started monitoring")
    }

    /// Stop monitoring network path changes
    func stopMonitoring() {
        pathMonitor?.cancel()
        pathMonitor = nil
        logger.info("Stopped monitoring")
    }

    /// Manually trigger a status check
    func checkStatus() {
        guard let monitor = pathMonitor else {
            // Create temporary monitor to check current state
            let tempMonitor = NWPathMonitor()
            tempMonitor.pathUpdateHandler = { [weak self] path in
                Task { @MainActor in
                    self?.updateVPNStatus(from: path)
                }
                tempMonitor.cancel()
            }
            tempMonitor.start(queue: monitorQueue)
            return
        }

        // Force update with current path
        let path = monitor.currentPath
        updateVPNStatus(from: path)
    }

    /// Update VPN status based on network path interfaces
    private func updateVPNStatus(from path: NWPath) {
        let previousStatus = status

        // Check if we have network connectivity first
        guard path.status == .satisfied else {
            status = .disconnected
            if previousStatus != .disconnected {
                logger.info("No network connectivity")
            }
            return
        }

        // Check available interfaces for VPN tunnels
        let interfaces = path.availableInterfaces

        for interface in interfaces {
            let name = interface.name.lowercased()

            // Check for common VPN interface prefixes
            for prefix in vpnInterfacePrefixes {
                if name.hasPrefix(prefix) {
                    let newStatus = VPNStatus.connected(interfaceName: formatInterfaceName(interface.name))
                    if status != newStatus {
                        status = newStatus
                        logger.info("VPN detected: \(interface.name, privacy: .public)")
                    } else {
                        status = newStatus
                    }
                    return
                }
            }

            // Check for known VPN service patterns
            for pattern in vpnServicePatterns {
                if name.contains(pattern) {
                    let newStatus = VPNStatus.connected(interfaceName: formatInterfaceName(interface.name))
                    if status != newStatus {
                        status = newStatus
                        logger.info("VPN service detected: \(interface.name, privacy: .public)")
                    } else {
                        status = newStatus
                    }
                    return
                }
            }
        }

        // No VPN interface found
        if status != .disconnected {
            logger.debug("No VPN interface found. Interfaces: \(interfaces.map { $0.name }.joined(separator: ", "), privacy: .public)")
        }
        status = .disconnected
    }

    /// Format interface name for display
    private func formatInterfaceName(_ name: String) -> String {
        // Try to identify the VPN type from the interface name
        let lowercased = name.lowercased()

        if lowercased.hasPrefix("utun") {
            // Could be Tailscale, WireGuard, or other tunnel
            // Try to identify by checking system configuration
            return detectVPNService() ?? "VPN"
        }

        if lowercased.contains("tailscale") { return "Tailscale" }
        if lowercased.contains("wireguard") { return "WireGuard" }
        if lowercased.hasPrefix("ipsec") { return "IPSec" }
        if lowercased.hasPrefix("ppp") { return "PPP VPN" }

        return "VPN"
    }

    /// Attempt to detect which VPN service is running
    /// This checks for common VPN service processes/indicators
    private func detectVPNService() -> String? {
        // Check for Tailscale by looking for its characteristic behavior
        // Tailscale uses utun interfaces and has a specific IP range (100.x.x.x)

        // For now, return a generic name
        // Future enhancement: could check NEVPNManager configurations
        return nil
    }
}

// MARK: - NWPath Extension

extension NWPath {
    /// Get all available interfaces as a string for debugging
    var interfaceSummary: String {
        availableInterfaces.map { "\($0.name) (\($0.type))" }.joined(separator: ", ")
    }
}
