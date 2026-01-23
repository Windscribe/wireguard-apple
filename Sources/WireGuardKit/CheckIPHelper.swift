// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import os.log

#if SWIFT_PACKAGE
import WireGuardKitGo
import WireGuardKitC
#endif

public class CheckIPHelper {

    private var isSetup = false

    public init() {}

    /// Setup the CheckIP tunnel using the same configuration as the main tunnel
    /// - Parameters:
    ///   - tunnelConfiguration: The WireGuard tunnel configuration
    ///   - completion: Called with error if setup fails
    public func setup(tunnelConfiguration: TunnelConfiguration, completion: @escaping (Error?) -> Void) {
        os_log("PacketTunnelProvider CheckIP setup starting", log: OSLog.default, type: .info)

        // Get the local IP from the tunnel configuration
        guard let localAddress = tunnelConfiguration.interface.addresses.first else {
            os_log("PacketTunnelProvider CheckIP setup failed: no local address", log: OSLog.default, type: .error)
            completion(CheckIPError.noLocalAddress)
            return
        }

        let localIP = "\(localAddress.address)"
        os_log("PacketTunnelProvider CheckIP using local IP: %{public}@", log: OSLog.default, type: .info, localIP)

        // Use a DNS server (can use any, but 8.8.8.8 is reliable)
        let dnsServer = "8.8.8.8"

        // Resolve peer endpoints (DNS resolution)
        os_log("PacketTunnelProvider CheckIP resolving endpoints...", log: OSLog.default, type: .info)
        let endpoints = tunnelConfiguration.peers.map { $0.endpoint }
        let resolutionResults = DNSResolver.resolveSync(endpoints: endpoints)

        // Check for DNS resolution errors
        let resolutionErrors = resolutionResults.compactMap { result -> DNSResolutionError? in
            if case .failure(let error) = result {
                return error
            }
            return nil
        }

        if !resolutionErrors.isEmpty {
            let errorMessages = resolutionErrors.map { $0.errorDescription ?? "unknown" }.joined(separator: ", ")
            os_log("PacketTunnelProvider CheckIP DNS resolution failed: %{public}@", log: OSLog.default, type: .error, errorMessages)
            completion(CheckIPError.dnsResolutionFailed(errorMessages))
            return
        }

        // Extract resolved endpoints
        let resolvedEndpoints = resolutionResults.map { result -> Endpoint? in
            return try? result?.get()
        }

        os_log("PacketTunnelProvider CheckIP endpoints resolved", log: OSLog.default, type: .info)

        // Convert tunnel configuration to WireGuard format
        let (wgConfig, _) = PacketTunnelSettingsGenerator(
            tunnelConfiguration: tunnelConfiguration,
            resolvedEndpoints: resolvedEndpoints
        ).uapiConfiguration()

        os_log("PacketTunnelProvider CheckIP calling wgSetupCheckIPTunnel", log: OSLog.default, type: .info)

        // Call the Go function to setup the tunnel
        let result = wgSetupCheckIPTunnel(localIP, dnsServer, wgConfig)

        if result == 0 {
            isSetup = true
            os_log("PacketTunnelProvider CheckIP tunnel ready", log: OSLog.default, type: .info)
            completion(nil)
        } else {
            os_log("PacketTunnelProvider CheckIP setup failed with code: %d", log: OSLog.default, type: .error, result)
            completion(CheckIPError.setupFailed(code: result))
        }
    }

    /// Check the public IP address by making a request through the WireGuard tunnel
    /// - Parameter completion: Called with the IP address string or error
    public func checkIP(completion: @escaping (Result<String, Error>) -> Void) {
        guard isSetup else {
            os_log("PacketTunnelProvider CheckIP request failed: tunnel not setup", log: OSLog.default, type: .error)
            completion(.failure(CheckIPError.notSetup))
            return
        }

        os_log("PacketTunnelProvider CheckIP request starting", log: OSLog.default, type: .info)

        DispatchQueue.global(qos: .userInitiated).async {
            // Call the Go function to check IP
            guard let cString = wgCheckIP() else {
                os_log("PacketTunnelProvider CheckIP request failed: null response", log: OSLog.default, type: .error)
                DispatchQueue.main.async {
                    completion(.failure(CheckIPError.requestFailed))
                }
                return
            }

            let result = String(cString: cString)
            free(cString)

            DispatchQueue.main.async {
                // Check if response is an error
                if result.hasPrefix("error:") {
                    os_log("PacketTunnelProvider CheckIP request failed: %{public}@", log: OSLog.default, type: .error, result)
                    completion(.failure(CheckIPError.requestError(result)))
                } else {
                    // Return the IP address
                    os_log("PacketTunnelProvider CheckIP got IP: %{public}@", log: OSLog.default, type: .info, result)
                    completion(.success(result))
                }
            }
        }
    }

    /// Cleanup the CheckIP tunnel
    public func cleanup() {
        if isSetup {
            os_log("PacketTunnelProvider CheckIP cleanup started", log: OSLog.default, type: .info)
            wgCleanupCheckIPTunnel()
            isSetup = false
            os_log("PacketTunnelProvider CheckIP cleanup complete", log: OSLog.default, type: .info)
        }
    }

    deinit {
        cleanup()
    }
}

public enum CheckIPError: Error, LocalizedError {
    case noLocalAddress
    case dnsResolutionFailed(String)
    case setupFailed(code: Int32)
    case notSetup
    case requestFailed
    case requestError(String)

    public var errorDescription: String? {
        switch self {
        case .noLocalAddress:
            return "No local address configured in tunnel"
        case .dnsResolutionFailed(let message):
            return "DNS resolution failed: \(message)"
        case .setupFailed(let code):
            return "Setup failed with code: \(code)"
        case .notSetup:
            return "CheckIP tunnel not setup. Call setup() first"
        case .requestFailed:
            return "Request failed"
        case .requestError(let message):
            return message
        }
    }
}
