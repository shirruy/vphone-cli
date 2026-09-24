import Foundation

/// Versioned, platform-neutral request passed across the vphone-cli -> VM backend seam.
///
/// Phase 2 intentionally models the existing boot semantics rather than replacing
/// them. The macOS Virtualization.framework runtime and the Windows research
/// backend can therefore share one wire contract while retaining different
/// implementations behind it.
public struct VPhoneBackendRequest: Codable, Equatable, Sendable {
    public static let currentProtocolVersion = 1

    public enum Operation: String, Codable, Sendable {
        case boot
    }

    public struct Boot: Codable, Equatable, Sendable {
        public var config: String
        public var dfu: Bool
        public var headless: Bool
        public var apiListen: String?
        public var kernelDebugPort: Int?
        public var vphonedBin: String
        public var installIPA: String?

        enum CodingKeys: String, CodingKey {
            case config
            case dfu
            case headless
            case apiListen = "api_listen"
            case kernelDebugPort = "kernel_debug_port"
            case vphonedBin = "vphoned_bin"
            case installIPA = "install_ipa"
        }

        public init(
            config: String,
            dfu: Bool = false,
            headless: Bool = false,
            apiListen: String? = nil,
            kernelDebugPort: Int? = nil,
            vphonedBin: String = ".vphoned.signed",
            installIPA: String? = nil
        ) {
            self.config = config
            self.dfu = dfu
            self.headless = headless
            self.apiListen = apiListen
            self.kernelDebugPort = kernelDebugPort
            self.vphonedBin = vphonedBin
            self.installIPA = installIPA
        }
    }

    public var protocolVersion: Int
    public var operation: Operation
    public var boot: Boot?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case operation
        case boot
    }

    public init(protocolVersion: Int = Self.currentProtocolVersion, operation: Operation, boot: Boot?) {
        self.protocolVersion = protocolVersion
        self.operation = operation
        self.boot = boot
    }

    public init(bootCommand: VPhoneBootCommand) {
        self.init(
            operation: .boot,
            boot: Boot(
                config: bootCommand.config.path,
                dfu: bootCommand.dfu,
                headless: bootCommand.headless,
                apiListen: bootCommand.apiListen,
                kernelDebugPort: bootCommand.kernelDebugPort,
                vphonedBin: bootCommand.vphonedBin,
                installIPA: bootCommand.installIPA?.path
            )
        )
    }

    @discardableResult
    public func validate() throws -> Self {
        guard protocolVersion == Self.currentProtocolVersion else {
            throw VPhoneBackendProtocolError.unsupportedVersion(protocolVersion)
        }

        switch operation {
        case .boot:
            guard let boot else {
                throw VPhoneBackendProtocolError.invalidRequest("boot operation requires a boot payload")
            }
            guard !boot.config.isEmpty else {
                throw VPhoneBackendProtocolError.invalidRequest("boot.config must not be empty")
            }
            if boot.dfu, boot.apiListen != nil {
                throw VPhoneBackendProtocolError.invalidRequest("api_listen is unavailable in DFU mode")
            }
            if boot.dfu, boot.installIPA != nil {
                throw VPhoneBackendProtocolError.invalidRequest("install_ipa is unavailable in DFU mode")
            }
        }

        return self
    }

    public func encodedJSON() throws -> Data {
        try validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    public static func decodeJSON(_ data: Data) throws -> Self {
        let value = try JSONDecoder().decode(Self.self, from: data)
        return try value.validate()
    }

    /// Reconstruct the existing command declaration from the protocol request.
    /// This is the compatibility invariant for the current macOS backend.
    public func bootCommand() throws -> VPhoneBootCommand {
        try validate()
        guard operation == .boot, let boot else {
            throw VPhoneBackendProtocolError.invalidRequest("request is not a boot request")
        }
        return VPhoneBootCommand(
            config: URL(fileURLWithPath: boot.config),
            dfu: boot.dfu,
            headless: boot.headless,
            apiListen: boot.apiListen,
            kernelDebugPort: boot.kernelDebugPort,
            vphonedBin: boot.vphonedBin,
            installIPA: boot.installIPA.map(URL.init(fileURLWithPath:))
        )
    }
}

public enum VPhoneBackendProtocolError: Error, Equatable, CustomStringConvertible {
    case unsupportedVersion(Int)
    case invalidRequest(String)

    public var description: String {
        switch self {
        case let .unsupportedVersion(version):
            return "unsupported backend protocol version: \(version)"
        case let .invalidRequest(message):
            return "invalid backend request: \(message)"
        }
    }
}
