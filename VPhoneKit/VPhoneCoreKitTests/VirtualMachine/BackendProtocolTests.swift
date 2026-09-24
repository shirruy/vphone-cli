import Foundation
import Testing
@testable import VPhoneCoreKit

struct BackendProtocolTests {
    private var fixtureURL: URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 {
            url.deleteLastPathComponent()
        }
        return url.appendingPathComponent("protocol/fixtures/backend_request_v1_boot.json")
    }

    @Test func `v1 fixture decodes and preserves existing boot arguments`() throws {
        let data = try Data(contentsOf: fixtureURL)
        let request = try VPhoneBackendRequest.decodeJSON(data)

        #expect(request.protocolVersion == 1)
        #expect(request.operation == .boot)
        #expect(request.boot?.config == "/tmp/vphone/demo/config.plist")
        #expect(request.boot?.dfu == false)
        #expect(request.boot?.headless == true)
        #expect(request.boot?.apiListen == "127.0.0.1:8765")
        #expect(request.boot?.kernelDebugPort == 62000)
        #expect(request.boot?.vphonedBin == ".vphoned.signed")
        #expect(request.boot?.installIPA == nil)

        let command = try request.bootCommand()
        #expect(command.bootArguments == [
            "--config", "/tmp/vphone/demo/config.plist",
            "--headless",
            "--api-listen", "127.0.0.1:8765",
            "--kernel-debug-port", "62000",
        ])
    }

    @Test func `existing command round trips through backend protocol`() throws {
        let original = VPhoneBootCommand(
            config: URL(fileURLWithPath: "/tmp/vphone/config.plist"),
            dfu: false,
            headless: true,
            apiListen: "127.0.0.1:9000",
            kernelDebugPort: 62001,
            vphonedBin: "/tmp/vphoned.signed",
            installIPA: URL(fileURLWithPath: "/tmp/Test.ipa")
        )

        let request = VPhoneBackendRequest(bootCommand: original)
        let encoded = try request.encodedJSON()
        let decoded = try VPhoneBackendRequest.decodeJSON(encoded)
        let reconstructed = try decoded.bootCommand()

        #expect(reconstructed.bootArguments == original.bootArguments)
    }

    @Test func `unsupported protocol version fails closed`() {
        let request = VPhoneBackendRequest(
            protocolVersion: 999,
            operation: .boot,
            boot: .init(config: "/tmp/config.plist")
        )

        #expect(throws: VPhoneBackendProtocolError.unsupportedVersion(999)) {
            try request.validate()
        }
    }

    @Test func `DFU request rejects guest API and package install`() {
        let apiRequest = VPhoneBackendRequest(
            operation: .boot,
            boot: .init(config: "/tmp/config.plist", dfu: true, apiListen: "127.0.0.1:1")
        )
        #expect(throws: (any Error).self) {
            try apiRequest.validate()
        }

        let ipaRequest = VPhoneBackendRequest(
            operation: .boot,
            boot: .init(config: "/tmp/config.plist", dfu: true, installIPA: "/tmp/Test.ipa")
        )
        #expect(throws: (any Error).self) {
            try ipaRequest.validate()
        }
    }
}
