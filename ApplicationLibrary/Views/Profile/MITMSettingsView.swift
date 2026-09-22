#if os(iOS) || os(macOS)
    import Foundation
    import Libbox
    import Library
    import SwiftUI
    import UniformTypeIdentifiers

    private struct MITMTextEntry: Identifiable, Hashable {
        let id: UUID
        var value: String

        init(_ value: String = "") {
            id = UUID()
            self.value = value
        }
    }

    private struct MITMScriptBinding: Identifiable {
        let id = UUID()
        var raw: [String: Any]
        var tag: String
        var event: Event
        var patterns: [MITMTextEntry]
        var timeout: String
        var requiresBody: Bool
        var maxSize: String
        var binaryBodyMode: Bool
        var fullHeaderMode: Bool
        var arguments: [MITMTextEntry]

        enum Event: String, CaseIterable, Identifiable {
            case request
            case response
            case both

            var id: Self { self }

            var title: String {
                switch self {
                case .request: return String(localized: "Request")
                case .response: return String(localized: "Response")
                case .both: return String(localized: "Both")
                }
            }
        }

        init(_ object: [String: Any] = [:]) {
            raw = object
            tag = object["tag"] as? String ?? ""
            let types = Self.stringArray(object["type"])
            if types.contains("http-request"), types.contains("http-response") {
                event = .both
            } else if types.contains("http-response") {
                event = .response
            } else {
                event = .request
            }
            patterns = Self.stringArray(object["pattern"]).map(MITMTextEntry.init)
            timeout = object["timeout"] as? String ?? ""
            requiresBody = Self.bool(object["requires_body"])
            maxSize = Self.numberString(object["max_size"])
            binaryBodyMode = Self.bool(object["binary_body_mode"])
            fullHeaderMode = Self.bool(object["full_header_mode"])
            arguments = Self.stringArray(object["arguments"]).map(MITMTextEntry.init)
        }

        func object() -> [String: Any] {
            var object = raw
            object["tag"] = tag
            switch event {
            case .request: object["type"] = ["http-request"]
            case .response: object["type"] = ["http-response"]
            case .both: object["type"] = ["http-request", "http-response"]
            }
            object["pattern"] = Self.values(patterns)
            Self.assign(&object, key: "timeout", value: timeout)
            object["requires_body"] = requiresBody
            if let maxSizeValue = Int64(maxSize), maxSizeValue > 0 {
                object["max_size"] = maxSizeValue
            } else {
                object.removeValue(forKey: "max_size")
            }
            object["binary_body_mode"] = binaryBodyMode
            object["full_header_mode"] = fullHeaderMode
            let argumentValues = Self.values(arguments)
            if argumentValues.isEmpty {
                object.removeValue(forKey: "arguments")
            } else {
                object["arguments"] = argumentValues
            }
            return object
        }

        private static func stringArray(_ value: Any?) -> [String] {
            MITMJSON.stringArray(value)
        }

        private static func bool(_ value: Any?) -> Bool {
            MITMJSON.bool(value)
        }

        private static func numberString(_ value: Any?) -> String {
            MITMJSON.numberString(value)
        }

        private static func values(_ entries: [MITMTextEntry]) -> [String] {
            MITMJSON.values(entries)
        }

        private static func assign(_ object: inout [String: Any], key: String, value: String) {
            MITMJSON.assign(&object, key: key, value: value)
        }
    }

    private struct MITMRule: Identifiable {
        let id = UUID()
        var originalIndex: Int?
        var raw: [String: Any]
        var mitmRaw: [String: Any]
        var enabled: Bool
        var printTraffic: Bool
        var domains: [MITMTextEntry]
        var domainSuffixes: [MITMTextEntry]
        var urlRewrites: [MITMTextEntry]
        var headerRewrites: [MITMTextEntry]
        var bodyRewrites: [MITMTextEntry]
        var mapLocal: [MITMTextEntry]
        var scripts: [MITMScriptBinding]

        init(object: [String: Any] = [:], originalIndex: Int? = nil) {
            self.originalIndex = originalIndex
            raw = object
            let mitm = object["mitm"] as? [String: Any] ?? [:]
            mitmRaw = mitm
            enabled = MITMJSON.bool(mitm["enabled"], defaultValue: true)
            printTraffic = MITMJSON.bool(mitm["print"])
            domains = MITMJSON.stringArray(object["domain"]).map(MITMTextEntry.init)
            domainSuffixes = MITMJSON.stringArray(object["domain_suffix"]).map(MITMTextEntry.init)
            urlRewrites = MITMJSON.stringArray(mitm["surge_url_rewrite"]).map(MITMTextEntry.init)
            headerRewrites = MITMJSON.stringArray(mitm["surge_header_rewrite"]).map(MITMTextEntry.init)
            bodyRewrites = MITMJSON.stringArray(mitm["surge_body_rewrite"]).map(MITMTextEntry.init)
            mapLocal = MITMJSON.stringArray(mitm["surge_map_local"]).map(MITMTextEntry.init)
            scripts = (mitm["surge_script"] as? [[String: Any]] ?? []).map(MITMScriptBinding.init)
        }

        var displayName: String {
            let matchers = MITMJSON.values(domains) + MITMJSON.values(domainSuffixes).map { ".\($0)" }
            return matchers.first ?? String(localized: "All Domains")
        }

        func object() -> [String: Any] {
            var object = raw
            if object["action"] == nil {
                object["action"] = "route-options"
            }
            MITMJSON.assign(&object, key: "domain", values: domains)
            MITMJSON.assign(&object, key: "domain_suffix", values: domainSuffixes)

            var mitm = mitmRaw
            mitm["enabled"] = enabled
            mitm["print"] = printTraffic
            MITMJSON.assign(&mitm, key: "surge_url_rewrite", values: urlRewrites)
            MITMJSON.assign(&mitm, key: "surge_header_rewrite", values: headerRewrites)
            MITMJSON.assign(&mitm, key: "surge_body_rewrite", values: bodyRewrites)
            MITMJSON.assign(&mitm, key: "surge_map_local", values: mapLocal)
            if scripts.isEmpty {
                mitm.removeValue(forKey: "surge_script")
            } else {
                mitm["surge_script"] = scripts.map { $0.object() }
            }
            object["mitm"] = mitm
            return object
        }
    }

    private struct MITMScriptDefinition: Identifiable {
        let id = UUID()
        var originalIndex: Int?
        var raw: [String: Any]
        var tag: String
        var source: Source
        var location: String
        var downloadDetour: String
        var updateInterval: String

        enum Source: String, CaseIterable, Identifiable {
            case local
            case remote

            var id: Self { self }
            var title: String { rawValue.capitalized }
        }

        init(object: [String: Any] = [:], originalIndex: Int? = nil) {
            self.originalIndex = originalIndex
            raw = object
            tag = object["tag"] as? String ?? ""
            source = Source(rawValue: object["source"] as? String ?? "local") ?? .local
            if source == .remote {
                location = object["url"] as? String ?? ""
            } else {
                location = object["path"] as? String ?? ""
            }
            downloadDetour = object["download_detour"] as? String ?? ""
            updateInterval = object["update_interval"] as? String ?? ""
        }

        func object() -> [String: Any] {
            var object = raw
            object["type"] = "surge"
            object["tag"] = tag
            object["source"] = source.rawValue
            if source == .remote {
                object["url"] = location
                object.removeValue(forKey: "path")
                MITMJSON.assign(&object, key: "download_detour", value: downloadDetour)
                MITMJSON.assign(&object, key: "update_interval", value: updateInterval)
            } else {
                object["path"] = location
                object.removeValue(forKey: "url")
                object.removeValue(forKey: "download_detour")
                object.removeValue(forKey: "update_interval")
            }
            return object
        }
    }

    private struct MITMModule: Identifiable {
        var id: String
        var raw: [String: Any]
        var name: String
        var moduleDescription: String
        var enabled: Bool
        var url: String
        var localPath: String
        var downloadDetour: String
        var updateInterval: String
        var generatedScripts: [[String: Any]]
        var generatedRules: [[String: Any]]

        init(object: [String: Any] = [:]) {
            raw = object
            id = object["id"] as? String ?? UUID().uuidString
            name = object["name"] as? String ?? ""
            moduleDescription = object["description"] as? String ?? ""
            enabled = MITMJSON.bool(object["enabled"], defaultValue: true)
            url = object["url"] as? String ?? ""
            localPath = object["local_path"] as? String ?? ""
            downloadDetour = object["download_detour"] as? String ?? ""
            updateInterval = object["update_interval"] as? String ?? "1d"
            generatedScripts = object["scripts"] as? [[String: Any]] ?? []
            generatedRules = object["rules"] as? [[String: Any]] ?? []
        }

        init(
            payload: SurgeModulePayload,
            url: String,
            localPath: String,
            downloadDetour: String,
            updateInterval: String,
            id: String = UUID().uuidString,
            enabled: Bool = true,
            raw: [String: Any] = [:]
        ) {
            self.id = id
            self.raw = raw
            name = payload.name
            moduleDescription = payload.moduleDescription
            self.enabled = enabled
            self.url = url
            self.localPath = localPath
            self.downloadDetour = downloadDetour
            self.updateInterval = updateInterval
            generatedScripts = payload.scripts
            generatedRules = payload.rules
        }

        var displayName: String {
            name.isEmpty ? String(localized: "Untitled Module") : name
        }

        func scriptObjects() -> [[String: Any]] {
            generatedScripts.map { script in
                var script = script
                MITMJSON.assign(&script, key: "download_detour", value: downloadDetour)
                MITMJSON.assign(&script, key: "update_interval", value: updateInterval)
                return script
            }
        }

        func object() -> [String: Any] {
            var object = raw
            object["type"] = "surge"
            object["id"] = id
            object["name"] = name
            MITMJSON.assign(&object, key: "description", value: moduleDescription)
            object["enabled"] = enabled
            object["url"] = url
            MITMJSON.assign(&object, key: "local_path", value: localPath)
            MITMJSON.assign(&object, key: "download_detour", value: downloadDetour)
            MITMJSON.assign(&object, key: "update_interval", value: updateInterval)
            object["scripts"] = scriptObjects()
            object["rules"] = generatedRules
            return object
        }
    }

    private enum MITMJSON {
        static func bool(_ value: Any?, defaultValue: Bool = false) -> Bool {
            (value as? NSNumber)?.boolValue ?? value as? Bool ?? defaultValue
        }

        static func stringArray(_ value: Any?) -> [String] {
            if let string = value as? String {
                return [string]
            }
            return value as? [String] ?? []
        }

        static func numberString(_ value: Any?) -> String {
            if let number = value as? NSNumber {
                return number.stringValue
            }
            return value as? String ?? ""
        }

        static func values(_ entries: [MITMTextEntry]) -> [String] {
            entries.map(\.value).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }

        static func assign(_ object: inout [String: Any], key: String, value: String) {
            let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if normalized.isEmpty {
                object.removeValue(forKey: key)
            } else {
                object[key] = normalized
            }
        }

        static func assign(_ object: inout [String: Any], key: String, values: [MITMTextEntry]) {
            let normalized = self.values(values)
            if normalized.isEmpty {
                object.removeValue(forKey: key)
            } else {
                object[key] = normalized
            }
        }

        static func canonicalKey(_ object: [String: Any]) -> String? {
            guard JSONSerialization.isValidJSONObject(object),
                  let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            else { return nil }
            return String(data: data, encoding: .utf8)
        }
    }

    @MainActor
    private final class MITMSettingsModel: ObservableObject {
        @Published var isLoading = true
        @Published var isSaving = false
        @Published var enabled = false
        @Published var http2Enabled = true
        @Published var certificateName = "sing-box MITM Root CA"
        @Published var keyPair = ""
        @Published var keyPairPassword = ""
        @Published var rules: [MITMRule] = []
        @Published var scripts: [MITMScriptDefinition] = []
        @Published var modules: [MITMModule] = []
        @Published var availableOutbounds: [String] = []

        private var root: [String: Any] = [:]
        private var originalRouteRules: [[String: Any]] = []
        private var originalScripts: [[String: Any]] = []
        private var originalModuleArtifacts = MITMModuleArtifactIndex()
        private var originalModuleLocalPaths: Set<String> = []
        private var profile: Profile?

        var hasCertificate: Bool { !keyPair.isEmpty && !keyPairPassword.isEmpty }

        func load(profileID: Int64) async throws {
            guard let profile = try await ProfileManager.get(profileID) else {
                throw NSError(domain: "MITMSettings", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "Profile missing")])
            }
            var error: NSError?
            let content = try profile.read()
            guard let formatted = LibboxFormatConfig(content, &error) else {
                throw error ?? NSError(domain: "MITMSettings", code: 2, userInfo: [NSLocalizedDescriptionKey: String(localized: "Invalid profile")])
            }
            if let error {
                throw error
            }
            guard let data = formatted.value.data(using: .utf8),
                  let root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            else {
                throw NSError(domain: "MITMSettings", code: 3, userInfo: [NSLocalizedDescriptionKey: String(localized: "Invalid profile")])
            }
            self.profile = profile
            apply(root)
            isLoading = false
        }

        private func apply(_ root: [String: Any]) {
            self.root = root
            let globalMITM = root["mitm"] as? [String: Any] ?? [:]
            enabled = MITMJSON.bool(globalMITM["enabled"])
            http2Enabled = MITMJSON.bool(globalMITM["http2_enabled"], defaultValue: true)

            let certificate = root["certificate"] as? [String: Any] ?? [:]
            let tlsDecryption = certificate["tls_decryption"] as? [String: Any] ?? [:]
            keyPair = tlsDecryption["key_pair_p12"] as? String ?? ""
            keyPairPassword = tlsDecryption["key_pair_p12_password"] as? String ?? ""

            availableOutbounds = (root["outbounds"] as? [[String: Any]] ?? [])
                .compactMap { $0["tag"] as? String }
                .filter { !$0.isEmpty }
            let loadedModules = (root["mitm_modules"] as? [[String: Any]] ?? []).map(MITMModule.init)
            originalModuleArtifacts = MITMModuleArtifactIndex(
                root: root,
                modules: loadedModules.map { $0.object() }
            )
            originalModuleLocalPaths = Set(loadedModules.map(\.localPath).filter { !$0.isEmpty })
            modules = loadedModules.map { module in
                var module = module
                module.downloadDetour = normalizedModuleDetour(module.downloadDetour)
                return module
            }

            let route = root["route"] as? [String: Any] ?? [:]
            originalRouteRules = route["rules"] as? [[String: Any]] ?? []
            rules = originalRouteRules.enumerated().compactMap { index, object in
                guard object["mitm"] is [String: Any],
                      !originalModuleArtifacts.owns(rule: object)
                else { return nil }
                return MITMRule(object: object, originalIndex: index)
            }

            originalScripts = root["scripts"] as? [[String: Any]] ?? []
            scripts = originalScripts.enumerated().compactMap { index, object in
                guard !originalModuleArtifacts.owns(script: object) else { return nil }
                return MITMScriptDefinition(object: object, originalIndex: index)
            }
        }

        func importModule(
            url: String,
            downloadDetour: String,
            updateInterval: String
        ) async throws {
            guard let sourceURL = URL(string: url), let scheme = sourceURL.scheme?.lowercased(), ["http", "https"].contains(scheme) else {
                throw NSError(domain: "MITMSettings", code: 8, userInfo: [NSLocalizedDescriptionKey: String(localized: "Invalid module URL")])
            }
            let downloadDetour = normalizedModuleDetour(downloadDetour)
            let content = try await HTTPClient.getStringAsync(sourceURL.absoluteString)
            let payload = try SurgeModuleParser.parse(
                content,
                sourceURL: sourceURL,
                downloadDetour: downloadDetour,
                updateInterval: updateInterval
            )
            if let index = modules.firstIndex(where: { $0.url == sourceURL.absoluteString }) {
                let existing = modules[index]
                let localPath = try cacheModule(content, id: existing.id)
                modules[index] = MITMModule(
                    payload: payload,
                    url: sourceURL.absoluteString,
                    localPath: localPath,
                    downloadDetour: downloadDetour,
                    updateInterval: updateInterval,
                    id: existing.id,
                    enabled: existing.enabled,
                    raw: existing.raw
                )
            } else {
                let id = UUID().uuidString
                let localPath = try cacheModule(content, id: id)
                modules.append(MITMModule(
                    payload: payload,
                    url: sourceURL.absoluteString,
                    localPath: localPath,
                    downloadDetour: downloadDetour,
                    updateInterval: updateInterval,
                    id: id
                ))
            }
            enabled = true
        }

        func refreshModule(id: String) async throws {
            guard let index = modules.firstIndex(where: { $0.id == id }) else { return }
            let existing = modules[index]
            guard let sourceURL = URL(string: existing.url) else {
                throw NSError(domain: "MITMSettings", code: 8, userInfo: [NSLocalizedDescriptionKey: String(localized: "Invalid module URL")])
            }
            let downloadDetour = normalizedModuleDetour(existing.downloadDetour)
            let content = try await HTTPClient.getStringAsync(sourceURL.absoluteString)
            let payload = try SurgeModuleParser.parse(
                content,
                sourceURL: sourceURL,
                downloadDetour: downloadDetour,
                updateInterval: existing.updateInterval
            )
            let localPath = try cacheModule(content, id: existing.id)
            modules[index] = MITMModule(
                payload: payload,
                url: existing.url,
                localPath: localPath,
                downloadDetour: downloadDetour,
                updateInterval: existing.updateInterval,
                id: existing.id,
                enabled: existing.enabled,
                raw: existing.raw
            )
        }

        private func cacheModule(_ content: String, id: String) throws -> String {
            guard let profile else { return "" }
            let safeID = id.replacingOccurrences(of: "/", with: "-")
            let relativePath = "configs/modules/profile_\(profile.mustID)/\(safeID).sgmodule"
            let destination = FilePath.sharedDirectory.appendingPathComponent(relativePath)
            try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
            try content.write(to: destination, atomically: true, encoding: .utf8)
            return relativePath
        }

        private func removeCachedModules(_ paths: Set<String>) {
            let modulesRoot = FilePath.sharedDirectory.appendingPathComponent("configs/modules", isDirectory: true).standardizedFileURL
            for path in paths where !path.isEmpty {
                let target = FilePath.sharedDirectory.appendingPathComponent(path).standardizedFileURL
                guard target.path.hasPrefix(modulesRoot.path + "/") else { continue }
                try? FileManager.default.removeItem(at: target)
            }
        }

        private func normalizedModuleDetour(_ value: String) -> String {
            let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !value.isEmpty, availableOutbounds.contains(value) else { return "" }
            return value
        }

        func generateCertificate() throws {
            var error: NSError?
            guard let certificate = LibboxGenerateMITMCertificate(certificateName, &error) else {
                throw error ?? NSError(domain: "MITMSettings", code: 4)
            }
            if let error { throw error }
            keyPair = certificate.keyPair
            keyPairPassword = certificate.password
            enabled = true
        }

        func importCertificate(from url: URL) throws {
            let accessed = url.startAccessingSecurityScopedResource()
            defer {
                if accessed { url.stopAccessingSecurityScopedResource() }
            }
            keyPair = try Data(contentsOf: url).base64EncodedString()
        }

        func exportCertificate() throws -> URL {
            var error: NSError?
            guard let exported = LibboxExportMITMCertificate(keyPair, keyPairPassword, &error) else {
                throw error ?? NSError(domain: "MITMSettings", code: 5)
            }
            if let error { throw error }
            guard let data = Data(base64Encoded: exported.value) else {
                throw NSError(domain: "MITMSettings", code: 6, userInfo: [NSLocalizedDescriptionKey: String(localized: "Invalid certificate")])
            }
            let fileName = certificateName.replacingOccurrences(of: "/", with: "-") + ".cer"
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)
            try data.write(to: url, options: .atomic)
            return url
        }

        func save() async throws {
            guard let profile, !isSaving else { return }
            isSaving = true
            defer { isSaving = false }

            for rule in rules where rule.enabled {
                guard !MITMJSON.values(rule.domains).isEmpty || !MITMJSON.values(rule.domainSuffixes).isEmpty else {
                    throw NSError(
                        domain: "MITMSettings",
                        code: 9,
                        userInfo: [NSLocalizedDescriptionKey: String(localized: "Every enabled MITM rule must match at least one domain.")]
                    )
                }
                for binding in rule.scripts {
                    guard !binding.tag.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                          !MITMJSON.values(binding.patterns).isEmpty
                    else {
                        throw NSError(
                            domain: "MITMSettings",
                            code: 10,
                            userInfo: [NSLocalizedDescriptionKey: String(localized: "Every script binding needs a tag and at least one URL pattern.")]
                        )
                    }
                }
            }

            var root = root
            for index in modules.indices {
                modules[index].downloadDetour = normalizedModuleDetour(modules[index].downloadDetour)
            }
            var globalMITM = root["mitm"] as? [String: Any] ?? [:]
            globalMITM["enabled"] = enabled
            globalMITM["http2_enabled"] = http2Enabled
            root["mitm"] = globalMITM

            var certificate = root["certificate"] as? [String: Any] ?? [:]
            var tlsDecryption = certificate["tls_decryption"] as? [String: Any] ?? [:]
            tlsDecryption["enabled"] = hasCertificate
            if hasCertificate {
                tlsDecryption["key_pair_p12"] = keyPair
                tlsDecryption["key_pair_p12_password"] = keyPairPassword
            } else {
                tlsDecryption.removeValue(forKey: "key_pair_p12")
                tlsDecryption.removeValue(forKey: "key_pair_p12_password")
            }
            certificate["tls_decryption"] = tlsDecryption
            root["certificate"] = certificate

            // route/reject/hijack-dns actions terminate sing-box rule matching.
            // Keep every MITM route-options rule directly after sniff so a
            // later ordinary routing rule cannot make it unreachable.
            var routeRules = originalRouteRules.filter {
                !originalModuleArtifacts.owns(rule: $0) && !($0["mitm"] is [String: Any])
            }
            let manualRules = rules.map { $0.object() }
            let moduleRules = MITMModuleArtifactIndex.deduplicatedRules(
                modules.filter(\.enabled).flatMap(\.generatedRules),
                in: root
            )
            let activeMITMRules = MITMModuleArtifactIndex.deduplicatedRules(
                moduleRules + manualRules,
                in: root
            )
            let moduleRuleInsertionIndex = routeRules.firstIndex(where: { ($0["action"] as? String) == "sniff" }).map { $0 + 1 } ?? 0
            routeRules.insert(contentsOf: activeMITMRules, at: moduleRuleInsertionIndex)
            var route = root["route"] as? [String: Any] ?? [:]
            route["rules"] = routeRules
            root["route"] = route

            var scriptsByIndex: [Int: MITMScriptDefinition] = [:]
            var newScripts: [MITMScriptDefinition] = []
            for script in scripts {
                if let index = script.originalIndex {
                    scriptsByIndex[index] = script
                } else {
                    newScripts.append(script)
                }
            }
            var scriptObjects: [[String: Any]] = []
            for (index, object) in originalScripts.enumerated() {
                if originalModuleArtifacts.owns(script: object) {
                    continue
                }
                if let replacement = scriptsByIndex[index] {
                    scriptObjects.append(replacement.object())
                }
            }
            scriptObjects.append(contentsOf: newScripts.map { $0.object() })
            let moduleScripts = MITMModuleArtifactIndex.deduplicatedScripts(
                modules.filter(\.enabled).reversed().flatMap { $0.scriptObjects() }
            )
            scriptObjects.append(contentsOf: moduleScripts)
            if scriptObjects.isEmpty {
                root.removeValue(forKey: "scripts")
            } else {
                root["scripts"] = scriptObjects
            }

            if modules.isEmpty {
                root.removeValue(forKey: "mitm_modules")
            } else {
                root["mitm_modules"] = modules.map { $0.object() }
            }

            if hasCertificate {
                var experimental = root["experimental"] as? [String: Any] ?? [:]
                var clashAPI = experimental["clash_api"] as? [String: Any] ?? [:]
                if (clashAPI["external_controller"] as? String ?? "").isEmpty {
                    clashAPI["external_controller"] = "127.0.0.1:9090"
                }
                experimental["clash_api"] = clashAPI
                root["experimental"] = experimental
            }

            let data = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
            guard var content = String(data: data, encoding: .utf8) else {
                throw NSError(domain: "MITMSettings", code: 7)
            }
            content += "\n"
            if let normalized = Profile.normalizedMITMRuntimeContent(content) {
                content = normalized
            }
            var error: NSError?
            LibboxCheckConfig(content, &error)
            if let error { throw error }
            try profile.write(content)
            try await profile.onProfileUpdated()
            let activeModuleLocalPaths = Set(modules.map(\.localPath).filter { !$0.isEmpty })
            removeCachedModules(originalModuleLocalPaths.subtracting(activeModuleLocalPaths))
            apply(root)
        }
    }

    @MainActor
    public struct MITMSettingsView: View {
        private let profileID: Int64
        private let readOnly: Bool

        @Environment(\.openURL) private var openURL
        @StateObject private var model = MITMSettingsModel()
        @State private var alert: AlertState?
        @State private var certificateImporterPresented = false
        @State private var moduleImporterPresented = false

        public init(profileID: Int64, readOnly: Bool) {
            self.profileID = profileID
            self.readOnly = readOnly
        }

        public var body: some View {
            Group {
                if model.isLoading {
                    ProgressView().onAppear {
                        Task { await load() }
                    }
                } else {
                    form
                }
            }
            .navigationTitle("MITM")
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
                .toolbar {
                    ToolbarItem(placement: editPlacement) {
                        if !readOnly, model.modules.count > 1 {
                            EditButton()
                        }
                    }
                    ToolbarItem(placement: savePlacement) {
                        if !readOnly {
                            Button("Save") {
                                Task { await save() }
                            }
                            .disabled(model.isSaving)
                        }
                    }
                }
                .alert($alert)
                .fileImporter(
                    isPresented: $certificateImporterPresented,
                    allowedContentTypes: [.data],
                    allowsMultipleSelection: false,
                    onCompletion: importCertificate
                )
                .sheet(isPresented: $moduleImporterPresented) {
                    MITMModuleImportView(availableOutbounds: model.availableOutbounds) { url, downloadDetour, updateInterval in
                        try await model.importModule(
                            url: url,
                            downloadDetour: downloadDetour,
                            updateInterval: updateInterval
                        )
                    }
                    .presentationDetentsIfAvailable()
                }
        }

        private var form: some View {
            FormView {
                Section("Core") {
                    Toggle("Enable MITM", isOn: $model.enabled)
                    Toggle("HTTP/2", isOn: $model.http2Enabled)
                }

                certificateSection

                Section("Modules") {
                    ForEach($model.modules) { $module in
                        FormNavigationLink {
                            MITMModuleView(
                                module: $module,
                                readOnly: readOnly,
                                availableOutbounds: model.availableOutbounds,
                                refresh: { try await model.refreshModule(id: module.id) }
                            )
                        } label: {
                            Label(module.displayName, systemImage: module.enabled ? "shippingbox.fill" : "shippingbox")
                        }
                    }
                    .onDelete { model.modules.remove(atOffsets: $0) }
                    .onMove { source, destination in
                        model.modules.move(fromOffsets: source, toOffset: destination)
                    }
                    if !readOnly {
                        FormButton {
                            moduleImporterPresented = true
                        } label: {
                            Label("Add Module", systemImage: "plus")
                        }
                    }
                }

                Section("Rules") {
                    ForEach($model.rules) { $rule in
                        FormNavigationLink {
                            MITMRuleView(rule: $rule, availableScripts: model.scripts.map(\.tag).filter { !$0.isEmpty })
                        } label: {
                            Label(rule.displayName, systemImage: rule.enabled ? "shield.lefthalf.filled" : "shield.slash")
                        }
                    }
                    .onDelete { model.rules.remove(atOffsets: $0) }
                    if !readOnly {
                        FormButton {
                            model.rules.append(MITMRule())
                        } label: {
                            Label("Add Rule", systemImage: "plus")
                        }
                    }
                }

                Section("Scripts") {
                    ForEach($model.scripts) { $script in
                        FormNavigationLink {
                            MITMScriptDefinitionView(script: $script)
                        } label: {
                            Label(script.tag.isEmpty ? String(localized: "Untitled Script") : script.tag, systemImage: "scroll")
                        }
                    }
                    .onDelete { model.scripts.remove(atOffsets: $0) }
                    if !readOnly {
                        FormButton {
                            model.scripts.append(MITMScriptDefinition())
                        } label: {
                            Label("Add Script", systemImage: "plus")
                        }
                    }
                }

                Section("Diagnostics") {
                    FormNavigationLink {
                        LogView()
                    } label: {
                        Label("View Logs", systemImage: "doc.text.magnifyingglass")
                    }
                }
            }
            .disabled(readOnly || model.isSaving)
        }

        @ViewBuilder
        private var certificateSection: some View {
            Section("Certificate Authority") {
                FormItem(String(localized: "Name")) {
                    TextField("Name", text: $model.certificateName)
                        .multilineTextAlignment(.trailing)
                }
                FormItem(String(localized: "Password")) {
                    SecureField("P12 Password", text: $model.keyPairPassword)
                        .multilineTextAlignment(.trailing)
                }
                FormTextItem("Status", model.hasCertificate ? String(localized: "Configured") : String(localized: "Not Configured"))

                if !readOnly {
                    FormButton {
                        generateCertificate()
                    } label: {
                        Label("Generate CA", systemImage: "key.fill")
                    }
                    FormButton {
                        certificateImporterPresented = true
                    } label: {
                        Label("Import P12", systemImage: "square.and.arrow.down")
                    }
                }
                if model.hasCertificate {
                    ShareButtonCompat($alert) {
                        Label("Export Certificate", systemImage: "square.and.arrow.up")
                    } itemURL: {
                        try model.exportCertificate()
                    }
                    FormButton {
                        Task { await installCertificate() }
                    } label: {
                        Label("Install Certificate", systemImage: "checkmark.shield")
                    }
                    if !readOnly {
                        FormButton(role: .destructive) {
                            model.keyPair = ""
                            model.keyPairPassword = ""
                        } label: {
                            Label("Remove CA", systemImage: "trash")
                        }
                        .foregroundColor(.red)
                    }
                }
            }
        }

        private var savePlacement: ToolbarItemPlacement {
            #if os(iOS)
                return .navigationBarTrailing
            #else
                return .primaryAction
            #endif
        }

        private var editPlacement: ToolbarItemPlacement {
            #if os(iOS)
                return .navigationBarLeading
            #else
                return .automatic
            #endif
        }

        private func load() async {
            do {
                try await model.load(profileID: profileID)
            } catch {
                model.isLoading = false
                alert = AlertState(action: "MITM", error: error)
            }
        }

        private func save() async {
            do {
                try await model.save()
            } catch {
                alert = AlertState(action: "MITM", error: error)
            }
        }

        private func generateCertificate() {
            do {
                try model.generateCertificate()
            } catch {
                alert = AlertState(action: "MITM", error: error)
            }
        }

        private func importCertificate(_ result: Result<[URL], Error>) {
            do {
                guard let url = try result.get().first else { return }
                try model.importCertificate(from: url)
            } catch {
                alert = AlertState(action: "MITM", error: error)
            }
        }

        private func installCertificate() async {
            do {
                if !readOnly {
                    try await model.save()
                }
                openURL(URL(string: "http://127.0.0.1:9090/mitm/mobileconfig")!)
            } catch {
                alert = AlertState(action: "MITM", error: error)
            }
        }
    }

    @MainActor
    private struct MITMModuleImportView: View {
        let availableOutbounds: [String]
        let importModule: (String, String, String) async throws -> Void

        @Environment(\.dismiss) private var dismiss
        @State private var url = ""
        @State private var downloadDetour = ""
        @State private var updateInterval = "1d"
        @State private var isImporting = false
        @State private var alert: AlertState?

        var body: some View {
            NavigationStackCompat {
                FormView {
                    Section("Module") {
                        FormItem(String(localized: "URL")) {
                            TextField("https://example.com/module.sgmodule", text: $url)
                                .multilineTextAlignment(.trailing)
                                #if os(iOS)
                                .keyboardType(.URL)
                                .textInputAutocapitalization(.none)
                                #endif
                        }
                        Picker("Download Detour", selection: $downloadDetour) {
                            Text("Default").tag("")
                            ForEach(availableOutbounds, id: \.self) { Text($0).tag($0) }
                        }
                        FormItem(String(localized: "Update Interval")) {
                            TextField("1d", text: $updateInterval).multilineTextAlignment(.trailing)
                        }
                    }
                }
                .navigationTitle("Add Module")
                #if os(iOS)
                    .navigationBarTitleDisplayMode(.inline)
                #endif
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { dismiss() }
                        }
                        ToolbarItem(placement: .confirmationAction) {
                            if isImporting {
                                ProgressView()
                            } else {
                                Button("Import") {
                                    isImporting = true
                                    Task {
                                        do {
                                            try await importModule(url, downloadDetour, updateInterval)
                                            dismiss()
                                        } catch {
                                            isImporting = false
                                            alert = AlertState(action: "import module", error: error)
                                        }
                                    }
                                }
                                .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                            }
                        }
                    }
                    .disabled(isImporting)
                    .alert($alert)
            }
        }
    }

    @MainActor
    private struct MITMModuleView: View {
        @Binding var module: MITMModule
        let readOnly: Bool
        let availableOutbounds: [String]
        let refresh: () async throws -> Void

        @State private var isRefreshing = false
        @State private var alert: AlertState?

        var body: some View {
            FormView {
                Section("Module") {
                    Toggle("Enabled", isOn: $module.enabled)
                    FormTextItem("Name", module.displayName)
                    if !module.moduleDescription.isEmpty {
                        FormTextItem("Description", module.moduleDescription)
                    }
                    FormTextItem("Rules", String(module.generatedRules.count))
                    FormTextItem("Scripts", String(module.generatedScripts.count))
                }
                Section("Source") {
                    FormItem(String(localized: "URL")) {
                        TextField("https://", text: $module.url)
                            .multilineTextAlignment(.trailing)
                            #if os(iOS)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.none)
                            #endif
                    }
                    Picker("Download Detour", selection: $module.downloadDetour) {
                        Text("Default").tag("")
                        ForEach(availableOutbounds, id: \.self) { Text($0).tag($0) }
                    }
                    FormItem(String(localized: "Update Interval")) {
                        TextField("1d", text: $module.updateInterval).multilineTextAlignment(.trailing)
                    }
                    if !readOnly {
                        FormButton {
                            isRefreshing = true
                            Task {
                                do {
                                    try await refresh()
                                } catch {
                                    alert = AlertState(action: "update module", error: error)
                                }
                                isRefreshing = false
                            }
                        } label: {
                            if isRefreshing {
                                ProgressView()
                            } else {
                                Label("Update Module", systemImage: "arrow.clockwise")
                            }
                        }
                    }
                }
            }
            .navigationTitle(module.displayName)
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
                .disabled(readOnly || isRefreshing)
                .alert($alert)
        }
    }

    private struct MITMRuleView: View {
        @Binding var rule: MITMRule
        let availableScripts: [String]

        var body: some View {
            FormView {
                Section("Core") {
                    Toggle("Enabled", isOn: $rule.enabled)
                    Toggle("Print Traffic", isOn: $rule.printTraffic)
                }
                Section("Domain Matching") {
                    FormNavigationLink {
                        MITMLineListView(title: String(localized: "Exact Domains"), placeholder: "example.com", entries: $rule.domains)
                    } label: {
                        MITMCountLabel(title: String(localized: "Exact Domains"), systemImage: "equal", count: rule.domains.count)
                    }
                    FormNavigationLink {
                        MITMLineListView(title: String(localized: "Domain Suffixes"), placeholder: "example.com", entries: $rule.domainSuffixes)
                    } label: {
                        MITMCountLabel(title: String(localized: "Domain Suffixes"), systemImage: "text.append", count: rule.domainSuffixes.count)
                    }
                }
                Section("Rewrite") {
                    rewriteLink("URL Rewrite", icon: "arrow.triangle.swap", entries: $rule.urlRewrites)
                    rewriteLink("Header Rewrite", icon: "list.bullet.rectangle", entries: $rule.headerRewrites)
                    rewriteLink("Body Rewrite", icon: "text.redaction", entries: $rule.bodyRewrites)
                    rewriteLink("Map Local", icon: "doc.badge.gearshape", entries: $rule.mapLocal)
                }
                Section("Scripts") {
                    ForEach($rule.scripts) { $script in
                        FormNavigationLink {
                            MITMScriptBindingView(script: $script, availableScripts: availableScripts)
                        } label: {
                            Label(script.tag.isEmpty ? String(localized: "Untitled Binding") : script.tag, systemImage: "link")
                        }
                    }
                    .onDelete { rule.scripts.remove(atOffsets: $0) }
                    FormButton {
                        rule.scripts.append(MITMScriptBinding())
                    } label: {
                        Label("Add Script Binding", systemImage: "plus")
                    }
                }
            }
            .navigationTitle("MITM Rule")
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
        }

        private func rewriteLink(_ title: String, icon: String, entries: Binding<[MITMTextEntry]>) -> some View {
            FormNavigationLink {
                MITMLineListView(title: title, placeholder: String(localized: "Surge rule line"), entries: entries)
            } label: {
                MITMCountLabel(title: title, systemImage: icon, count: entries.wrappedValue.count)
            }
        }
    }

    private struct MITMScriptBindingView: View {
        @Binding var script: MITMScriptBinding
        let availableScripts: [String]

        var body: some View {
            FormView {
                Section("Script") {
                    if availableScripts.isEmpty {
                        FormItem(String(localized: "Tag")) {
                            TextField("Tag", text: $script.tag).multilineTextAlignment(.trailing)
                        }
                    } else {
                        Picker("Tag", selection: $script.tag) {
                            Text("Select").tag("")
                            ForEach(availableScripts, id: \.self) { Text($0).tag($0) }
                        }
                    }
                    Picker("Event", selection: $script.event) {
                        ForEach(MITMScriptBinding.Event.allCases) { Text($0.title).tag($0) }
                    }
                    FormItem(String(localized: "Timeout")) {
                        TextField("10s", text: $script.timeout).multilineTextAlignment(.trailing)
                    }
                    Toggle("Requires Body", isOn: $script.requiresBody)
                    Toggle("Binary Body", isOn: $script.binaryBodyMode)
                    Toggle("Full Header Mode", isOn: $script.fullHeaderMode)
                    FormItem(String(localized: "Maximum Size")) {
                        TextField("131072", text: $script.maxSize)
                            .multilineTextAlignment(.trailing)
                            #if os(iOS)
                                .keyboardType(.numberPad)
                            #endif
                    }
                }
                Section("Matching") {
                    FormNavigationLink {
                        MITMLineListView(title: String(localized: "URL Patterns"), placeholder: "^https://example\\.com/", entries: $script.patterns)
                    } label: {
                        MITMCountLabel(title: String(localized: "URL Patterns"), systemImage: "text.magnifyingglass", count: script.patterns.count)
                    }
                    FormNavigationLink {
                        MITMLineListView(title: String(localized: "Arguments"), placeholder: String(localized: "Argument"), entries: $script.arguments)
                    } label: {
                        MITMCountLabel(title: String(localized: "Arguments"), systemImage: "list.bullet", count: script.arguments.count)
                    }
                }
            }
            .navigationTitle("Script Binding")
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }

    private struct MITMScriptDefinitionView: View {
        @Binding var script: MITMScriptDefinition

        var body: some View {
            FormView {
                Section("Script") {
                    FormItem(String(localized: "Tag")) {
                        TextField("Tag", text: $script.tag).multilineTextAlignment(.trailing)
                    }
                    Picker("Source", selection: $script.source) {
                        ForEach(MITMScriptDefinition.Source.allCases) { Text($0.title).tag($0) }
                    }
                    FormItem(script.source == .remote ? String(localized: "URL") : String(localized: "Path")) {
                        TextField(script.source == .remote ? "https://" : "script.js", text: $script.location)
                            .multilineTextAlignment(.trailing)
                            #if os(iOS)
                                .keyboardType(script.source == .remote ? .URL : .asciiCapable)
                                .textInputAutocapitalization(.none)
                            #endif
                    }
                    if script.source == .remote {
                        FormItem(String(localized: "Download Detour")) {
                            TextField("direct", text: $script.downloadDetour).multilineTextAlignment(.trailing)
                        }
                        FormItem(String(localized: "Update Interval")) {
                            TextField("1d", text: $script.updateInterval).multilineTextAlignment(.trailing)
                        }
                    }
                }
            }
            .navigationTitle("Script")
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }

    private struct MITMLineListView: View {
        let title: String
        let placeholder: String
        @Binding var entries: [MITMTextEntry]

        var body: some View {
            FormView {
                Section {
                    ForEach($entries) { $entry in
                        HStack {
                            TextField(placeholder, text: $entry.value)
                                #if os(iOS)
                                    .keyboardType(.asciiCapable)
                                    .textInputAutocapitalization(.none)
                                #endif
                            Button(role: .destructive) {
                                entries.removeAll { $0.id == entry.id }
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    FormButton {
                        entries.append(MITMTextEntry())
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            }
            .navigationTitle(title)
            #if os(iOS)
                .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }

    private struct MITMCountLabel: View {
        let title: String
        let systemImage: String
        let count: Int

        var body: some View {
            HStack {
                Label(title, systemImage: systemImage)
                Spacer()
                Text(String(count)).foregroundStyle(.secondary)
            }
        }
    }
#endif
