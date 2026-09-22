import Foundation
import GRDB
import Libbox

public extension Profile {
    nonisolated func updateRemoteProfile() async throws {
        if type != .remote {
            return
        }
        let url = remoteURL
        let remoteContent = try await HTTPClient.getStringAsync(url)
        try await BlockingIO.run {
            var error: NSError?
            LibboxCheckConfig(remoteContent, &error)
            if let error {
                throw error
            }
        }
        await MainActor.run {
            lastUpdated = Date()
        }
        try await ProfileManager.update(self)
        let oldContent = (try? await readAsync()) ?? ""
        if oldContent == remoteContent {
            return
        }
        var content = remoteContent
        if !oldContent.isEmpty,
           let mergedContent = RemoteProfileMerger.merge(remoteContent: remoteContent, localContent: oldContent) {
            do {
                try await BlockingIO.run {
                    var error: NSError?
                    LibboxCheckConfig(mergedContent, &error)
                    if let error {
                        throw error
                    }
                }
                content = mergedContent
            } catch {
                // Preservation must never break the subscription update itself.
            }
        }
        if content == oldContent {
            return
        }
        try await writeAsync(content)
        try await onProfileUpdated()
    }

    nonisolated func onProfileUpdated() async throws {
        if await SharedPreferences.selectedProfileID.get() == id {
            if let profile = try? await ExtensionProfile.load() {
                if await profile.status == .connected {
                    try await profile.reloadService()
                }
            }
        }
    }
}

/// Identifies the route rules and scripts materialized by imported MITM modules.
/// Route rules are formatted through libbox because listable values and durations
/// do not retain the same JSON representation after a configuration round trip.
public struct MITMModuleArtifactIndex {
    private var ruleKeys: Set<String>
    private var scriptTags: Set<String>

    public init() {
        ruleKeys = []
        scriptTags = []
    }

    public init(root: [String: Any], modules: [[String: Any]]) {
        let rules = modules.flatMap { $0["rules"] as? [[String: Any]] ?? [] }
        ruleKeys = Set(rules.compactMap(Self.canonicalKey))
        ruleKeys.formUnion(Self.normalizedRuleKeys(rules, in: root).compactMap { $0 })
        scriptTags = Set(modules.flatMap { module in
            (module["scripts"] as? [[String: Any]] ?? []).compactMap { script in
                let tag = (script["tag"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                return tag.isEmpty ? nil : tag
            }
        })
    }

    public func owns(rule: [String: Any]) -> Bool {
        guard let key = Self.canonicalKey(rule) else { return false }
        return ruleKeys.contains(key)
    }

    public func owns(script: [String: Any]) -> Bool {
        guard let tag = script["tag"] as? String else { return false }
        return scriptTags.contains(tag.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    public static func deduplicatedRules(_ rules: [[String: Any]], in root: [String: Any]) -> [[String: Any]] {
        let keys = normalizedRuleKeys(rules, in: root)
        var seen: Set<String> = []
        return rules.enumerated().compactMap { index, rule in
            guard let key = keys[index] ?? canonicalKey(rule) else { return rule }
            return seen.insert(key).inserted ? rule : nil
        }
    }

    public static func deduplicatedScripts(_ scripts: [[String: Any]]) -> [[String: Any]] {
        var seenTags: Set<String> = []
        var seenObjects: Set<String> = []
        return scripts.filter { script in
            let tag = (script["tag"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !tag.isEmpty {
                return seenTags.insert(tag).inserted
            }
            guard let key = canonicalKey(script) else { return true }
            return seenObjects.insert(key).inserted
        }
    }

    private static func normalizedRuleKeys(_ rules: [[String: Any]], in root: [String: Any]) -> [String?] {
        guard !rules.isEmpty else { return [] }
        var probe = root
        var route = probe["route"] as? [String: Any] ?? [:]
        route["rules"] = rules
        probe["route"] = route
        probe.removeValue(forKey: "mitm_modules")
        guard JSONSerialization.isValidJSONObject(probe),
              let data = try? JSONSerialization.data(withJSONObject: probe),
              let content = String(data: data, encoding: .utf8)
        else { return rules.map(canonicalKey) }

        var error: NSError?
        guard let formatted = LibboxFormatConfig(content, &error), error == nil,
              let formattedData = formatted.value.data(using: .utf8),
              let formattedRoot = try? JSONSerialization.jsonObject(with: formattedData) as? [String: Any],
              let formattedRoute = formattedRoot["route"] as? [String: Any],
              let formattedRules = formattedRoute["rules"] as? [[String: Any]],
              formattedRules.count == rules.count
        else { return rules.map(canonicalKey) }
        return formattedRules.map(canonicalKey)
    }

    private static func canonicalKey(_ object: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

/// Re-applies the local MITM layer (modules, rules, scripts, certificate) on
/// top of freshly downloaded subscription content, which otherwise replaces
/// the profile file wholesale.
enum RemoteProfileMerger {
    static func merge(remoteContent: String, localContent: String) -> String? {
        guard let remoteData = remoteContent.data(using: .utf8),
              let localData = localContent.data(using: .utf8),
              var remote = try? JSONSerialization.jsonObject(with: remoteData) as? [String: Any],
              let local = try? JSONSerialization.jsonObject(with: localData) as? [String: Any]
        else { return nil }

        // The subscription itself manages the module layer.
        if remote["mitm_modules"] != nil {
            return nil
        }

        let modules = local["mitm_modules"] as? [[String: Any]] ?? []
        let moduleArtifacts = MITMModuleArtifactIndex(root: local, modules: modules)
        let enabledModules = modules.filter { boolValue($0["enabled"], defaultValue: true) }
        let moduleRules = MITMModuleArtifactIndex.deduplicatedRules(
            enabledModules.flatMap { $0["rules"] as? [[String: Any]] ?? [] },
            in: local
        )
        let moduleScripts = MITMModuleArtifactIndex.deduplicatedScripts(
            enabledModules.flatMap { $0["scripts"] as? [[String: Any]] ?? [] }
        )

        let localRoute = local["route"] as? [String: Any] ?? [:]
        let localRules = localRoute["rules"] as? [[String: Any]] ?? []
        let preservedRules = localRules.filter {
            $0["mitm"] is [String: Any] && !moduleArtifacts.owns(rule: $0)
        }
        let localScripts = local["scripts"] as? [[String: Any]] ?? []
        let preservedScripts = localScripts.filter {
            !moduleArtifacts.owns(script: $0)
        }
        let localMITM = local["mitm"] as? [String: Any]
        let localCertificate = local["certificate"] as? [String: Any]
        let localTLSDecryption = localCertificate?["tls_decryption"] as? [String: Any]

        guard !modules.isEmpty || !preservedRules.isEmpty || !preservedScripts.isEmpty
            || localMITM != nil || localTLSDecryption != nil
        else { return nil }

        if remote["mitm"] == nil, let localMITM {
            remote["mitm"] = localMITM
        }
        if let localTLSDecryption {
            var certificate = remote["certificate"] as? [String: Any] ?? [:]
            if certificate["tls_decryption"] == nil {
                certificate["tls_decryption"] = localTLSDecryption
                remote["certificate"] = certificate
            }
        }
        if !modules.isEmpty {
            remote["mitm_modules"] = modules
        }

        let insertRules = moduleRules + preservedRules
        if !insertRules.isEmpty {
            var route = remote["route"] as? [String: Any] ?? [:]
            var rules = route["rules"] as? [[String: Any]] ?? []
            rules.removeAll { moduleArtifacts.owns(rule: $0) }
            var seen = Set(rules.compactMap(canonicalKey))
            var additions: [[String: Any]] = []
            for rule in insertRules {
                guard let key = canonicalKey(rule), !seen.contains(key) else { continue }
                seen.insert(key)
                additions.append(rule)
            }
            if !additions.isEmpty {
                let insertionIndex = rules.firstIndex(where: { ($0["action"] as? String) == "sniff" }).map { $0 + 1 } ?? 0
                rules.insert(contentsOf: additions, at: insertionIndex)
                route["rules"] = rules
                remote["route"] = route
            }
        }

        let insertScripts = preservedScripts + moduleScripts
        if !insertScripts.isEmpty {
            var scripts = remote["scripts"] as? [[String: Any]] ?? []
            scripts.removeAll { moduleArtifacts.owns(script: $0) }
            var seen = Set(scripts.compactMap(canonicalKey))
            for script in insertScripts {
                guard let key = canonicalKey(script), !seen.contains(key) else { continue }
                seen.insert(key)
                scripts.append(script)
            }
            remote["scripts"] = scripts
        }

        // The CA installation endpoint requires a Clash API controller.
        if let certificate = remote["certificate"] as? [String: Any],
           let tlsDecryption = certificate["tls_decryption"] as? [String: Any],
           boolValue(tlsDecryption["enabled"], defaultValue: false) {
            var experimental = remote["experimental"] as? [String: Any] ?? [:]
            var clashAPI = experimental["clash_api"] as? [String: Any] ?? [:]
            if (clashAPI["external_controller"] as? String ?? "").isEmpty {
                clashAPI["external_controller"] = "127.0.0.1:9090"
            }
            experimental["clash_api"] = clashAPI
            remote["experimental"] = experimental
        }

        guard JSONSerialization.isValidJSONObject(remote),
              let data = try? JSONSerialization.data(withJSONObject: remote, options: [.prettyPrinted, .sortedKeys]),
              let content = String(data: data, encoding: .utf8)
        else { return nil }
        return content + "\n"
    }

    private static func boolValue(_ value: Any?, defaultValue: Bool) -> Bool {
        (value as? NSNumber)?.boolValue ?? value as? Bool ?? defaultValue
    }

    private static func canonicalKey(_ object: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
