import Foundation

public extension Profile {
    /// User-visible recovery copies. On iOS this directory is exposed as
    /// On My iPhone/sing-box/Profiles when file sharing is enabled.
    nonisolated static var filesMirrorDirectory: URL {
        #if os(iOS)
            let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            return documents.appendingPathComponent("Profiles", isDirectory: true)
        #else
            return FilePath.workingDirectory.appendingPathComponent("profiles", isDirectory: true)
        #endif
    }

    /// A non-cache recovery copy shared with the packet tunnel. This protects
    /// profiles when the runtime configs directory is accidentally cleared.
    nonisolated static var recoveryDirectory: URL {
        FilePath.sharedDirectory
            .appendingPathComponent("Backups", isDirectory: true)
            .appendingPathComponent("Profiles", isDirectory: true)
    }

    /// Refreshes both recovery copies with the complete profile. MITM profiles
    /// include the private CA, so these files must be handled as secrets.
    nonisolated func updateFilesMirror(content: String? = nil) {
        guard type != .icloud, let id else { return }
        do {
            let content = try content ?? read()
            try Profile.writeBackup(content, profileID: id, path: path, directory: Profile.recoveryDirectory)
            if Profile.canAccessUserDocuments {
                try Profile.writeBackup(content, profileID: id, path: path, directory: Profile.filesMirrorDirectory)
            }
            Profile.removeFilesMirrorFiles(profileID: id, in: Profile.legacyFilesMirrorDirectory)
        } catch {}
    }

    /// Restores a missing runtime profile from the durable or user-visible
    /// backup. The database keeps the relative path, so restoration is
    /// transparent to callers and to the packet tunnel.
    nonisolated static func restoreProfileFileIfNeeded(profileID: Int64?, path: String) throws {
        let destination = FilePath.sharedDirectory.appendingPathComponent(path)
        guard !FileManager.default.fileExists(atPath: destination.path) else { return }

        let fileName = backupFileName(profileID: profileID, path: path)
        var candidates = [
            recoveryDirectory.appendingPathComponent(fileName),
        ]
        if canAccessUserDocuments {
            candidates.append(filesMirrorDirectory.appendingPathComponent(fileName))
        }
        if let profileID,
           let legacyFile = legacyFilesMirrorFile(profileID: profileID)
        {
            candidates.append(legacyFile)
        }
        guard let source = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }) else {
            return
        }

        let content = try Data(contentsOf: source)
        try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        try content.write(to: destination, options: .atomic)
    }

    /// Moves MITM route-options ahead of terminal routing rules. Route, reject
    /// and hijack rules stop sing-box rule matching, so MITM rules left near
    /// the end of a subscription are otherwise silently unreachable.
    nonisolated static func normalizedMITMRuntimeContent(_ content: String) -> String? {
        guard let data = content.data(using: .utf8),
              var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }

        var changed = false
        if var route = root["route"] as? [String: Any],
           let rules = route["rules"] as? [[String: Any]]
        {
            let mitmRules = rules.filter { $0["mitm"] is [String: Any] }
            if !mitmRules.isEmpty {
                var otherRules = rules.filter { !($0["mitm"] is [String: Any]) }
                let insertionIndex = otherRules.firstIndex(where: { ($0["action"] as? String) == "sniff" }).map { $0 + 1 } ?? 0
                otherRules.insert(contentsOf: mitmRules, at: insertionIndex)
                if !routeRulesEqual(rules, otherRules) {
                    route["rules"] = otherRules
                    root["route"] = route
                    changed = true
                }
            }
        }

        if usesScriptHub(root), ensureScriptHubDNS(in: &root) {
            changed = true
        }
        guard changed else { return nil }
        guard JSONSerialization.isValidJSONObject(root),
              let repairedData = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys]),
              let repaired = String(data: repairedData, encoding: .utf8)
        else { return nil }
        return repaired + "\n"
    }

    nonisolated func removeFilesMirror() {
        guard let id else { return }
        Profile.removeFilesMirror(profileID: id)
    }

    nonisolated static func removeFilesMirror(profileID: Int64) {
        removeFilesMirrorFiles(profileID: profileID, in: recoveryDirectory)
        if canAccessUserDocuments {
            removeFilesMirrorFiles(profileID: profileID, in: filesMirrorDirectory)
        }
        removeFilesMirrorFiles(profileID: profileID, in: legacyFilesMirrorDirectory)
    }

    /// Ensures every stored profile has an up-to-date mirror, e.g. after an
    /// app update or after the working directory was cleared.
    nonisolated static func backfillFilesMirrors() async {
        guard let profiles = try? await ProfileManager.list() else { return }
        for profile in profiles where profile.type != .icloud {
            profile.updateFilesMirror()
        }
    }

    private nonisolated static var canAccessUserDocuments: Bool {
        #if os(iOS)
            return Bundle.main.bundleURL.pathExtension == "app"
        #else
            return true
        #endif
    }

    private nonisolated static var legacyFilesMirrorDirectory: URL {
        FilePath.workingDirectory.appendingPathComponent("profiles", isDirectory: true)
    }

    private nonisolated static func backupFileName(profileID: Int64?, path: String) -> String {
        let pathFileName = URL(fileURLWithPath: path).lastPathComponent
        if !pathFileName.isEmpty {
            return pathFileName
        }
        return "config_\(profileID ?? 0).json"
    }

    private nonisolated static func writeBackup(_ content: String, profileID: Int64, path: String, directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        removeFilesMirrorFiles(profileID: profileID, in: directory)
        try content.write(
            to: directory.appendingPathComponent(backupFileName(profileID: profileID, path: path)),
            atomically: true,
            encoding: .utf8
        )
    }

    private nonisolated static func legacyFilesMirrorFile(profileID: Int64) -> URL? {
        let prefix = "\(profileID)-"
        guard let file = (try? FileManager.default.contentsOfDirectory(atPath: legacyFilesMirrorDirectory.path))?
            .first(where: { $0.hasPrefix(prefix) && $0.hasSuffix(".json") })
        else { return nil }
        return legacyFilesMirrorDirectory.appendingPathComponent(file)
    }

    private nonisolated static func routeRulesEqual(_ lhs: [[String: Any]], _ rhs: [[String: Any]]) -> Bool {
        guard JSONSerialization.isValidJSONObject(lhs), JSONSerialization.isValidJSONObject(rhs),
              let lhsData = try? JSONSerialization.data(withJSONObject: lhs, options: [.sortedKeys]),
              let rhsData = try? JSONSerialization.data(withJSONObject: rhs, options: [.sortedKeys])
        else { return false }
        return lhsData == rhsData
    }

    private nonisolated static func usesScriptHub(_ root: [String: Any]) -> Bool {
        let scripts = root["scripts"] as? [[String: Any]] ?? []
        if scripts.contains(where: { script in
            let tag = (script["tag"] as? String ?? "").lowercased()
            let url = (script["url"] as? String ?? "").lowercased()
            return tag.contains("script hub") || url.contains("script-hub-org/script-hub")
        }) {
            return true
        }
        let route = root["route"] as? [String: Any]
        let rules = route?["rules"] as? [[String: Any]] ?? []
        return rules.contains { rule in
            guard let mitm = rule["mitm"] as? [String: Any],
                  let bindings = mitm["surge_script"] as? [[String: Any]]
            else { return false }
            return bindings.contains { binding in
                let tag = (binding["tag"] as? String ?? "").lowercased()
                let patterns = binding["pattern"] as? [String] ?? []
                return tag.contains("script hub") || patterns.contains(where: { $0.lowercased().contains("script\\.hub") })
            }
        }
    }

    @discardableResult
    private nonisolated static func ensureScriptHubDNS(in root: inout [String: Any]) -> Bool {
        var dns = root["dns"] as? [String: Any] ?? [:]
        var servers = dns["servers"] as? [[String: Any]] ?? []
        var rules = dns["rules"] as? [[String: Any]] ?? []
        let tag = "mitm-virtual-hosts"
        let domains = ["script.hub", "www.script.hub"]

        var changed = false
        let server: [String: Any] = [
            "type": "hosts",
            "tag": tag,
            "predefined": [
                "script.hub": "198.18.0.1",
                "www.script.hub": "198.18.0.1",
            ],
        ]
        if let index = servers.firstIndex(where: { ($0["tag"] as? String) == tag }) {
            if canonicalJSON(servers[index]) != canonicalJSON(server) {
                servers[index] = server
                changed = true
            }
        } else {
            servers.append(server)
            changed = true
        }

        let dnsRule: [String: Any] = [
            "domain": domains,
            "action": "route",
            "server": tag,
        ]
        let matchingRuleIndex = rules.firstIndex { rule in
            (rule["server"] as? String) == tag || Set(stringArray(rule["domain"])).isSuperset(of: domains)
        }
        if let matchingRuleIndex {
            if canonicalJSON(rules[matchingRuleIndex]) != canonicalJSON(dnsRule) {
                rules[matchingRuleIndex] = dnsRule
                changed = true
            }
            if matchingRuleIndex != 0 {
                let rule = rules.remove(at: matchingRuleIndex)
                rules.insert(rule, at: 0)
                changed = true
            }
        } else {
            rules.insert(dnsRule, at: 0)
            changed = true
        }

        if changed {
            dns["servers"] = servers
            dns["rules"] = rules
            root["dns"] = dns
        }
        return changed
    }

    private nonisolated static func stringArray(_ value: Any?) -> [String] {
        if let value = value as? String { return [value] }
        return value as? [String] ?? []
    }

    private nonisolated static func canonicalJSON(_ object: [String: Any]) -> Data? {
        guard JSONSerialization.isValidJSONObject(object) else { return nil }
        return try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    private nonisolated static func removeFilesMirrorFiles(profileID: Int64, in directory: URL) {
        let prefix = "\(profileID)-"
        let configName = "config_\(profileID).json"
        for file in (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        where file == configName || file.hasPrefix(prefix) {
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(file))
        }
    }
}
