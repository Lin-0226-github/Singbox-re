#if os(iOS) || os(macOS)
    import Foundation

    struct SurgeModulePayload {
        var name: String
        var moduleDescription: String
        var scripts: [[String: Any]]
        var rules: [[String: Any]]
    }

    enum SurgeModuleParserError: LocalizedError {
        case missingName
        case missingHostname
        case invalidScript(String)
        case unsupportedRewrite(String)
        case unsupportedFeature(String)
        case unsupportedPlatform(String)

        var errorDescription: String? {
            switch self {
            case .missingName:
                return "The module has no name."
            case .missingHostname:
                return "The module uses MITM features but has no [MITM] hostname entry."
            case let .invalidScript(line):
                return "Invalid script entry: \(line)"
            case let .unsupportedRewrite(line):
                return "Unsupported Loon rewrite: \(line)"
            case let .unsupportedFeature(line):
                return "Unsupported Surge module feature: \(line)"
            case let .unsupportedPlatform(platform):
                return "This Surge module is only available on \(platform)."
            }
        }
    }

    enum SurgeModuleParser {
        static func parse(
            _ content: String,
            sourceURL: URL,
            downloadDetour: String,
            updateInterval: String
        ) throws -> SurgeModulePayload {
            var name = ""
            var description = ""
            var section = ""
            var sections: [String: [String]] = [:]

            // Surge parameter tables substitute declared defaults before the
            // module is parsed. Custom values can be added to the UI later;
            // using defaults already makes parameterized public modules work.
            var argumentDefaults: [String: String] = [:]
            var requiredPlatform = ""
            for rawLine in content.components(separatedBy: .newlines) {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if let platform = metadataValue(line, key: "system") {
                    requiredPlatform = platform.lowercased()
                }
                guard let arguments = metadataValue(line, key: "arguments") else { continue }
                for declaration in splitTopLevel(arguments, separator: ",") {
                    let pair = splitOnce(declaration, separator: ":")
                    let key = pair[0].trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !key.isEmpty else { continue }
                    argumentDefaults[key] = pair.count == 2 ? unquote(pair[1].trimmingCharacters(in: .whitespacesAndNewlines)) : ""
                }
            }
            if !requiredPlatform.isEmpty, !currentPlatformAliases.contains(requiredPlatform) {
                throw SurgeModuleParserError.unsupportedPlatform(requiredPlatform)
            }
            var expandedContent = content
            for (key, value) in argumentDefaults {
                expandedContent = expandedContent.replacingOccurrences(of: "{{{\(key)}}}", with: value)
            }

            for rawLine in expandedContent.components(separatedBy: .newlines) {
                guard let conditionalLine = platformConditionalLine(rawLine) else { continue }
                let line = conditionalLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if let value = metadataValue(line, key: "name") {
                    name = value
                    continue
                }
                if let value = metadataValue(line, key: "desc") {
                    description = value.replacingOccurrences(of: #"\n"#, with: "\n")
                    continue
                }
                if line.hasPrefix("["), line.hasSuffix("]") {
                    section = String(line.dropFirst().dropLast()).lowercased()
                    continue
                }
                if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") || section.isEmpty {
                    continue
                }
                sections[section, default: []].append(line)
            }

            if name.isEmpty {
                name = sourceURL.deletingPathExtension().lastPathComponent
            }
            guard !name.isEmpty else { throw SurgeModuleParserError.missingName }

            let moduleInterval = updateInterval.trimmingCharacters(in: .whitespacesAndNewlines)
            let moduleDetour = downloadDetour.trimmingCharacters(in: .whitespacesAndNewlines)
            var scriptDefinitions: [[String: Any]] = []
            var scriptBindings: [[String: Any]] = []

            for line in sections["script", default: []] {
                let parsed = parseScriptLine(line)
                let tag = parsed.tag
                guard !tag.isEmpty else { throw SurgeModuleParserError.invalidScript(line) }
                let options = parsed.options
                guard let scriptPath = options["script-path"], !scriptPath.isEmpty else {
                    throw SurgeModuleParserError.invalidScript(line)
                }
                let resolvedURL = URL(string: scriptPath, relativeTo: sourceURL)?.absoluteURL.absoluteString ?? scriptPath
                var definition: [String: Any] = [
                    "type": "surge",
                    "tag": tag,
                    "source": "remote",
                    "url": resolvedURL,
                ]
                if !moduleDetour.isEmpty {
                    definition["download_detour"] = moduleDetour
                }
                let scriptInterval = normalizedInterval(options["script-update-interval"], fallback: moduleInterval)
                if !scriptInterval.isEmpty {
                    definition["update_interval"] = scriptInterval
                }
                let event = options["type"]?.lowercased() ?? "generic"
                if event == "cron", let expression = options["cronexp"], !expression.isEmpty {
                    var cron: [String: Any] = ["expression": expression]
                    if let timeout = options["timeout"], !timeout.isEmpty {
                        cron["timeout"] = normalizedInterval(timeout, fallback: "")
                    }
                    if let argument = options["argument"], !argument.isEmpty {
                        cron["arguments"] = [argument]
                    }
                    definition["cron"] = cron
                }
                scriptDefinitions.append(definition)

                guard event == "http-request" || event == "http-response" else { continue }
                var binding: [String: Any] = [
                    "tag": tag,
                    "type": [event],
                ]
                if let pattern = options["pattern"], !pattern.isEmpty {
                    binding["pattern"] = [normalizeRegex(pattern)]
                }
                if boolValue(options["requires-body"]) {
                    binding["requires_body"] = true
                }
                if boolValue(options["binary-body-mode"]) {
                    binding["binary_body_mode"] = true
                }
                if boolValue(options["full-header-mode"]) {
                    binding["full_header_mode"] = true
                }
                if let maxSize = Int64(options["max-size"] ?? "") {
                    binding["max_size"] = maxSize == 0 ? 10 * 1024 * 1024 : maxSize
                }
                if let timeout = options["timeout"], !timeout.isEmpty {
                    binding["timeout"] = normalizedInterval(timeout, fallback: "")
                }
                if let argument = options["argument"], !argument.isEmpty {
                    binding["arguments"] = [argument]
                }
                scriptBindings.append(binding)
            }

            var moduleRules: [[String: Any]] = []
            var forceHTTPHostnames: [String] = []
            for line in sections["general", default: []] {
                let pair = splitOnce(line, separator: "=")
                guard pair.count == 2,
                      pair[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "force-http-engine-hosts"
                else { continue }
                forceHTTPHostnames.append(contentsOf: splitTopLevel(pair[1], separator: ",").map {
                    $0.replacingOccurrences(of: "%APPEND%", with: "", options: .caseInsensitive)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty })
            }
            if !forceHTTPHostnames.isEmpty {
                moduleRules.append([
                    "type": "logical",
                    "mode": "and",
                    "rules": [hostnameMatchRule(forceHTTPHostnames), ["protocol": "quic"]],
                    "action": "reject",
                ])
            }
            var urlRegexRewrites: [String] = []
            for line in sections["rule", default: []] {
                if let urlRewrite = parseURLRegexRule(line) {
                    urlRegexRewrites.append(urlRewrite)
                } else if let rule = parseRule(line) {
                    moduleRules.append(rule)
                }
            }
            var headerRewrites = sections["header rewrite", default: []].map(normalizeHeaderRewrite)
            var urlRewrites = sections["url rewrite", default: []].map(normalizeRewrite) + urlRegexRewrites
            let bodyRewrites = sections["body rewrite", default: []].map(normalizeRegex)
            var mapLocal = sections["map local", default: []].map(normalizeMapLocal)
            for line in sections["rewrite", default: []] {
                let conversion = try parseLoonRewrite(line)
                urlRewrites.append(contentsOf: conversion.url)
                headerRewrites.append(contentsOf: conversion.header)
                mapLocal.append(contentsOf: conversion.mapLocal)
            }

            var hostnames: [String] = []
            for line in sections["mitm", default: []] {
                let pair = splitOnce(line, separator: "=")
                guard pair.count == 2, pair[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "hostname" else {
                    continue
                }
                hostnames.append(contentsOf: splitTopLevel(pair[1], separator: ",").map {
                    $0.replacingOccurrences(of: "%APPEND%", with: "", options: .caseInsensitive)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                }.filter { !$0.isEmpty })
            }

            let usesMITM = !headerRewrites.isEmpty || !urlRewrites.isEmpty || !bodyRewrites.isEmpty || !mapLocal.isEmpty || !scriptBindings.isEmpty
            if usesMITM || !hostnames.isEmpty {
                guard !hostnames.isEmpty else { throw SurgeModuleParserError.missingHostname }
                var mitm: [String: Any] = ["enabled": true]
                assign(&mitm, key: "surge_header_rewrite", values: headerRewrites)
                assign(&mitm, key: "surge_url_rewrite", values: urlRewrites)
                assign(&mitm, key: "surge_body_rewrite", values: bodyRewrites)
                assign(&mitm, key: "surge_map_local", values: mapLocal)
                if !scriptBindings.isEmpty {
                    mitm["surge_script"] = scriptBindings
                }
                moduleRules.append(mitmRule(hostnames: hostnames, options: mitm))
            }

            return SurgeModulePayload(
                name: name,
                moduleDescription: description,
                scripts: deduplicated(scriptDefinitions, key: "tag"),
                rules: moduleRules
            )
        }

        private static func isRuleFlag(_ field: String) -> Bool {
            switch field.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "no-resolve", "pre-matching", "extended-matching":
                return true
            default:
                return false
            }
        }

        private static func parseRule(_ line: String) -> [String: Any]? {
            let fields = splitTopLevel(line, separator: ",")
            guard fields.count >= 3 else { return nil }
            var actionIndex = fields.count - 1
            while actionIndex > 0, isRuleFlag(fields[actionIndex]) {
                actionIndex -= 1
            }
            guard actionIndex >= 1,
                  let action = routeAction(fields[actionIndex])
            else { return nil }
            let expression = fields[..<actionIndex].joined(separator: ",")
            guard var rule = parseExpression(expression) else { return nil }
            rule.merge(action) { _, new in new }
            return rule
        }

        private static func parseScriptLine(_ line: String) -> (tag: String, options: [String: String]) {
            let leadingType = line.split(whereSeparator: { $0.isWhitespace }).first?.lowercased() ?? ""
            if ["http-request", "http-response", "rule", "dns", "event", "cron", "generic"].contains(leadingType) {
                return parseLegacyScriptLine(line)
            }
            if let delimiter = line.firstIndex(of: "=") {
                let tag = String(line[..<delimiter]).trimmingCharacters(in: .whitespacesAndNewlines)
                let value = String(line[line.index(after: delimiter)...])
                var options: [String: String] = [:]
                for field in splitTopLevel(value, separator: ",") {
                    let optionPair = splitOnce(field, separator: "=")
                    if optionPair.count == 2 {
                        options[optionPair[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()] =
                            unquote(optionPair[1].trimmingCharacters(in: .whitespacesAndNewlines))
                    }
                }
                options["type"] = options["type"] ?? "generic"
                return (tag, options)
            }
            let tokens = splitTopLevel(line, separator: " ").filter { !$0.isEmpty }
            guard tokens.count >= 3, !tokens[0].contains("=") else { return ("", [:]) }
            let type = tokens[0].lowercased()
            var options: [String: String] = [
                "type": type,
            ]
            switch type {
            case "http-request", "http-response": options["pattern"] = unquote(tokens[1])
            case "cron": options["cronexp"] = unquote(tokens[1])
            case "event": options["event-name"] = unquote(tokens[1])
            default: break
            }
            let optionText = tokens.dropFirst(2).joined(separator: " ")
            for token in splitTopLevel(optionText, separator: ",") {
                let optionPair = splitOnce(token, separator: "=")
                guard optionPair.count == 2 else { continue }
                options[optionPair[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()] =
                    unquote(optionPair[1].trimmingCharacters(in: .whitespacesAndNewlines))
            }
            let tag = options["tag"] ?? options["name"] ?? scriptName(from: options["script-path"])
            return (tag, options)
        }

        private static func parseLegacyScriptLine(_ line: String) -> (tag: String, options: [String: String]) {
            let tokens = splitTopLevel(line, separator: " ").filter { !$0.isEmpty }
            guard tokens.count >= 3 else { return ("", [:]) }
            let type = tokens[0].lowercased()
            var options: [String: String] = ["type": type]
            switch type {
            case "http-request", "http-response": options["pattern"] = unquote(tokens[1])
            case "cron": options["cronexp"] = unquote(tokens[1])
            case "event": options["event-name"] = unquote(tokens[1])
            default: break
            }
            let optionText = tokens.dropFirst(2).joined(separator: " ")
            for token in splitTopLevel(optionText, separator: ",") {
                let optionPair = splitOnce(token, separator: "=")
                guard optionPair.count == 2 else { continue }
                options[optionPair[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()] =
                    unquote(optionPair[1].trimmingCharacters(in: .whitespacesAndNewlines))
            }
            let tag = options["tag"] ?? options["name"] ?? scriptName(from: options["script-path"])
            return (tag, options)
        }

        private static func parseURLRegexRule(_ line: String) -> String? {
            var fields = splitTopLevel(line, separator: ",")
            guard fields.count >= 3, fields[0].trimmingCharacters(in: .whitespacesAndNewlines).uppercased() == "URL-REGEX" else { return nil }
            while fields.count > 2, isRuleFlag(fields[fields.count - 1]) {
                fields.removeLast()
            }
            guard fields.count >= 3,
                  fields[fields.count - 1].trimmingCharacters(in: .whitespacesAndNewlines).uppercased().hasPrefix("REJECT")
            else { return nil }
            return normalizeRegex(fields[1]) + " _ reject"
        }

        private static func parseExpression(_ value: String) -> [String: Any]? {
            let expression = unwrap(value)
            let fields = splitTopLevel(expression, separator: ",")
            guard let first = fields.first?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() else { return nil }
            if first == "AND" || first == "OR" {
                let children = parseChildren(Array(fields.dropFirst()))
                guard !children.isEmpty else { return nil }
                return ["type": "logical", "mode": first.lowercased(), "rules": children]
            }
            if first == "NOT" {
                let children = parseChildren(Array(fields.dropFirst()))
                guard children.count == 1 else { return nil }
                var child = children[0]
                child["invert"] = !(child["invert"] as? Bool ?? false)
                return child
            }
            return matcherFields(fields)
        }

        private static func parseChildren(_ values: [String]) -> [[String: Any]] {
            var values = values
            if values.count == 1 {
                var container = values[0].trimmingCharacters(in: .whitespacesAndNewlines)
                if hasOuterParentheses(container) {
                    container = String(container.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
                }
                values = splitTopLevel(container, separator: ",")
            }
            return values.compactMap(parseExpression)
        }

        private static func unwrap(_ value: String) -> String {
            var value = value.trimmingCharacters(in: .whitespacesAndNewlines)
            while hasOuterParentheses(value) {
                value = String(value.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
            }
            return value
        }

        private static func hasOuterParentheses(_ value: String) -> Bool {
            guard value.first == "(", value.last == ")" else { return false }
            var depth = 0
            var quote: Character?
            var escaped = false
            for (index, character) in value.enumerated() {
                if escaped { escaped = false; continue }
                if character == "\\" { escaped = true; continue }
                if character == "\"" || character == "'" {
                    if quote == character { quote = nil } else if quote == nil { quote = character }
                    continue
                }
                guard quote == nil else { continue }
                if character == "(" { depth += 1 }
                if character == ")" { depth -= 1 }
                if depth == 0 && index != value.count - 1 { return false }
            }
            return depth == 0
        }

        private static func normalizeRewrite(_ line: String) -> String {
            let fields = splitTopLevel(line, separator: " ").filter { !$0.isEmpty }.map(unquote)
            guard fields.count >= 2 else { return normalizeRegex(line) }
            let pattern = normalizeRegex(fields[0])
            if fields[1].lowercased() == "reject" {
                return pattern + " _ reject"
            }
            let action = fields.count >= 3 ? fields[2].lowercased() : "header"
            switch action {
            case "header", "301", "302", "307", "308", "reject":
                return ([pattern, fields[1], action]).joined(separator: " ")
            default:
                return ([pattern, fields[1], "header"]).joined(separator: " ")
            }
        }

        private static func normalizeHeaderRewrite(_ line: String) -> String {
            let normalized = normalizeRegex(line)
            let first = splitTopLevel(normalized, separator: " ").first?.lowercased()
            if first == "http-request" || first == "http-response" { return normalized }
            return "http-request " + normalized
        }

        private static func normalizeMapLocal(_ line: String) -> String {
            let normalized = normalizeRegex(line)
            let fields = splitTopLevel(normalized, separator: " ").filter { !$0.isEmpty }
            guard !fields.isEmpty else { return normalized }
            if fields.dropFirst().contains(where: { $0.lowercased().hasPrefix("data-type=") }) {
                return normalized
            }
            return ([fields[0], "data-type=file"] + fields.dropFirst()).joined(separator: " ")
        }

        private struct LoonRewriteConversion {
            var url: [String] = []
            var header: [String] = []
            var mapLocal: [String] = []
        }

        private static func parseLoonRewrite(_ line: String) throws -> LoonRewriteConversion {
            let fields = splitTopLevel(line, separator: " ").filter { !$0.isEmpty }
            guard fields.count >= 2 else { throw SurgeModuleParserError.unsupportedRewrite(line) }
            let pattern = normalizeRegex(fields[0])
            let action = fields[1].lowercased()
            var result = LoonRewriteConversion()
            switch action {
            case "reject":
                result.url = [pattern + " _ reject"]
            case "reject-dict":
                result.mapLocal = [pattern + " data-type=text data={} status-code=200 header=Content-Type:application/json"]
            case "reject-array":
                result.mapLocal = [pattern + " data-type=text data=[] status-code=200 header=Content-Type:application/json"]
            case "reject-200":
                result.mapLocal = [pattern + " data-type=text data= status-code=200"]
            case "mock-response-body":
                var options = Array(fields.dropFirst(2))
                let base64 = options.contains { $0.lowercased() == "mock-data-is-base64=true" }
                options.removeAll { $0.lowercased() == "mock-data-is-base64=true" }
                if base64 {
                    options = options.map { $0.lowercased() == "data-type=text" ? "data-type=base64" : $0 }
                }
                if !options.contains(where: { $0.lowercased().hasPrefix("status-code=") }) {
                    options.append("status-code=200")
                }
                result.mapLocal = [([pattern] + options).joined(separator: " ")]
            case "response-header-add", "request-header-add":
                guard fields.count >= 4 else { throw SurgeModuleParserError.unsupportedRewrite(line) }
                let event = action.hasPrefix("response") ? "http-response" : "http-request"
                result.header = ["\(event) \(pattern) header-add \(fields[2]) \(fields.dropFirst(3).joined(separator: " "))"]
            case "response-header-del", "request-header-del":
                guard fields.count >= 3 else { throw SurgeModuleParserError.unsupportedRewrite(line) }
                let event = action.hasPrefix("response") ? "http-response" : "http-request"
                result.header = ["\(event) \(pattern) header-del \(fields[2])"]
            default:
                throw SurgeModuleParserError.unsupportedRewrite(line)
            }
            return result
        }

        private static func matcherFields(_ fields: [String]) -> [String: Any]? {
            guard fields.count >= 2 else { return nil }
            let type = fields[0].trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            let target = fields[1].trimmingCharacters(in: .whitespacesAndNewlines)
            switch type {
            case "DOMAIN": return ["domain": target]
            case "DOMAIN-SUFFIX": return ["domain_suffix": target]
            case "DOMAIN-KEYWORD": return ["domain_keyword": target]
            case "DOMAIN-WILDCARD": return ["domain_regex": globRegex(target)]
            case "IP-CIDR", "IP-CIDR6": return ["ip_cidr": target]
            case "SRC-IP": return ["source_ip_cidr": target]
            case "GEOIP": return ["geoip": target.lowercased()]
            case "PROTOCOL": return ["protocol": target.lowercased()]
            case "NETWORK": return ["network": target.lowercased()]
            case "PROCESS-NAME":
                if target.hasPrefix("/") { return ["process_path": target] }
                return ["process_name": target]
            case "SRC-PORT": return portMatcher(target, exact: "source_port", range: "source_port_range")
            case "PORT", "DEST-PORT": return portMatcher(target, exact: "port", range: "port_range")
            default: return nil
            }
        }

        private static func matcherFields(_ value: String) -> [String: Any]? {
            matcherFields(splitTopLevel(value, separator: ","))
        }

        private static func routeAction(_ value: String) -> [String: Any]? {
            let action = value.trimmingCharacters(in: .whitespacesAndNewlines)
            let upper = action.uppercased()
            if upper.hasPrefix("REJECT") {
                return ["action": "reject"]
            }
            if upper == "DIRECT" {
                return ["action": "direct"]
            }
            return action.isEmpty ? nil : ["outbound": action]
        }

        private static func mitmRule(hostnames: [String], options: [String: Any]) -> [String: Any] {
            var result = hostnameMatchRule(hostnames)
            result["action"] = "route-options"
            result["mitm"] = options
            return result
        }

        private static func hostnameMatchRule(_ hostnames: [String]) -> [String: Any] {
            var includes: [[String: Any]] = []
            var excludes: [[String: Any]] = []
            for rawHostname in hostnames {
                let excluded = rawHostname.hasPrefix("-")
                let hostname = excluded ? String(rawHostname.dropFirst()) : rawHostname
                guard var matcher = hostnameMatcher(hostname) else { continue }
                if excluded { matcher["invert"] = true }
                if excluded { excludes.append(matcher) } else { includes.append(matcher) }
            }
            if includes.isEmpty {
                includes.append(["domain_regex": ".*"])
            }
            let includeRule: [String: Any]
            if includes.count == 1 {
                includeRule = includes[0]
            } else {
                includeRule = ["type": "logical", "mode": "or", "rules": includes]
            }
            let matchRule: [String: Any]
            if excludes.isEmpty {
                matchRule = includeRule
            } else {
                matchRule = ["type": "logical", "mode": "and", "rules": [includeRule] + excludes]
            }
            return matchRule
        }

        private static func hostnameMatcher(_ value: String) -> [String: Any]? {
            var hostname = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !hostname.isEmpty else { return nil }
            var port: Int?
            if let separator = hostname.lastIndex(of: ":"),
               !hostname.hasSuffix("]"),
               let parsedPort = Int(hostname[hostname.index(after: separator)...])
            {
                port = parsedPort
                hostname = String(hostname[..<separator])
            }
            var matcher: [String: Any]
            if hostname == "*" {
                matcher = ["domain_regex": ".*"]
            } else if hostname.hasPrefix("*.") {
                matcher = ["domain_suffix": String(hostname.dropFirst(2))]
            } else if hostname.contains("*") || hostname.contains("?") || hostname.contains("[") {
                matcher = ["domain_regex": globRegex(hostname)]
            } else {
                matcher = ["domain": hostname]
            }
            if let port, port > 0 { matcher["port"] = port }
            return matcher
        }

        private static func splitTopLevel(_ value: String, separator: Character) -> [String] {
            var result: [String] = []
            var current = ""
            var depth = 0
            var quote: Character?
            var escaped = false
            for character in value {
                if escaped {
                    current.append(character)
                    escaped = false
                    continue
                }
                if character == "\\" {
                    current.append(character)
                    escaped = true
                    continue
                }
                if character == "\"" || character == "'" {
                    if quote == character { quote = nil } else if quote == nil { quote = character }
                    current.append(character)
                    continue
                }
                if quote == nil {
                    if "([{<".contains(character) { depth += 1 }
                    if ")]}>".contains(character) { depth = max(0, depth - 1) }
                    if character == separator, depth == 0 {
                        result.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
                        current = ""
                        continue
                    }
                }
                current.append(character)
            }
            result.append(current.trimmingCharacters(in: .whitespacesAndNewlines))
            return result
        }

        private static func splitOnce(_ value: String, separator: Character) -> [String] {
            guard let index = value.firstIndex(of: separator) else { return [value] }
            return [String(value[..<index]), String(value[value.index(after: index)...])]
        }

        private static func normalizeRegex(_ value: String) -> String {
            value.replacingOccurrences(of: #"\/"#, with: "/")
        }

        private static func metadataValue(_ line: String, key: String) -> String? {
            let prefix = "#!\(key)"
            guard line.lowercased().hasPrefix(prefix.lowercased()) else { return nil }
            let remainder = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespacesAndNewlines)
            guard remainder.hasPrefix("=") else { return nil }
            return remainder.dropFirst().trimmingCharacters(in: .whitespacesAndNewlines)
        }

        private static func platformConditionalLine(_ rawLine: String) -> String? {
            var line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            let current: String
            #if os(iOS)
                current = "IOS"
            #elseif os(macOS)
                current = "MACOS"
            #else
                current = "TVOS"
            #endif
            for platform in ["IOS", "MACOS", "TVOS"] {
                let marker = "#!\(platform)-ONLY"
                if line.uppercased().hasPrefix(marker) {
                    guard platform == current else { return nil }
                    line = String(line.dropFirst(marker.count)).trimmingCharacters(in: .whitespacesAndNewlines)
                }
                if let range = line.range(of: marker, options: [.caseInsensitive, .backwards]) {
                    guard platform == current else { return nil }
                    line = String(line[..<range.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
            // End-of-line requirements are comments on older Surge versions.
            // Keep the line and remove the condition so supported content loads.
            for marker in [" //!REQUIREMENT", " #!REQUIREMENT"] {
                if let range = line.range(of: marker, options: [.caseInsensitive, .backwards]) {
                    line = String(line[..<range.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
                }
            }
            return line
        }

        private static var currentPlatformAliases: Set<String> {
            #if os(iOS)
                return ["ios"]
            #elseif os(macOS)
                return ["mac", "macos"]
            #else
                return ["tvos"]
            #endif
        }

        private static func unquote(_ value: String) -> String {
            guard value.count >= 2,
                  let first = value.first,
                  first == value.last,
                  first == "\"" || first == "'"
            else { return value }
            return String(value.dropFirst().dropLast())
        }

        private static func scriptName(from path: String?) -> String {
            guard let path, !path.isEmpty else { return "" }
            let url = URL(string: unquote(path))
            let component = url?.deletingPathExtension().lastPathComponent ?? ""
            return component.removingPercentEncoding ?? component
        }

        private static func globRegex(_ value: String) -> String {
            var result = "^"
            var inCharacterClass = false
            for character in value {
                switch character {
                case "*": result += ".*"
                case "?": result += "."
                case "[": inCharacterClass = true; result.append(character)
                case "]": inCharacterClass = false; result.append(character)
                default:
                    if !inCharacterClass, #"\.^$|(){}+"#.contains(character) { result.append("\\") }
                    result.append(character)
                }
            }
            return result + "$"
        }

        private static func portMatcher(_ value: String, exact: String, range: String) -> [String: Any]? {
            if let port = Int(value) { return [exact: port] }
            if value.contains("-") { return [range: value] }
            if value.hasPrefix(">=") { return [range: "\(value.dropFirst(2))-65535"] }
            if value.hasPrefix(">") { return Int(value.dropFirst()).map { [range: "\($0 + 1)-65535"] } }
            if value.hasPrefix("<=") { return [range: "0-\(value.dropFirst(2))"] }
            if value.hasPrefix("<") { return Int(value.dropFirst()).map { [range: "0-\(max(0, $0 - 1))"] } }
            return nil
        }

        private static func boolValue(_ value: String?) -> Bool {
            guard let value else { return false }
            return ["1", "true", "yes"].contains(value.lowercased())
        }

        private static func normalizedInterval(_ value: String?, fallback: String) -> String {
            guard let value, !value.isEmpty, value != "0" else { return fallback }
            if Int(value) != nil { return value + "s" }
            return value
        }

        private static func assign(_ object: inout [String: Any], key: String, values: [String]) {
            if !values.isEmpty { object[key] = values }
        }

        private static func captureGroups(_ value: String, pattern: String) -> [String] {
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
            let range = NSRange(value.startIndex..., in: value)
            return regex.matches(in: value, range: range).compactMap { match in
                guard match.numberOfRanges > 1, let range = Range(match.range(at: 1), in: value) else { return nil }
                return String(value[range])
            }
        }

        private static func deduplicated(_ values: [[String: Any]], key: String) -> [[String: Any]] {
            var seen: Set<String> = []
            return values.filter { value in
                guard let item = value[key] as? String else { return true }
                return seen.insert(item).inserted
            }
        }
    }
#endif
