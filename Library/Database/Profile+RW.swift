import Foundation

public extension Profile {
    func read() throws -> String {
        #if DEBUG
            precondition(!Thread.isMainThread, "Profile.read() must not be called on the main thread")
        #endif
        switch type {
        case .local, .remote:
            try Profile.restoreProfileFileIfNeeded(profileID: id, path: path)
            let url = FilePath.sharedDirectory.appendingPathComponent(path)
            let content = try String(contentsOf: url)
            if let repaired = Profile.normalizedMITMRuntimeContent(content) {
                try repaired.write(to: url, atomically: true, encoding: .utf8)
                updateFilesMirror(content: repaired)
                return repaired
            }
            return content
        case .icloud:
            return try String(contentsOf: FilePath.iCloudDirectory.appendingPathComponent(path))
        }
    }

    func write(_ content: String) throws {
        #if DEBUG
            precondition(!Thread.isMainThread, "Profile.write(...) must not be called on the main thread")
        #endif
        switch type {
        case .local, .remote:
            try content.write(to: FilePath.sharedDirectory.appendingPathComponent(path), atomically: true, encoding: .utf8)
        case .icloud:
            try content.write(to: FilePath.iCloudDirectory.appendingPathComponent(path), atomically: true, encoding: .utf8)
        }
        updateFilesMirror(content: content)
    }

    func readAsync() async throws -> String {
        let type = type
        let path = path
        let profileID = id
        let result: (String, Bool) = try await BlockingIO.run {
            switch type {
            case .local, .remote:
                try Profile.restoreProfileFileIfNeeded(profileID: profileID, path: path)
                let url = FilePath.sharedDirectory.appendingPathComponent(path)
                let content = try String(contentsOf: url)
                if let repaired = Profile.normalizedMITMRuntimeContent(content) {
                    try repaired.write(to: url, atomically: true, encoding: .utf8)
                    return (repaired, true)
                }
                return (content, false)
            case .icloud:
                return (try String(contentsOf: FilePath.iCloudDirectory.appendingPathComponent(path)), false)
            }
        }
        if result.1 {
            updateFilesMirror(content: result.0)
        }
        return result.0
    }

    func writeAsync(_ content: String) async throws {
        let type = type
        let path = path
        let content = content
        try await BlockingIO.run {
            switch type {
            case .local, .remote:
                try content.write(to: FilePath.sharedDirectory.appendingPathComponent(path), atomically: true, encoding: .utf8)
            case .icloud:
                try content.write(to: FilePath.iCloudDirectory.appendingPathComponent(path), atomically: true, encoding: .utf8)
            }
        }
        updateFilesMirror(content: content)
    }
}
