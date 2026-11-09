// PQCC macOS URLSession client (Network.framework TLS, Security.framework trust evaluation).
// Usage: version | <variant> <mode> <host> <port>. Certificates from $PQCC_CERTS.
//
// Trust: the variant's root is the only anchor (SecTrustSetAnchorCertificatesOnly) under the
// SSL policy for the hostname, so the chain, validity, EKU and name are all still checked.
// mTLS: the identity comes from client.p12, imported in memory only (no keychain changes).
import Foundation
import Security

setvbuf(stdout, nil, _IOLBF, 0)

func fail(_ stage: String, _ detail: String) -> Never {
    FileHandle.standardError.write("stage failed: \(stage)\n\(detail)\n".data(using: .utf8)!)
    exit(1)
}

func describe(_ error: Error) -> String {
    var lines: [String] = []
    var e: NSError? = error as NSError
    while let x = e {
        var line = "\(x.domain) \(x.code): \(x.localizedDescription)"
        for key in ["_kCFStreamErrorDomainKey", "_kCFStreamErrorCodeKey", "NSErrorFailingURLStringKey"] {
            if let v = x.userInfo[key] { line += " [\(key)=\(v)]" }
        }
        lines.append(line)
        e = x.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    return lines.joined(separator: "\n")
}

func loadPEMCertificate(_ path: String) throws -> SecCertificate {
    let pem = try String(contentsOfFile: path, encoding: .utf8)
    let b64 = pem.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
    guard let der = Data(base64Encoded: b64), let cert = SecCertificateCreateWithData(nil, der as CFData)
    else { throw NSError(domain: "pqcc", code: 1, userInfo: [NSLocalizedDescriptionKey: "SecCertificateCreateWithData returned nil for \(path)"]) }
    return cert
}

let args = Array(CommandLine.arguments.dropFirst())
if args == ["version"] {
    let os = ProcessInfo.processInfo.operatingSystemVersionString
    let cfnetwork = Bundle(identifier: "com.apple.CFNetwork")?.infoDictionary?["CFBundleVersion"] as? String ?? "?"
    print("URLSession on macOS \(os) (CFNetwork \(cfnetwork))")
    exit(0)
}
let (variant, mode, host, port) = (args[0], args[1], args[2], args[3])
let dir = (ProcessInfo.processInfo.environment["PQCC_CERTS"] ?? "/certs/out") + "/" + variant

let root: SecCertificate
do { root = try loadPEMCertificate(dir + "/root.crt") } catch { fail("parse root certificate", describe(error)) }

var identity: SecIdentity?
var clientChain: [SecCertificate] = []
if mode == "mtls" {
    guard let p12 = FileManager.default.contents(atPath: dir + "/client.p12") else { fail("load client certificate/key", "cannot read client.p12") }
    var items: CFArray?
    let status = SecPKCS12Import(p12 as CFData, [kSecImportExportPassphrase as String: "pqcc",
                                                  kSecImportToMemoryOnly as String: true] as CFDictionary, &items)
    guard status == errSecSuccess, let first = (items as? [[String: Any]])?.first,
          let id = first[kSecImportItemIdentity as String] else {
        fail("load client certificate/key", "SecPKCS12Import: OSStatus \(status) \(SecCopyErrorMessageString(status, nil) as String? ?? "")")
    }
    identity = (id as! SecIdentity)
    // The p12 carries the intermediate too; send it after the leaf.
    let chain = (first[kSecImportItemCertChain as String] as? [SecCertificate]) ?? []
    clientChain = Array(chain.dropFirst())
    print("Client identity imported (chain length \(chain.count))")
}

final class Delegate: NSObject, URLSessionTaskDelegate {
    var metrics: URLSessionTaskMetrics?

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let method = challenge.protectionSpace.authenticationMethod
        if method == NSURLAuthenticationMethodServerTrust, let trust = challenge.protectionSpace.serverTrust {
            SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
            SecTrustSetAnchorCertificates(trust, [root] as CFArray)
            SecTrustSetAnchorCertificatesOnly(trust, true)
            var error: CFError?
            let ok = SecTrustEvaluateWithError(trust, &error)
            for cert in (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? [] {
                print("  chain: \(SecCertificateCopySubjectSummary(cert) as String? ?? "?")")
            }
            if ok {
                completionHandler(.useCredential, URLCredential(trust: trust))
            } else {
                print("verify error: \(error.map { describe($0 as Error) } ?? "unknown")")
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } else if method == NSURLAuthenticationMethodClientCertificate {
            print("Server requested a client certificate (presenting: \(identity != nil))")
            if let identity {
                completionHandler(.useCredential, URLCredential(identity: identity, certificates: clientChain, persistence: .forSession))
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        self.metrics = metrics
    }
}

let config = URLSessionConfiguration.ephemeral
config.timeoutIntervalForRequest = 20
config.urlCache = nil
let delegate = Delegate()
let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
var request = URLRequest(url: URL(string: "https://\(host):\(port)/")!)
request.cachePolicy = .reloadIgnoringLocalCacheData

let done = DispatchSemaphore(value: 0)
var status = 0
var taskError: Error?
session.dataTask(with: request) { _, response, error in
    status = (response as? HTTPURLResponse)?.statusCode ?? 0
    taskError = error
    done.signal()
}.resume()
done.wait()
session.finishTasksAndInvalidate()

if let t = delegate.metrics?.transactionMetrics.last, let v = t.negotiatedTLSProtocolVersion {
    let names: [UInt16: String] = [0x0304: "TLSv1.3", 0x0303: "TLSv1.2"]
    print("Protocol version: \(names[v.rawValue] ?? String(format: "0x%04x", v.rawValue))")
    if let c = t.negotiatedTLSCipherSuite { print(String(format: "Cipher: 0x%04x", c.rawValue)) }
}
if let taskError { fail("handshake", describe(taskError)) }
print("Response: HTTP \(status)")
if status != 200 { fail("http", "unexpected status \(status)") }
