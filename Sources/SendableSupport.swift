import Foundation

/// Wrapper for passing a non-Sendable value into a @Sendable closure when the
/// transfer is provably safe (e.g. a FileHandle handed to exactly one reader
/// task, or a read-to-EOF in a termination handler). This is the documented
/// escape hatch pending `sending`/region-based isolation everywhere; each use
/// site states why it's safe.
struct UncheckedSendable<T>: @unchecked Sendable {
    let value: T
    init(_ value: T) { self.value = value }
}
