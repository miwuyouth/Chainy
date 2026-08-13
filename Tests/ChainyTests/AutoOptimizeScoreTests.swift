import XCTest
import ChainCore
@testable import Chainy

/// Coverage for `AppStore.combinedScore` and `AppStore.autoOptimizeBestChainID`
/// -- the ranking math behind the "OPTIMAL" badge and Auto-Optimize's
/// background chain switching. `combinedScore` is tested directly as a pure
/// function (fast, deterministic, no sockets); `autoOptimizeBestChainID` is
/// driven through the same public surface a real screen would use, with
/// `recordChainScore` standing in for a completed "Test Connection"/"Test
/// Bandwidth" tap so no real network probe is needed.
@MainActor
final class AutoOptimizeScoreTests: XCTestCase {
    private func makeStore() -> AppStore {
        AppStore(directoryURL: FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true))
    }

    private func chain(named name: String) -> NamedProxyChain {
        NamedProxyChain(name: name, hops: [ProxyHop(host: "127.0.0.1", port: 1080, protocolConfig: .socks5(auth: .none))])
    }

    // MARK: - combinedScore

    /// The whole point of normalizing against `maxObservedMbps` instead of a
    /// fixed ceiling: whatever chain is fastest in its own comparison set
    /// always gets full bandwidth credit, whether that top speed is 10 Mbps
    /// or 300 Mbps. A fixed ceiling (the old bug) would score these two very
    /// differently even though each is the best available in its own set.
    func testFastestChainGetsFullBandwidthCreditRegardlessOfAbsoluteSpeed() {
        let atLowSpeed = AppStore.combinedScore(latencyMs: nil, mbps: 10, maxObservedMbps: 10)
        let atHighSpeed = AppStore.combinedScore(latencyMs: nil, mbps: 300, maxObservedMbps: 300)
        XCTAssertEqual(atLowSpeed, 0.5, accuracy: 0.0001)
        XCTAssertEqual(atHighSpeed, 0.5, accuracy: 0.0001)
    }

    func testSlowerChainScoresProportionallyToTheFastestObserved() {
        let score = AppStore.combinedScore(latencyMs: nil, mbps: 5, maxObservedMbps: 10)
        XCTAssertEqual(score, 0.25, accuracy: 0.0001) // (5/10) * 0.5 weight
    }

    func testHigherBandwidthOutscoresLowerBandwidthAtEqualLatency() {
        let winner = AppStore.combinedScore(latencyMs: 100, mbps: 80, maxObservedMbps: 80)
        let loser = AppStore.combinedScore(latencyMs: 100, mbps: 20, maxObservedMbps: 80)
        XCTAssertGreaterThan(winner, loser)
        XCTAssertEqual(winner, 0.9, accuracy: 0.0001)   // (1 - 100/500)*0.5 + (80/80)*0.5
        XCTAssertEqual(loser, 0.525, accuracy: 0.0001)  // (1 - 100/500)*0.5 + (20/80)*0.5
    }

    func testMissingBandwidthFallsBackToLatencyOnly() {
        let score = AppStore.combinedScore(latencyMs: 100, mbps: nil, maxObservedMbps: 80)
        XCTAssertEqual(score, 0.4, accuracy: 0.0001) // (1 - 100/500) * 0.5 weight, bandwidth half dropped
    }

    func testMissingLatencyFallsBackToBandwidthOnly() {
        let score = AppStore.combinedScore(latencyMs: nil, mbps: 50, maxObservedMbps: 100)
        XCTAssertEqual(score, 0.25, accuracy: 0.0001) // (50/100) * 0.5 weight, latency half dropped
    }

    /// No chain in the comparison set has a bandwidth reading yet -- there's
    /// nothing to normalize against, so bandwidth must drop out rather than
    /// divide by (or against) nothing.
    func testNilMaxObservedMbpsFallsBackToLatencyOnly() {
        let score = AppStore.combinedScore(latencyMs: 100, mbps: 50, maxObservedMbps: nil)
        XCTAssertEqual(score, 0.4, accuracy: 0.0001)
    }

    /// Defensive: a zero (or negative) max shouldn't divide-by-zero/produce
    /// infinity -- this shouldn't arise from real measurements, but the guard
    /// exists precisely so a degenerate value can't corrupt the ranking.
    func testZeroMaxObservedMbpsDoesNotDivideByZero() {
        let score = AppStore.combinedScore(latencyMs: 100, mbps: 50, maxObservedMbps: 0)
        XCTAssertEqual(score, 0.4, accuracy: 0.0001)
    }

    func testNoLatencyOrBandwidthScoresZero() {
        XCTAssertEqual(AppStore.combinedScore(latencyMs: nil, mbps: nil, maxObservedMbps: nil), 0)
    }

    // MARK: - autoOptimizeBestChainID

    func testFewerThanTwoScoredChainsReturnsNil() {
        let store = makeStore()
        let a = chain(named: "A")
        store.addChain(a)
        store.recordChainScore(chainID: a.id, latencyMs: 50, mbps: 100)

        XCTAssertNil(store.autoOptimizeBestChainID)
    }

    func testPicksTheHighestScoringChainAmongSeveral() {
        let store = makeStore()
        let a = chain(named: "A")
        let b = chain(named: "B")
        let c = chain(named: "C")
        store.addChain(a)
        store.addChain(b)
        store.addChain(c)

        store.recordChainScore(chainID: a.id, latencyMs: 400, mbps: 10)  // slow both ways
        store.recordChainScore(chainID: b.id, latencyMs: 50, mbps: 100)  // fast both ways
        store.recordChainScore(chainID: c.id, latencyMs: 50, mbps: 60)   // fast latency, mid bandwidth

        XCTAssertEqual(store.autoOptimizeBestChainID, b.id)
    }

    /// Regression guard for the reason scores are computed on read instead
    /// of cached at measurement time: recording a new, much faster chain
    /// must immediately change the winner (and implicitly, every other
    /// chain's bandwidth normalization), never leave a previously-recorded
    /// chain's cached score "stuck" ranking first against a since-outdated
    /// notion of the best available speed.
    func testRankingUpdatesImmediatelyWhenAFasterChainIsRecorded() {
        let store = makeStore()
        let a = chain(named: "A")
        let b = chain(named: "B")
        store.addChain(a)
        store.addChain(b)

        store.recordChainScore(chainID: a.id, latencyMs: 100, mbps: 50)
        store.recordChainScore(chainID: b.id, latencyMs: 100, mbps: 10)
        XCTAssertEqual(store.autoOptimizeBestChainID, a.id)

        let c = chain(named: "C")
        store.addChain(c)
        store.recordChainScore(chainID: c.id, latencyMs: 480, mbps: 500) // poor latency, huge bandwidth lead

        XCTAssertEqual(store.autoOptimizeBestChainID, c.id)
    }
}
