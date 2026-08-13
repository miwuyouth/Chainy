import XCTest
@testable import ProxyKit

/// Cross-checked against the *official* published BLAKE3 test vectors
/// (BLAKE3-team/BLAKE3/test_vectors/test_vectors.json), not just internal
/// self-consistency -- the strongest possible check for a from-scratch
/// crypto primitive port. Covers all three modes (hash/keyed_hash/
/// derive_key) across the input lengths that actually exercise the tricky
/// parts of the algorithm: within one block (1, 63), exactly/just past one
/// block (64/65), exactly/just past one chunk (1024/1025), and several
/// multi-chunk sizes that force the Merkle-tree chaining-value stack to
/// merge subtrees of different depths (2048, 3073, 8192, 102400).
final class BLAKE3Tests: XCTestCase {
    /// Every test vector's input is this exact repeating sequence,
    /// per the official test_vectors.json's own description.
    private func testInput(length: Int) -> [UInt8] {
        (0..<length).map { UInt8($0 % 251) }
    }

    private let key = Array("whats the Elvish word for friend".utf8)
    private let contextString = "BLAKE3 2019-12-27 16:29:52 test vectors context"

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// (input length, expected default-output hex for hash/keyed_hash/derive_key).
    private let vectors: [(Int, String, String, String)] = [
        (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
         "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
         "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
         "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
         "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
         "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
         "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
        (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
         "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
         "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
         "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
         "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
         "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
         "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
         "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
         "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
         "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
         "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
         "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
         "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
        (3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
         "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a",
         "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081"),
        (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
         "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
         "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"),
        (102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
         "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
         "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"),
    ]

    func testHashAgainstOfficialVectors() {
        for (length, expected, _, _) in vectors {
            let got = hex(blake3Hash(testInput(length: length)))
            XCTAssertEqual(got, expected, "hash mismatch at input_len=\(length)")
        }
    }

    func testKeyedHashAgainstOfficialVectors() {
        for (length, _, expected, _) in vectors {
            let got = hex(blake3KeyedHash(key: key, input: testInput(length: length)))
            XCTAssertEqual(got, expected, "keyed_hash mismatch at input_len=\(length)")
        }
    }

    func testDeriveKeyAgainstOfficialVectors() {
        for (length, _, _, expected) in vectors {
            let got = hex(blake3DeriveKey(context: contextString, keyMaterial: testInput(length: length)))
            XCTAssertEqual(got, expected, "derive_key mismatch at input_len=\(length)")
        }
    }

    /// `update()` called in several small pieces must produce the exact
    /// same digest as one big call -- proves the chunk/block buffering
    /// doesn't depend on how the caller happens to chop up its input.
    func testIncrementalUpdateMatchesSingleCall() {
        let input = testInput(length: 8192)
        let whole = blake3Hash(input)

        let hasher = BLAKE3Hasher.standard()
        var offset = 0
        let pieceSizes = [1, 63, 64, 65, 900, 1, 4096, 100_000] // last piece will just take the remainder
        for size in pieceSizes {
            guard offset < input.count else { break }
            let end = min(offset + size, input.count)
            hasher.update(Array(input[offset..<end]))
            offset = end
        }
        if offset < input.count { hasher.update(Array(input[offset...])) }
        XCTAssertEqual(hasher.finalize(), whole)
    }
}
