// BLAKE3.swift
//
// A from-scratch port of the official BLAKE3 reference implementation
// (BLAKE3-team/BLAKE3/reference_impl/reference_impl.rs) -- needed for
// Shadowsocks 2022's session-subkey derivation (`blake3::derive_key`),
// which no existing Swift/CryptoKit primitive implements. Cross-checked
// against the official published test vectors (BLAKE3-team/BLAKE3/
// test_vectors/test_vectors.json) in BLAKE3Tests -- hash, keyed_hash, and
// derive_key all covered, not just the one mode Shadowsocks 2022 actually
// needs, since the three share every internal function below and a wrong
// port would very likely fail all three the same way.
//
// This is a direct structural port, not a reinterpretation: the chunk
// (1024B) / block (64B) chaining, the Merkle-tree chunk-combining via a
// chaining-value stack, and the two-phase `derive_key` (hash the context
// string first, then use *that* as the key for a second keyed hash over the
// key material) all mirror the reference implementation's own shape --
// see its comments for *why* each piece works, not repeated here.

import Foundation

private let blockLength = 64
private let chunkLength = 1024

private let chunkStart: UInt32 = 1 << 0
private let chunkEnd: UInt32 = 1 << 1
private let parentFlag: UInt32 = 1 << 2
private let rootFlag: UInt32 = 1 << 3
private let keyedHashFlag: UInt32 = 1 << 4
private let deriveKeyContextFlag: UInt32 = 1 << 5
private let deriveKeyMaterialFlag: UInt32 = 1 << 6

private let blake3IV: [UInt32] = [
    0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
    0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
]

private let msgPermutation: [Int] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

private func rotr32(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

// MARK: - Compression

private func g(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ mx: UInt32, _ my: UInt32) {
    state[a] = state[a] &+ state[b] &+ mx
    state[d] = rotr32(state[d] ^ state[a], 16)
    state[c] = state[c] &+ state[d]
    state[b] = rotr32(state[b] ^ state[c], 12)
    state[a] = state[a] &+ state[b] &+ my
    state[d] = rotr32(state[d] ^ state[a], 8)
    state[c] = state[c] &+ state[d]
    state[b] = rotr32(state[b] ^ state[c], 7)
}

private func blake3Round(_ state: inout [UInt32], _ m: [UInt32]) {
    // Columns.
    g(&state, 0, 4, 8, 12, m[0], m[1])
    g(&state, 1, 5, 9, 13, m[2], m[3])
    g(&state, 2, 6, 10, 14, m[4], m[5])
    g(&state, 3, 7, 11, 15, m[6], m[7])
    // Diagonals.
    g(&state, 0, 5, 10, 15, m[8], m[9])
    g(&state, 1, 6, 11, 12, m[10], m[11])
    g(&state, 2, 7, 8, 13, m[12], m[13])
    g(&state, 3, 4, 9, 14, m[14], m[15])
}

private func permute(_ m: inout [UInt32]) {
    var permuted = [UInt32](repeating: 0, count: 16)
    for i in 0..<16 { permuted[i] = m[msgPermutation[i]] }
    m = permuted
}

private func compress(chainingValue: [UInt32], blockWords: [UInt32], counter: UInt64, blockLenBytes: UInt32, flags: UInt32) -> [UInt32] {
    let counterLow = UInt32(truncatingIfNeeded: counter)
    let counterHigh = UInt32(truncatingIfNeeded: counter >> 32)
    var state: [UInt32] = chainingValue + [blake3IV[0], blake3IV[1], blake3IV[2], blake3IV[3], counterLow, counterHigh, blockLenBytes, flags]
    var block = blockWords

    for round in 0..<7 {
        blake3Round(&state, block)
        if round < 6 { permute(&block) }
    }

    for i in 0..<8 {
        state[i] ^= state[i + 8]
        state[i + 8] ^= chainingValue[i]
    }
    return state
}

private func first8Words(_ compressionOutput: [UInt32]) -> [UInt32] { Array(compressionOutput[0..<8]) }

private func wordsFromLittleEndianBytes(_ bytes: [UInt8], count: Int) -> [UInt32] {
    var words = [UInt32](repeating: 0, count: count)
    for i in 0..<count {
        let base = i * 4
        words[i] = UInt32(bytes[base]) | (UInt32(bytes[base + 1]) << 8) | (UInt32(bytes[base + 2]) << 16) | (UInt32(bytes[base + 3]) << 24)
    }
    return words
}

// MARK: - Output (a chunk or parent node, prior to choosing chaining-value vs. root-bytes)

private struct BLAKE3Output {
    let inputChainingValue: [UInt32]
    let blockWords: [UInt32]
    let counter: UInt64
    let blockLen: UInt32
    let flags: UInt32

    func chainingValue() -> [UInt32] {
        first8Words(compress(chainingValue: inputChainingValue, blockWords: blockWords, counter: counter, blockLenBytes: blockLen, flags: flags))
    }

    /// Extended-output bytes: one compression per 64-byte block, `ROOT`
    /// flagged, with an incrementing `output_block_counter` in place of the
    /// chunk/parent counter -- only ever called once, at the very end, with
    /// the final root `Output`.
    func rootOutputBytes(count: Int) -> [UInt8] {
        var result = [UInt8]()
        result.reserveCapacity(count)
        var outputBlockCounter: UInt64 = 0
        while result.count < count {
            let words = compress(chainingValue: inputChainingValue, blockWords: blockWords, counter: outputBlockCounter, blockLenBytes: blockLen, flags: flags | rootFlag)
            outer: for word in words {
                for shift: UInt32 in [0, 8, 16, 24] {
                    if result.count >= count { break outer }
                    result.append(UInt8((word >> shift) & 0xFF))
                }
            }
            outputBlockCounter += 1
        }
        return result
    }
}

// MARK: - Chunk state (accumulates up to 1024 bytes / 16 blocks)

private final class BLAKE3ChunkState {
    var chainingValue: [UInt32]
    let chunkCounter: UInt64
    var block: [UInt8]
    var bufferedLength: UInt8 = 0
    var blocksCompressed: UInt8 = 0
    let flags: UInt32

    init(keyWords: [UInt32], chunkCounter: UInt64, flags: UInt32) {
        self.chainingValue = keyWords
        self.chunkCounter = chunkCounter
        self.block = [UInt8](repeating: 0, count: blockLength)
        self.flags = flags
    }

    var length: Int { blockLength * Int(blocksCompressed) + Int(bufferedLength) }

    var startFlag: UInt32 { blocksCompressed == 0 ? chunkStart : 0 }

    func update(_ input: [UInt8]) {
        var offset = 0
        while offset < input.count {
            if Int(bufferedLength) == blockLength {
                // Block buffer is full: compress it (not CHUNK_END -- more
                // input is coming) and start a fresh one.
                let blockWords = wordsFromLittleEndianBytes(block, count: 16)
                chainingValue = first8Words(compress(chainingValue: chainingValue, blockWords: blockWords, counter: chunkCounter, blockLenBytes: UInt32(blockLength), flags: flags | startFlag))
                blocksCompressed += 1
                block = [UInt8](repeating: 0, count: blockLength)
                bufferedLength = 0
            }
            let want = blockLength - Int(bufferedLength)
            let take = min(want, input.count - offset)
            for i in 0..<take { block[Int(bufferedLength) + i] = input[offset + i] }
            bufferedLength += UInt8(take)
            offset += take
        }
    }

    func output() -> BLAKE3Output {
        let blockWords = wordsFromLittleEndianBytes(block, count: 16)
        return BLAKE3Output(inputChainingValue: chainingValue, blockWords: blockWords, counter: chunkCounter, blockLen: UInt32(bufferedLength), flags: flags | startFlag | chunkEnd)
    }
}

private func parentOutput(leftChildCV: [UInt32], rightChildCV: [UInt32], keyWords: [UInt32], flags: UInt32) -> BLAKE3Output {
    BLAKE3Output(inputChainingValue: keyWords, blockWords: leftChildCV + rightChildCV, counter: 0, blockLen: UInt32(blockLength), flags: parentFlag | flags)
}

private func parentChainingValue(leftChildCV: [UInt32], rightChildCV: [UInt32], keyWords: [UInt32], flags: UInt32) -> [UInt32] {
    parentOutput(leftChildCV: leftChildCV, rightChildCV: rightChildCV, keyWords: keyWords, flags: flags).chainingValue()
}

// MARK: - Hasher

/// An incremental BLAKE3 hasher, in any of its three modes. `update` can be
/// called any number of times; `finalize` doesn't mutate state, so it can be
/// called more than once (e.g. for a shorter check-length before the real
/// extended output), mirroring the reference implementation.
public final class BLAKE3Hasher {
    private var chunkState: BLAKE3ChunkState
    private let keyWords: [UInt32]
    private var cvStack: [[UInt32]] = []
    private let flags: UInt32

    private init(keyWords: [UInt32], flags: UInt32) {
        self.keyWords = keyWords
        self.flags = flags
        self.chunkState = BLAKE3ChunkState(keyWords: keyWords, chunkCounter: 0, flags: flags)
    }

    public static func standard() -> BLAKE3Hasher { BLAKE3Hasher(keyWords: blake3IV, flags: 0) }

    public static func keyed(key: [UInt8]) -> BLAKE3Hasher {
        precondition(key.count == 32, "BLAKE3 keyed_hash needs a 32-byte key")
        return BLAKE3Hasher(keyWords: wordsFromLittleEndianBytes(key, count: 8), flags: keyedHashFlag)
    }

    /// The key-derivation mode: hashes `context` (with `DERIVE_KEY_CONTEXT`)
    /// into a 32-byte context key, then returns a *second* hasher keyed with
    /// that (via `DERIVE_KEY_MATERIAL`) -- callers `update()` the key
    /// material into the returned hasher, then `finalize()` it.
    public static func deriveKey(context: String) -> BLAKE3Hasher {
        let contextHasher = BLAKE3Hasher(keyWords: blake3IV, flags: deriveKeyContextFlag)
        contextHasher.update(Array(context.utf8))
        let contextKey = contextHasher.finalize(outputByteCount: 32)
        let contextKeyWords = wordsFromLittleEndianBytes(contextKey, count: 8)
        return BLAKE3Hasher(keyWords: contextKeyWords, flags: deriveKeyMaterialFlag)
    }

    private func addChunkChainingValue(_ newCV: [UInt32], totalChunks: UInt64) {
        // Each completed subtree's left child is the current stack top;
        // pop and merge until the trailing-zero-bit count of `totalChunks`
        // is exhausted, then push what's left.
        var newCV = newCV
        var total = totalChunks
        while total & 1 == 0 {
            let left = cvStack.removeLast()
            newCV = parentChainingValue(leftChildCV: left, rightChildCV: newCV, keyWords: keyWords, flags: flags)
            total >>= 1
        }
        cvStack.append(newCV)
    }

    public func update(_ input: [UInt8]) {
        var offset = 0
        while offset < input.count {
            if chunkState.length == chunkLength {
                let chunkCV = chunkState.output().chainingValue()
                let totalChunks = chunkState.chunkCounter + 1
                addChunkChainingValue(chunkCV, totalChunks: totalChunks)
                chunkState = BLAKE3ChunkState(keyWords: keyWords, chunkCounter: totalChunks, flags: flags)
            }
            let want = chunkLength - chunkState.length
            let take = min(want, input.count - offset)
            chunkState.update(Array(input[offset..<offset + take]))
            offset += take
        }
    }

    public func finalize(outputByteCount: Int = 32) -> [UInt8] {
        var output = chunkState.output()
        var parentNodesRemaining = cvStack.count
        while parentNodesRemaining > 0 {
            parentNodesRemaining -= 1
            output = parentOutput(leftChildCV: cvStack[parentNodesRemaining], rightChildCV: output.chainingValue(), keyWords: keyWords, flags: flags)
        }
        return output.rootOutputBytes(count: outputByteCount)
    }
}

// MARK: - Convenience entry points

public func blake3Hash(_ input: [UInt8], outputByteCount: Int = 32) -> [UInt8] {
    let hasher = BLAKE3Hasher.standard()
    hasher.update(input)
    return hasher.finalize(outputByteCount: outputByteCount)
}

public func blake3KeyedHash(key: [UInt8], input: [UInt8], outputByteCount: Int = 32) -> [UInt8] {
    let hasher = BLAKE3Hasher.keyed(key: key)
    hasher.update(input)
    return hasher.finalize(outputByteCount: outputByteCount)
}

/// `blake3::derive_key(context, key_material)` -- the one mode Shadowsocks
/// 2022 actually needs (session subkey derivation, see `ShadowsocksCore.swift`).
public func blake3DeriveKey(context: String, keyMaterial: [UInt8], outputByteCount: Int = 32) -> [UInt8] {
    let hasher = BLAKE3Hasher.deriveKey(context: context)
    hasher.update(keyMaterial)
    return hasher.finalize(outputByteCount: outputByteCount)
}
