#include "vphone/apfs_reader.hpp"

#include <windows.h>

#include <wincrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kBlockCount = 16;
constexpr std::uint64_t kApsbOid = 42;
constexpr std::uint64_t kApsbXid = 3;
constexpr std::uint64_t kOmapPhys = 4;
constexpr std::uint64_t kOmapTreeOid = 5;
constexpr std::uint64_t kRootOid = 300;
constexpr std::uint64_t kLeafOid = 301;
constexpr std::uint64_t kFileCnid = 50;
constexpr std::uint64_t kLaunchDaemonsCnid = 5;

std::uint64_t fletcher64(const std::vector<std::uint8_t>& b) {
    constexpr std::uint64_t modulus = 0xFFFFFFFFull;
    std::uint64_t s1 = 0;
    std::uint64_t s2 = 0;
    for (std::size_t i = 8; i + 4 <= b.size(); i += 4) {
        const std::uint32_t v =
            static_cast<std::uint32_t>(b[i]) |
            (static_cast<std::uint32_t>(b[i + 1]) << 8) |
            (static_cast<std::uint32_t>(b[i + 2]) << 16) |
            (static_cast<std::uint32_t>(b[i + 3]) << 24);
        s1 = (s1 + v) % modulus;
        s2 = (s2 + s1) % modulus;
    }
    const std::uint64_t c1 =
        modulus - ((s1 + s2) % modulus);
    const std::uint64_t c2 =
        modulus - ((s1 + c1) % modulus);
    return c1 | (c2 << 32);
}

void put_le16(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v & 0xff);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
}

void put_le32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b[off + i] =
            static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void put_le64(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + i] =
            static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void seal(std::vector<std::uint8_t>& b) {
    put_le64(b, 0, fletcher64(b));
}

bool write_all(
    const std::string& path,
    const std::vector<std::uint8_t>& data) {
    HANDLE f = CreateFileA(
        path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(
        f, data.data(), static_cast<DWORD>(data.size()),
        &written, nullptr);
    CloseHandle(f);
    return ok && written == data.size();
}

bool read_all(
    const std::string& path, std::vector<std::uint8_t>& out) {
    HANDLE f = CreateFileA(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    out.resize(GetFileSize(f, nullptr));
    DWORD n = 0;
    const BOOL ok = ReadFile(
        f, out.data(), static_cast<DWORD>(out.size()), &n,
        nullptr);
    CloseHandle(f);
    return ok && n == out.size();
}

std::string sha256_hex(const std::vector<std::uint8_t>& data) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return out;
    }
    if (CryptCreateHash(
            prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(
                hash, const_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()), 0)) {
            BYTE buf[32];
            DWORD len = 32;
            if (CryptGetHashParam(
                    hash, HP_HASHVAL, buf, &len, 0) &&
                len == 32) {
                char hex[65];
                for (DWORD i = 0; i < 32; ++i) {
                    std::snprintf(
                        hex + i * 2, 3, "%02x", buf[i]);
                }
                out = hex;
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

std::vector<std::uint8_t> build_image() {
    std::vector<std::uint8_t> img(
        static_cast<std::size_t>(kBlockCount) * kBlockSize, 0);

    auto put = [&](
        std::uint64_t block,
        const std::vector<std::uint8_t>& blk) {
        std::memcpy(
            img.data() +
                static_cast<std::size_t>(block) * kBlockSize,
            blk.data(), kBlockSize);
    };

    // FSTREE leaf at block 8.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kLeafOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 28, 0x0000000Eu);
        blk[0x20] = 0x02;
        blk[0x22] = 0x00;

        const std::uint16_t tlen = 8 * 8;
        const std::uint64_t kb = 0x38 + tlen;
        const std::uint64_t vb = kBlockSize;
        std::uint16_t nkeys = 0;
        std::uint16_t cur_key = 0;
        std::uint64_t cur_val_end = vb;

        auto add_rec = [&](
            std::uint64_t hdr,
            const std::vector<std::uint8_t>& key_extra,
            std::uint16_t val_len,
            const std::vector<std::uint8_t>& val) {
            const std::uint16_t k_len =
                8 + static_cast<std::uint16_t>(
                        key_extra.size());
            const std::uint64_t toc = 0x38 + nkeys * 8;
            put_le16(blk, toc, cur_key);
            put_le16(blk, toc + 2, k_len);
            const std::uint16_t v_off =
                static_cast<std::uint16_t>(
                    vb - (cur_val_end - val_len));
            put_le16(blk, toc + 4, v_off);
            put_le16(blk, toc + 6, val_len);

            const std::uint64_t kp = kb + cur_key;
            put_le64(blk, kp, hdr);
            if (!key_extra.empty()) {
                std::memcpy(
                    blk.data() + kp + 8, key_extra.data(),
                    key_extra.size());
            }
            const std::uint64_t vp = vb - v_off;
            if (!val.empty()) {
                std::memcpy(
                    blk.data() + vp, val.data(), val.size());
            }
            cur_key += k_len;
            cur_val_end -= val_len;
            ++nkeys;
        };

        {
            const char* names[] = {
                "System", "Library", "LaunchDaemons"};
            const std::uint64_t parents[] = {2, 3, 4};
            const std::uint64_t children[] = {
                3, 4, kLaunchDaemonsCnid};
            for (int i = 0; i < 3; ++i) {
                const std::string n = names[i];
                const std::uint16_t stored =
                    static_cast<std::uint16_t>(n.size()) + 1;
                std::vector<std::uint8_t> ke(2 + stored);
                ke[0] = stored & 0xff;
                ke[1] = stored >> 8;
                std::memcpy(ke.data() + 2, n.c_str(), n.size());
                std::vector<std::uint8_t> v(18, 0);
                put_le64(v, 0, children[i]);
                put_le32(v, 16, 4);
                add_rec(
                    (9ull << 60) | parents[i], ke, 18, v);
            }
        }

        {
            const std::string n = "test.plist";
            const std::uint16_t stored =
                static_cast<std::uint16_t>(n.size()) + 1;
            std::vector<std::uint8_t> ke(2 + stored);
            ke[0] = stored & 0xff;
            ke[1] = stored >> 8;
            std::memcpy(ke.data() + 2, n.c_str(), n.size());
            std::vector<std::uint8_t> v(18, 0);
            put_le64(v, 0, kFileCnid);
            put_le32(v, 16, 8);
            add_rec(
                (9ull << 60) | kLaunchDaemonsCnid, ke, 18, v);
        }

        {
            std::vector<std::uint8_t> v(0x64, 0);
            put_le64(v, 0, kLaunchDaemonsCnid);
            put_le64(v, 8, kFileCnid);
            put_le32(v, 0x44, 0x20);
            put_le32(v, 0x50, 0x81a4);
            put_le16(v, 0x5c, 1);
            put_le16(v, 0x5e, 0);
            add_rec((3ull << 60) | kFileCnid, {},
                static_cast<std::uint16_t>(v.size()), v);
        }

        {
            constexpr std::uint16_t kNameLen = 18;
            std::vector<std::uint8_t> ke(2 + kNameLen);
            ke[0] = kNameLen & 0xff;
            ke[1] = kNameLen >> 8;
            std::memcpy(
                ke.data() + 2, "com.apple.decmpfs", 17);
            ke[2 + 17] = 0;

            std::vector<std::uint8_t> xd(28, 0);
            put_le32(xd, 0, 0x636D7066u);
            put_le32(xd, 4, 9);
            put_le64(xd, 8, 11);
            xd[16] = 0xCC;
            const char* payload = "bplist00XY";
            std::memcpy(xd.data() + 17, payload, 10);
            xd[27] = 'Z';

            std::vector<std::uint8_t> xv(4 + xd.size(), 0);
            put_le16(xv, 0, 0x0002);
            put_le16(xv, 2, static_cast<std::uint16_t>(xd.size()));
            std::memcpy(xv.data() + 4, xd.data(), xd.size());
            add_rec(
                (4ull << 60) | kFileCnid, ke,
                static_cast<std::uint16_t>(xv.size()), xv);
        }

        put_le32(blk, 0x24, nkeys);
        put_le32(blk, 0x28,
            static_cast<std::uint32_t>(tlen) << 16);
        seal(blk);
        put(8, blk);
    }

    // OMAP tree leaf at block 5.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kOmapTreeOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 0x20, 0x00000006u);
        put_le32(blk, 0x24, 2);
        put_le32(blk, 0x28, 0x00100000u);
        blk[0x38] = 0x00; blk[0x39] = 0x00;
        blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        blk[0x3c] = 0x10; blk[0x3d] = 0x00;
        blk[0x3e] = 0x20; blk[0x3f] = 0x00;
        blk[0x40] = 0x20; blk[0x41] = 0x00;
        blk[0x42] = 0x30; blk[0x43] = 0x00;
        put_le64(blk, 0x48, kRootOid);
        put_le64(blk, 0x50, kApsbXid);
        put_le64(blk, 0x58, kLeafOid);
        put_le64(blk, 0x60, kApsbXid);
        put_le64(blk, 0xfc8 + 8, 6);
        put_le64(blk, 0xfb8 + 8, 8);
        seal(blk);
        put(5, blk);
    }

    // FSTREE root at block 6.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kRootOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 28, 0x0000000Eu);
        blk[0x20] = 0x01;
        blk[0x22] = 0x01;
        put_le32(blk, 0x24, 1);
        put_le32(blk, 0x28, 0x00100000u);
        blk[0x38] = 0x00; blk[0x39] = 0x00;
        blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        blk[0x3c] = 0x10; blk[0x3d] = 0x00;
        blk[0x3e] = 0x08; blk[0x3f] = 0x00;
        put_le64(blk, 0x48, (9ull << 60) | 1ull);
        put_le64(blk, 0xfc8, kLeafOid);
        put_le32(blk, kBlockSize - 0x28, 0);
        put_le32(blk, kBlockSize - 0x28 + 4, kBlockSize);
        seal(blk);
        put(6, blk);
    }

    // OMAP object at block 4.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kOmapPhys);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x4000000Bu);
        put_le64(blk, 0x30, kOmapTreeOid);
        seal(blk);
        put(4, blk);
    }

    // APSB at block 1.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kApsbOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x80000009u);
        put_le32(blk, 32, 0x42535041u);
        put_le64(blk, 0x80, kOmapPhys);
        put_le64(blk, 0x88, kRootOid);
        put_le64(blk, 0x90, 3);
        std::memcpy(blk.data() + 0x2C0, "mutvol", 6);
        seal(blk);
        put(1, blk);
    }

    // NXSB at block 0.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, 1);
        put_le64(blk, 16, 1);
        put_le32(blk, 24, 0x80000001u);
        put_le32(blk, 32, 0x4253584Eu);
        put_le32(blk, 36, kBlockSize);
        put_le64(blk, 40, kBlockCount);
        seal(blk);
        put(0, blk);
    }

    return img;
}

} // namespace

int main() {
    char temp[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, temp)) {
        std::fprintf(stderr, "GetTempPathA failed\n");
        return 1;
    }
    const std::string dir(temp);
    const std::string source = dir + "apfs_mut_source.img";
    const std::string output = dir + "apfs_mut_output.img";
    const std::string variant =
        dir + "apfs_mut_variant.img";
    const std::string variant_out =
        dir + "apfs_mut_variant_out.img";

    const auto base = build_image();
    if (!write_all(source, base)) {
        std::fprintf(stderr, "source write failed\n");
        return 1;
    }

    std::string plist_sha;
    {
        vphone::ApfsReaderReport rpt;
        std::string err;
        if (!vphone::apfs_read_container(source, rpt, err)) {
            std::fprintf(
                stderr, "reader failed: %s\n", err.c_str());
            return 1;
        }
        if (rpt.plist_file.status != "READ_OK" ||
            rpt.plist_file.drec_cnid != kFileCnid ||
            rpt.plist_file.format != "binary-plist" ||
            rpt.plist_file.bytes.size() != 11) {
            std::fprintf(
                stderr,
                "unexpected plist resolution: status=%s "
                "cnid=%llu size=%zu\n",
                rpt.plist_file.status.c_str(),
                static_cast<unsigned long long>(
                    rpt.plist_file.drec_cnid),
                rpt.plist_file.bytes.size());
            return 1;
        }
        if (rpt.plist_file.bytes[0] != 'b' ||
            rpt.plist_file.bytes[9] != 'Y' ||
            rpt.plist_file.bytes[10] != 'Z') {
            std::fprintf(
                stderr, "unexpected plist payload\n");
            return 1;
        }
        plist_sha = sha256_hex(rpt.plist_file.bytes);
    }

    // Positive: mutate byte 9 'Y' -> 'Q'; verify reread and
    // source immutability.
    DeleteFileA(output.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (!vphone::apfs_mutate_plist_byte_safe(
                source, output, plist_sha, kFileCnid, 9,
                'Y', 'Q', r, err) ||
            !r.success || !r.reread_verified ||
            r.reread_plist_sha256.empty() ||
            r.reread_plist_sha256 == plist_sha) {
            std::fprintf(
                stderr, "positive safe mutation failed: %s\n",
                err.c_str());
            return 1;
        }

        vphone::ApfsReaderReport out;
        std::string rerr;
        if (!vphone::apfs_read_container(
                output, out, rerr)) {
            std::fprintf(
                stderr, "output reread failed: %s\n",
                rerr.c_str());
            return 1;
        }
        if (out.plist_file.status != "READ_OK" ||
            out.plist_file.bytes.size() != 11 ||
            out.plist_file.bytes[9] != 'Q' ||
            out.plist_file.bytes[10] != 'Z' ||
            sha256_hex(out.plist_file.bytes) !=
                r.reread_plist_sha256) {
            std::fprintf(
                stderr, "certified reread mismatch\n");
            return 1;
        }

        std::vector<std::uint8_t> after;
        if (!read_all(source, after) || after != base) {
            std::fprintf(
                stderr, "SOURCE IMAGE WAS MODIFIED\n");
            return 1;
        }
    }

    // Refusal: source == output.
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                source, source, plist_sha, kFileCnid, 9,
                'Y', 'Q', r, err) ||
            err != "REFUSED: source and output must be "
                   "distinct paths") {
            std::fprintf(
                stderr,
                "[same_source_output] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: wrong source hash.
    DeleteFileA(variant_out.c_str());
    if (!write_all(variant, base)) {
        std::fprintf(stderr, "variant write failed\n");
        return 1;
    }
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, "deadbeef", kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err != "REFUSED: source hash mismatch") {
            std::fprintf(
                stderr,
                "[wrong_source_hash] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: wrong CNID.
    DeleteFileA(variant_out.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, 999, 9,
                'Y', 'Q', r, err) ||
            err != "REFUSED: target CNID mismatch") {
            std::fprintf(
                stderr,
                "[wrong_cnid] expected refusal, got '%s'\n",
                err.c_str());
            return 1;
        }
    }

    // Refusal: old-byte mismatch.
    DeleteFileA(variant_out.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'X', 'Q', r, err) ||
            err !=
                "REFUSED: old byte mismatch at offset") {
            std::fprintf(
                stderr,
                "[old_byte_mismatch] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: XATTR absent (reader fails closed on the
    // only candidate). Locate the decmpfs signature in the
    // leaf and corrupt it, then reseal nothing so the reader
    // rejects the record structurally.
    {
        std::vector<std::uint8_t> bad = base;
        const std::size_t leaf_off =
            static_cast<std::size_t>(8) * kBlockSize;
        bool found = false;
        const std::array<std::uint8_t, 4> sig = {
            0x66, 0x70, 0x6D, 0x63}; // "cmpf" LE
        for (std::size_t i = leaf_off;
             i + 4 < leaf_off + kBlockSize; ++i) {
            if (bad[i] == sig[0] && bad[i + 1] == sig[1] &&
                bad[i + 2] == sig[2] &&
                bad[i + 3] == sig[3]) {
                bad[i] = 0xEE;
                found = true;
                break;
            }
        }
        if (!found) {
            std::fprintf(
                stderr, "could not locate decmpfs sig\n");
            return 1;
        }
        if (!write_all(variant, bad)) {
            std::fprintf(stderr, "bad variant write\n");
            return 1;
        }
        DeleteFileA(variant_out.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err !=
                "REFUSED: source plist not readable: "
                "NOT_ATTEMPTED") {
            std::fprintf(
                stderr,
                "[xattr_absent] expected reader refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: bad block checksum pre-write.
    {
        std::vector<std::uint8_t> bad = base;
        const std::size_t leaf_off =
            static_cast<std::size_t>(8) * kBlockSize;
        bad[leaf_off + 0x100] ^= 0xFF;
        if (!write_all(variant, bad)) {
            std::fprintf(stderr, "bad cksum write\n");
            return 1;
        }
        DeleteFileA(variant_out.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err !=
                "REFUSED: source plist not readable: "
                "NOT_ATTEMPTED") {
            std::fprintf(
                stderr,
                "[bad_block_checksum] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    DeleteFileA(source.c_str());
    DeleteFileA(output.c_str());
    DeleteFileA(variant.c_str());
    DeleteFileA(variant_out.c_str());

    std::printf("APFS_MUTATOR_TEST_PASS\n");
    return 0;
}
