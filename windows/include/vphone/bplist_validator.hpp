// Binary plist (bplist00) structural validator implementing the
// Apple CoreFoundation marker grammar. Shared by the semantic
// wrapper unit test and the real-APFS integration driver so the
// same validator guards both the spy control-flow proof and the
// production mutation path.
//
// Grammar implemented (marker = high nibble type, low nibble info):
//   0x00 null | 0x08 false | 0x09 true | 0x0F fill
//   0x1n integer  (size = 2^n bytes)
//   0x2n real     (size = 2^(n+2) bytes)
//   0x33 date     (8-byte float, fixed marker)
//   0x4n data     (n bytes)
//   0x5n ASCII string (n bytes)
//   0x6n UTF-16BE string (n code units)
//   0x8n UID      (n+1 bytes)
//   0xAn array    (n refs)
//   0xCn set      (n refs)
//   0xDn dict     (n key/value ref pairs)
// Unsupported high nibbles 0x7, 0x9, 0xB, 0xE are rejected.
//
// Trailer (last 32 bytes, big-endian):
//   +5 sort version | +6 offset table entry size | +7 ref size
//   +8 num_objects | +16 top object | +24 offset table offset
//
// Object table boundary: every object offset must satisfy
//   8 <= offset < offset_table_off
// and every complete object span must end at <= offset_table_off,
// so no object may overlap the offset table.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace vphone {

// Overflow-safe big-endian integer reader. Returns false when the
// span is out of bounds or size > 8; never reads past data.
inline bool bplist_read_be(
    const std::vector<std::uint8_t>& data,
    std::uint64_t off,
    int size,
    std::uint64_t& out
) {
    if (size < 1 || size > 8) {
        return false;
    }
    const std::uint64_t byte_count =
        static_cast<std::uint64_t>(size);
    if (off > data.size() ||
        byte_count > data.size() - off) {
        return false;
    }
    out = 0;
    for (int i = 0; i < size; ++i) {
        out = (out << 8) |
            data[static_cast<std::size_t>(off + i)];
    }
    return true;
}

// Parse an object length. info != 0xF: count = info, payload
// starts at object_offset + 1. info == 0xF: the byte after the
// marker must itself be an integer marker 0x1n; the count is the
// big-endian integer that follows; the payload starts immediately
// after that integer. All arithmetic is bounds- and overflow-safe.
inline bool bplist_parse_length(
    const std::vector<std::uint8_t>& data,
    std::uint64_t object_offset,
    std::uint8_t info,
    std::uint64_t object_table_end,
    std::uint64_t& payload_offset,
    std::uint64_t& count,
    std::string& error
) {
    if (info != 0x0F) {
        count = info;
        payload_offset = object_offset + 1;
        return true;
    }

    // info == 0xF: a length marker must exist after the marker.
    if (object_offset + 1 >= object_table_end) {
        error = "extended length marker missing";
        return false;
    }
    const std::uint8_t len_marker =
        data[static_cast<std::size_t>(object_offset + 1)];
    if ((len_marker >> 4) != 0x1) {
        error = "invalid extended length marker (not an integer)";
        return false;
    }
    const int width_info = len_marker & 0x0F;
    if (width_info > 3) {
        error = "extended length integer width exceeds uint64";
        return false;
    }
    const int width = 1 << width_info;
    const std::uint64_t int_off = object_offset + 2;
    if (!bplist_read_be(data, int_off, width, count)) {
        error = "extended length integer out of bounds";
        return false;
    }
    if (int_off > object_table_end ||
        static_cast<std::uint64_t>(width) >
            object_table_end - int_off) {
        error = "extended length integer crosses object table";
        return false;
    }
    payload_offset =
        int_off + static_cast<std::uint64_t>(width);
    return true;
}

// Structural validation of a binary plist. Returns an empty string
// on success or an error description on failure. Every read is
// bounds-checked; object spans may never cross offset_table_off.
inline std::string bplist_validate(
    const std::vector<std::uint8_t>& data
) {
    const std::size_t n = data.size();

    // Minimum: header(8) + one object + one offset entry + trailer(32).
    if (n < 42) {
        return "too short for binary plist";
    }
    if (std::memcmp(data.data(), "bplist00", 8) != 0) {
        return "missing bplist00 magic";
    }

    const std::uint8_t* trailer = data.data() + n - 32;
    const int offset_size = trailer[6];
    const int ref_size = trailer[7];
    std::uint64_t num_objects = 0;
    std::uint64_t top_object = 0;
    std::uint64_t offset_table_off = 0;
    if (!bplist_read_be(data, n - 32 + 8, 8, num_objects) ||
        !bplist_read_be(data, n - 32 + 16, 8, top_object) ||
        !bplist_read_be(data, n - 32 + 24, 8, offset_table_off)) {
        return "trailer unreadable";
    }

    if (offset_size != 1 && offset_size != 2 &&
        offset_size != 4 && offset_size != 8) {
        return "invalid offset table entry size";
    }
    if (ref_size != 1 && ref_size != 2 &&
        ref_size != 4 && ref_size != 8) {
        return "invalid object reference size";
    }
    if (num_objects == 0 || num_objects > 100000) {
        return "invalid object count";
    }
    if (top_object >= num_objects) {
        return "top object index out of range";
    }

    // Offset table must sit entirely inside the trailer boundary
    // and must not start before the header.
    const std::uint64_t offset_table_size =
        num_objects * static_cast<std::uint64_t>(offset_size);
    if (offset_table_off < 8) {
        return "offset table starts inside header";
    }
    if (offset_table_off > n - 32 ||
        offset_table_size > (n - 32) - offset_table_off) {
        return "offset table exceeds data bounds";
    }

    // Read every object offset.
    std::vector<std::uint64_t> offsets(
        static_cast<std::size_t>(num_objects), 0);
    for (std::uint64_t i = 0; i < num_objects; ++i) {
        const std::uint64_t entry_off =
            offset_table_off +
            i * static_cast<std::uint64_t>(offset_size);
        if (!bplist_read_be(
                data, entry_off, offset_size, offsets[i])) {
            return "offset table entry out of bounds";
        }
        if (offsets[i] < 8) {
            return "object offset before header end";
        }
        if (offsets[i] >= offset_table_off) {
            return "object offset inside offset table";
        }
    }

    // Validate every object. object_table_end == offset_table_off
    // is the hard upper bound for all object spans.
    const std::uint64_t object_table_end = offset_table_off;
    for (std::uint64_t i = 0; i < num_objects; ++i) {
        const std::uint64_t o = offsets[i];
        const std::uint8_t marker =
            data[static_cast<std::size_t>(o)];
        const int type = marker >> 4;
        const int info = marker & 0x0F;

        switch (type) {
        case 0x0: { // null / false / true / fill
            switch (info) {
            case 0x0: // null
            case 0x8: // false
            case 0x9: // true
            case 0xF: // fill
                break;
            default:
                return "invalid 0x0-special marker";
            }
            break;
        }
        case 0x1: { // integer, size = 2^info
            if (info > 4) {
                return "invalid integer size";
            }
            const std::uint64_t size =
                std::uint64_t{1} << info;
            if (size > object_table_end ||
                o + 1 > object_table_end - size ||
                o + 1 + size > object_table_end) {
                return "integer extends past object table";
            }
            break;
        }
        case 0x2: { // real
            if (info > 3) {
                return "invalid real size";
            }
            const std::uint64_t size =
                std::uint64_t{1} << (info + 2);
            if (size > object_table_end ||
                o + 1 > object_table_end - size ||
                o + 1 + size > object_table_end) {
                return "real extends past object table";
            }
            break;
        }
        case 0x3: { // date: fixed 8-byte float
            if (info != 0x3) {
                return "invalid date marker";
            }
            if (o + 9 > object_table_end) {
                return "date extends past object table";
            }
            break;
        }
        case 0x4: { // data
            std::uint64_t count = 0;
            std::uint64_t payload_off = 0;
            std::string err;
            if (!bplist_parse_length(
                    data, o, static_cast<std::uint8_t>(info),
                    object_table_end, payload_off, count, err)) {
                return "data: " + err;
            }
            if (count > object_table_end ||
                payload_off > object_table_end - count ||
                payload_off + count > object_table_end) {
                return "data extends past object table";
            }
            break;
        }
        case 0x5: { // ASCII string
            std::uint64_t count = 0;
            std::uint64_t payload_off = 0;
            std::string err;
            if (!bplist_parse_length(
                    data, o, static_cast<std::uint8_t>(info),
                    object_table_end, payload_off, count, err)) {
                return "string: " + err;
            }
            if (count > object_table_end ||
                payload_off > object_table_end - count ||
                payload_off + count > object_table_end) {
                return "string extends past object table";
            }
            break;
        }
        case 0x6: { // UTF-16BE string
            std::uint64_t count = 0;
            std::uint64_t payload_off = 0;
            std::string err;
            if (!bplist_parse_length(
                    data, o, static_cast<std::uint8_t>(info),
                    object_table_end, payload_off, count, err)) {
                return "utf16 string: " + err;
            }
            if (count > object_table_end / 2) {
                return "utf16 string length overflows";
            }
            const std::uint64_t bytes = count * 2;
            if (bytes > object_table_end ||
                payload_off > object_table_end - bytes ||
                payload_off + bytes > object_table_end) {
                return "utf16 string extends past object table";
            }
            break;
        }
        case 0x8: { // UID, length = n + 1
            if (info > 8) {
                return "invalid UID size";
            }
            const std::uint64_t len =
                static_cast<std::uint64_t>(info) + 1;
            if (len > object_table_end ||
                o + 1 > object_table_end - len ||
                o + 1 + len > object_table_end) {
                return "uid extends past object table";
            }
            break;
        }
        case 0xA: // array
        case 0xC: { // set
            std::uint64_t count = 0;
            std::uint64_t refs_off = 0;
            std::string err;
            if (!bplist_parse_length(
                    data, o, static_cast<std::uint8_t>(info),
                    object_table_end, refs_off, count, err)) {
                return "array/set: " + err;
            }
            if (count >
                object_table_end /
                    static_cast<std::uint64_t>(ref_size)) {
                return "array/set reference count overflows";
            }
            const std::uint64_t span =
                count * static_cast<std::uint64_t>(ref_size);
            if (span > object_table_end ||
                refs_off > object_table_end - span ||
                refs_off + span > object_table_end) {
                return "array/set references past object table";
            }
            for (std::uint64_t j = 0; j < count; ++j) {
                std::uint64_t ref = 0;
                if (!bplist_read_be(
                        data,
                        refs_off +
                            j * static_cast<std::uint64_t>(ref_size),
                        ref_size, ref)) {
                    return "array/set reference unreadable";
                }
                if (ref >= num_objects) {
                    return "array/set reference out of range";
                }
            }
            break;
        }
        case 0xD: { // dict
            std::uint64_t count = 0;
            std::uint64_t key_refs_off = 0;
            std::string err;
            if (!bplist_parse_length(
                    data, o, static_cast<std::uint8_t>(info),
                    object_table_end, key_refs_off, count, err)) {
                return "dict: " + err;
            }
            if (count >
                object_table_end /
                    static_cast<std::uint64_t>(ref_size)) {
                return "dict entry count overflows";
            }
            const std::uint64_t key_span =
                count * static_cast<std::uint64_t>(ref_size);
            if (key_span > object_table_end ||
                key_refs_off > object_table_end - key_span ||
                key_refs_off + key_span > object_table_end) {
                return "dict keys past object table";
            }
            const std::uint64_t val_refs_off =
                key_refs_off + key_span;
            if (key_span > object_table_end ||
                val_refs_off > object_table_end - key_span ||
                val_refs_off + key_span > object_table_end) {
                return "dict values past object table";
            }
            for (std::uint64_t j = 0; j < count; ++j) {
                std::uint64_t kref = 0;
                std::uint64_t vref = 0;
                if (!bplist_read_be(
                        data,
                        key_refs_off +
                            j * static_cast<std::uint64_t>(ref_size),
                        ref_size, kref) ||
                    !bplist_read_be(
                        data,
                        val_refs_off +
                            j * static_cast<std::uint64_t>(ref_size),
                        ref_size, vref)) {
                    return "dict reference unreadable";
                }
                if (kref >= num_objects) {
                    return "dict key reference out of range";
                }
                if (vref >= num_objects) {
                    return "dict value reference out of range";
                }
            }
            break;
        }
        default:
            return "unsupported object type marker";
        }
    }

    return "";
}

} // namespace vphone
