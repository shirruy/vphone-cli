#include "vphone/udif_portable.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace vphone {
namespace {

constexpr std::size_t kKolySize = 512;
constexpr std::size_t kCopyBufferSize = 1024 * 1024;
constexpr std::uint32_t kKolyMagic = 0x6b6f6c79u;
constexpr std::uint32_t kMishMagic = 0x6d697368u;
constexpr std::uint32_t kRawBlockType = 0x00000001u;
constexpr std::uint32_t kTerminatorBlockType = 0xffffffffu;

void put_be32(std::uint8_t* p, std::uint32_t value) {
    p[0] = static_cast<std::uint8_t>((value >> 24) & 0xff);
    p[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    p[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    p[3] = static_cast<std::uint8_t>(value & 0xff);
}

void put_be64(std::uint8_t* p, std::uint64_t value) {
    put_be32(p, static_cast<std::uint32_t>(value >> 32));
    put_be32(p + 4, static_cast<std::uint32_t>(value & 0xffffffffu));
}

std::uint32_t get_be32(const std::uint8_t* p) {
    return
        (static_cast<std::uint32_t>(p[0]) << 24) |
        (static_cast<std::uint32_t>(p[1]) << 16) |
        (static_cast<std::uint32_t>(p[2]) << 8) |
        static_cast<std::uint32_t>(p[3]);
}

std::uint64_t get_be64(const std::uint8_t* p) {
    return
        (static_cast<std::uint64_t>(get_be32(p)) << 32) |
        static_cast<std::uint64_t>(get_be32(p + 4));
}

void append_be32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    const std::size_t old = out.size();
    out.resize(old + 4);
    put_be32(out.data() + old, value);
}

void append_be64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    const std::size_t old = out.size();
    out.resize(old + 8);
    put_be64(out.data() + old, value);
}

bool stream_size(std::ifstream& input, std::uint64_t& size, std::string& error) {
    input.clear();
    input.seekg(0, std::ios::end);
    if (!input) {
        error = "could not seek input file";
        return false;
    }

    const std::streamoff end = input.tellg();
    if (end < 0) {
        error = "could not determine input file size";
        return false;
    }

    size = static_cast<std::uint64_t>(end);
    input.clear();
    input.seekg(0, std::ios::beg);
    if (!input) {
        error = "could not rewind input file";
        return false;
    }
    return true;
}

bool read_exact(
    std::istream& input,
    void* data,
    std::size_t size,
    std::string& error
) {
    if (size == 0) {
        return true;
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "read size exceeds streamsize range";
        return false;
    }

    input.read(static_cast<char*>(data), static_cast<std::streamsize>(size));
    if (!input || input.gcount() != static_cast<std::streamsize>(size)) {
        error = "unexpected end of file";
        return false;
    }
    return true;
}

bool write_exact(
    std::ostream& output,
    const void* data,
    std::size_t size,
    std::string& error
) {
    if (size == 0) {
        return true;
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "write size exceeds streamsize range";
        return false;
    }

    output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!output) {
        error = "write failed";
        return false;
    }
    return true;
}

bool copy_exact(
    std::istream& input,
    std::ostream& output,
    std::uint64_t count,
    std::vector<std::uint8_t>& buffer,
    std::string& error
) {
    std::uint64_t remaining = count;
    while (remaining != 0) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size())
        );
        if (!read_exact(input, buffer.data(), chunk, error)) {
            return false;
        }
        if (!write_exact(output, buffer.data(), chunk, error)) {
            return false;
        }
        remaining -= chunk;
    }
    return true;
}

struct TempCleanup {
    std::string path;
    ~TempCleanup() {
        if (!path.empty()) {
            std::remove(path.c_str());
        }
    }
};

bool atomic_replace(
    const std::string& temp_path,
    const std::string& output_path,
    std::string& error
) {
#ifdef _WIN32
    if (!MoveFileExA(
            temp_path.c_str(),
            output_path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        )) {
        error = "MoveFileExA failed with Win32 error " + std::to_string(GetLastError());
        return false;
    }
    return true;
#else
    if (std::rename(temp_path.c_str(), output_path.c_str()) != 0) {
        error = "rename failed";
        return false;
    }
    return true;
#endif
}

std::string base64_encode(const std::vector<std::uint8_t>& data) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 3 <= data.size()) {
        const std::uint32_t value =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (static_cast<std::uint32_t>(data[i + 1]) << 8) |
            static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(table[(value >> 18) & 0x3f]);
        out.push_back(table[(value >> 12) & 0x3f]);
        out.push_back(table[(value >> 6) & 0x3f]);
        out.push_back(table[value & 0x3f]);
        i += 3;
    }

    const std::size_t tail = data.size() - i;
    if (tail == 1) {
        const std::uint32_t value = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(table[(value >> 18) & 0x3f]);
        out.push_back(table[(value >> 12) & 0x3f]);
        out.push_back('=');
        out.push_back('=');
    } else if (tail == 2) {
        const std::uint32_t value =
            (static_cast<std::uint32_t>(data[i]) << 16) |
            (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(table[(value >> 18) & 0x3f]);
        out.push_back(table[(value >> 12) & 0x3f]);
        out.push_back(table[(value >> 6) & 0x3f]);
        out.push_back('=');
    }

    return out;
}

void append_checksum_none(std::vector<std::uint8_t>& out) {
    append_be32(out, 0);
    append_be32(out, 0);
    out.insert(out.end(), 128, 0);
}

void append_block(
    std::vector<std::uint8_t>& out,
    std::uint32_t type,
    std::uint64_t sector_number,
    std::uint64_t sector_count,
    std::uint64_t data_offset,
    std::uint64_t data_length
) {
    append_be32(out, type);
    append_be32(out, 0);
    append_be64(out, sector_number);
    append_be64(out, sector_count);
    append_be64(out, data_offset);
    append_be64(out, data_length);
}

std::vector<std::uint8_t> build_mish(
    std::uint64_t sector_count,
    std::uint64_t raw_size
) {
    std::vector<std::uint8_t> out;
    out.reserve(284);

    append_be32(out, kMishMagic);
    append_be32(out, 1);
    append_be64(out, 0);
    append_be64(out, sector_count);
    append_be64(out, 0);
    append_be32(out, 520);
    append_be32(out, 0xfffffffeu);

    for (int i = 0; i < 6; ++i) {
        append_be32(out, 0);
    }

    append_checksum_none(out);
    append_be32(out, 2);

    append_block(
        out,
        kRawBlockType,
        0,
        sector_count,
        0,
        raw_size
    );

    append_block(
        out,
        kTerminatorBlockType,
        sector_count,
        0,
        raw_size,
        0
    );

    return out;
}

std::string build_plist(const std::vector<std::uint8_t>& mish) {
    const std::string encoded = base64_encode(mish);
    std::ostringstream out;
    out
        << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        << "<plist version=\"1.0\">\n"
        << "<dict>\n"
        << "<key>resource-fork</key>\n"
        << "<dict>\n"
        << "<key>blkx</key>\n"
        << "<array>\n"
        << "<dict>\n"
        << "<key>Attributes</key><string>0x0050</string>\n"
        << "<key>Data</key><data>" << encoded << "</data>\n"
        << "<key>ID</key><string>0</string>\n"
        << "<key>Name</key><string>whole disk (unknown partition : 0)</string>\n"
        << "<key>CFName</key><string>whole disk (unknown partition : 0)</string>\n"
        << "</dict>\n"
        << "</array>\n"
        << "<key>plst</key><array/>\n"
        << "</dict>\n"
        << "</dict>\n"
        << "</plist>\n";
    return out.str();
}

std::array<std::uint8_t, kKolySize> build_koly(
    std::uint64_t raw_size,
    std::uint64_t xml_offset,
    std::uint64_t xml_length,
    std::uint64_t sector_count
) {
    std::array<std::uint8_t, kKolySize> footer{};

    put_be32(footer.data() + 0, kKolyMagic);
    put_be32(footer.data() + 4, 4);
    put_be32(footer.data() + 8, static_cast<std::uint32_t>(kKolySize));
    put_be32(footer.data() + 12, 1);

    put_be64(footer.data() + 16, 0);
    put_be64(footer.data() + 24, 0);
    put_be64(footer.data() + 32, raw_size);
    put_be64(footer.data() + 40, 0);
    put_be64(footer.data() + 48, 0);

    put_be32(footer.data() + 56, 0);
    put_be32(footer.data() + 60, 0);

    // Segment ID [64,80) remains zero.
    // Data-fork checksum at [80,216) is type=0, size=0, payload=0.

    put_be64(footer.data() + 216, xml_offset);
    put_be64(footer.data() + 224, xml_length);

    // Reserved [232,352) stays zero.
    // Master checksum [352,488) stays type=0, size=0, payload=0.

    put_be32(footer.data() + 488, 1);
    put_be64(footer.data() + 492, sector_count);

    return footer;
}

} // namespace

bool udif_inspect(
    const std::string& input_path,
    UdifInfo& info,
    std::string& error
) {
    info = {};
    error.clear();

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not open UDIF image";
        return false;
    }

    std::uint64_t total_size = 0;
    if (!stream_size(input, total_size, error)) {
        return false;
    }
    if (total_size < kKolySize) {
        error = "file is too small to contain a UDIF koly footer";
        return false;
    }
    if (total_size - kKolySize >
        static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "UDIF footer offset exceeds streamoff range";
        return false;
    }

    input.seekg(
        static_cast<std::streamoff>(total_size - kKolySize),
        std::ios::beg
    );
    if (!input) {
        error = "could not seek to UDIF footer";
        return false;
    }

    std::array<std::uint8_t, kKolySize> footer{};
    if (!read_exact(input, footer.data(), footer.size(), error)) {
        return false;
    }

    if (get_be32(footer.data()) != kKolyMagic) {
        error = "invalid UDIF koly magic";
        return false;
    }

    info.version = get_be32(footer.data() + 4);
    const std::uint32_t header_size = get_be32(footer.data() + 8);
    info.flags = get_be32(footer.data() + 12);
    info.data_fork_offset = get_be64(footer.data() + 24);
    info.data_fork_length = get_be64(footer.data() + 32);
    info.xml_offset = get_be64(footer.data() + 216);
    info.xml_length = get_be64(footer.data() + 224);
    info.image_variant = get_be32(footer.data() + 488);
    info.sector_count = get_be64(footer.data() + 492);

    if (info.version != 4 || header_size != kKolySize) {
        error = "unsupported UDIF footer version/header size";
        return false;
    }

    const std::uint64_t footer_offset = total_size - kKolySize;

    if (info.data_fork_offset > footer_offset ||
        info.data_fork_length > footer_offset - info.data_fork_offset) {
        error = "UDIF data fork is out of bounds";
        return false;
    }

    if (info.xml_offset > footer_offset ||
        info.xml_length > footer_offset - info.xml_offset) {
        error = "UDIF XML plist is out of bounds";
        return false;
    }

    const std::uint64_t data_end =
        info.data_fork_offset + info.data_fork_length;

    if (data_end > info.xml_offset) {
        error = "UDIF data fork overlaps XML plist";
        return false;
    }

    if (info.sector_count >
        std::numeric_limits<std::uint64_t>::max() / 512ull) {
        error = "UDIF sector count overflows byte size";
        return false;
    }

    info.raw_data_fork =
        info.data_fork_offset == 0 &&
        info.data_fork_length == info.sector_count * 512ull &&
        info.xml_offset == info.data_fork_length;

    return true;
}

bool udif_wrap_raw_as_udrw(
    const std::string& input_path,
    const std::string& output_path,
    UdifFileResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not open raw disk image";
        return false;
    }

    std::uint64_t raw_size = 0;
    if (!stream_size(input, raw_size, error)) {
        return false;
    }

    if (raw_size == 0) {
        error = "raw disk image is empty";
        return false;
    }
    if ((raw_size % 512ull) != 0) {
        error = "raw disk image size must be a multiple of 512 bytes";
        return false;
    }

    const std::uint64_t sector_count = raw_size / 512ull;
    const std::vector<std::uint8_t> mish =
        build_mish(sector_count, raw_size);
    const std::string xml = build_plist(mish);

    const std::uint64_t xml_offset = raw_size;
    const std::uint64_t xml_length =
        static_cast<std::uint64_t>(xml.size());

    if (xml_length >
        std::numeric_limits<std::uint64_t>::max() - raw_size - kKolySize) {
        error = "UDIF output size overflow";
        return false;
    }

    const auto footer =
        build_koly(raw_size, xml_offset, xml_length, sector_count);

    const std::string temp_path = output_path + ".vphone.tmp";
    std::remove(temp_path.c_str());
    TempCleanup cleanup{temp_path};

    std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "could not create temporary UDRW image";
        return false;
    }

    std::vector<std::uint8_t> buffer(kCopyBufferSize);
    result.peak_buffer_bytes = std::max<std::uint64_t>(
        buffer.capacity(),
        static_cast<std::uint64_t>(mish.capacity()) +
            static_cast<std::uint64_t>(xml.capacity())
    );

    if (!copy_exact(input, output, raw_size, buffer, error)) {
        return false;
    }
    if (!write_exact(output, xml.data(), xml.size(), error)) {
        return false;
    }
    if (!write_exact(output, footer.data(), footer.size(), error)) {
        return false;
    }

    output.flush();
    if (!output) {
        error = "could not flush UDRW output";
        return false;
    }
    output.close();

    if (!atomic_replace(temp_path, output_path, error)) {
        return false;
    }

    result.input_size = raw_size;
    result.output_size = raw_size + xml_length + kKolySize;
    result.sector_count = sector_count;
    return true;
}

bool udif_extract_raw_data_fork(
    const std::string& input_path,
    const std::string& output_path,
    UdifFileResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    UdifInfo info;
    if (!udif_inspect(input_path, info, error)) {
        return false;
    }
    if (!info.raw_data_fork) {
        error = "UDIF image does not expose a contiguous raw data fork";
        return false;
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not reopen UDIF image";
        return false;
    }

    if (info.data_fork_offset >
        static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "UDIF data-fork offset exceeds streamoff range";
        return false;
    }

    input.seekg(
        static_cast<std::streamoff>(info.data_fork_offset),
        std::ios::beg
    );
    if (!input) {
        error = "could not seek to UDIF data fork";
        return false;
    }

    const std::string temp_path = output_path + ".vphone.tmp";
    std::remove(temp_path.c_str());
    TempCleanup cleanup{temp_path};

    std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "could not create temporary raw disk image";
        return false;
    }

    std::vector<std::uint8_t> buffer(kCopyBufferSize);
    result.peak_buffer_bytes = buffer.capacity();

    if (!copy_exact(
            input,
            output,
            info.data_fork_length,
            buffer,
            error
        )) {
        return false;
    }

    output.flush();
    if (!output) {
        error = "could not flush raw output";
        return false;
    }
    output.close();

    if (!atomic_replace(temp_path, output_path, error)) {
        return false;
    }

    std::ifstream source(input_path, std::ios::binary);
    std::uint64_t total_size = 0;
    if (!source || !stream_size(source, total_size, error)) {
        return false;
    }

    result.input_size = total_size;
    result.output_size = info.data_fork_length;
    result.sector_count = info.sector_count;
    return true;
}

} // namespace vphone
