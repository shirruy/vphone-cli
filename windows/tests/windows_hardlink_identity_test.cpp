#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <string>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "CHECK FAILED at %s:%d: %s (GetLastError=%lu)\n", \
                __FILE__, __LINE__, #expr, GetLastError()); \
            return 1; \
        } \
    } while (0)

static bool same_identity(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b)
{
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh &&
        a.nFileIndexLow == b.nFileIndexLow;
}

int main(int argc, char** argv)
{
    CHECK(argc == 2);

    const std::string base = argv[1];
    const std::string original = base + "\\vphone-hardlink-original.bin";
    const std::string linked = base + "\\vphone-hardlink-linked.bin";

    DeleteFileA(linked.c_str());
    DeleteFileA(original.c_str());

    HANDLE file = CreateFileA(
        original.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    CHECK(file != INVALID_HANDLE_VALUE);

    static const unsigned char payload[] = {0xAA, 0xBB, 0xCC, 0xDD};
    DWORD written = 0;
    CHECK(WriteFile(file, payload, sizeof(payload), &written, NULL));
    CHECK(written == sizeof(payload));
    CHECK(CloseHandle(file));

    CHECK(CreateHardLinkA(linked.c_str(), original.c_str(), NULL));

    HANDLE a = CreateFileA(
        original.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    CHECK(a != INVALID_HANDLE_VALUE);

    HANDLE b = CreateFileA(
        linked.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    CHECK(b != INVALID_HANDLE_VALUE);

    BY_HANDLE_FILE_INFORMATION infoA = {};
    BY_HANDLE_FILE_INFORMATION infoB = {};

    CHECK(GetFileInformationByHandle(a, &infoA));
    CHECK(GetFileInformationByHandle(b, &infoB));
    CHECK(same_identity(infoA, infoB));
    CHECK(infoA.nNumberOfLinks >= 2);
    CHECK(infoB.nNumberOfLinks >= 2);

    CHECK(CloseHandle(b));
    CHECK(CloseHandle(a));

    CHECK(DeleteFileA(linked.c_str()));
    CHECK(DeleteFileA(original.c_str()));

    return 0;
}
