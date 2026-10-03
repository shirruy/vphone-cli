#include "vphone/file_extent.hpp"

#include <algorithm>
#include <limits>

namespace vphone {

FileExtentValidation validate_file_extents(
    const std::vector<FileExtent>& extents,
    const FileExtentContext& ctx
) {
    FileExtentValidation out;
    if (extents.empty()) {
        out.error = "no FILE_EXTENT records";
        return out;
    }
    if (ctx.block_size == 0 ||
        (ctx.block_size & (ctx.block_size - 1)) != 0) {
        out.error = "invalid block size";
        return out;
    }
    if (ctx.block_count == 0) {
        out.error = "invalid block count";
        return out;
    }
    // Physical multiplication overflow guard: the whole container
    // byte range must be representable.
    if (ctx.block_count >
        std::numeric_limits<std::uint64_t>::max() /
            ctx.block_size) {
        out.error = "block_count * block_size overflows";
        return out;
    }

    std::vector<FileExtent> sorted = extents;
    std::sort(
        sorted.begin(), sorted.end(),
        [](const FileExtent& a, const FileExtent& b) {
            return a.logical < b.logical;
        });

    // Per-extent structural and physical checks.
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const auto& e = sorted[i];
        if (e.length == 0) {
            out.error = "zero-length extent";
            return out;
        }
        // Logical overflow guard.
        if (e.length >
            std::numeric_limits<std::uint64_t>::max() -
                e.logical) {
            out.error = "extent logical + length overflows";
            return out;
        }
        if (e.logical >= ctx.dstream_size) {
            out.error = "extent entirely after dstream_size";
            return out;
        }
        if (i > 0) {
            const auto& prev = sorted[i - 1];
            // Overlap / duplicate logical start.
            if (prev.logical == e.logical ||
                e.logical < prev.logical + prev.length) {
                out.error = "extent overlap or duplicate start";
                return out;
            }
            // Middle gap.
            if (e.logical > prev.logical + prev.length) {
                out.error = "extent coverage gap";
                return out;
            }
        }
        // Physical bounds: phys==0 is an explicit sparse extent and
        // is only acceptable when the context permits sparse holes.
        if (e.phys == 0 && !ctx.allow_sparse) {
            out.error = "sparse extent not allowed";
            return out;
        }
        if (e.phys != 0) {
            // Physical byte multiplication must not overflow; check
            // before any block-arithmetic below.
            if (e.phys >
                std::numeric_limits<std::uint64_t>::max() /
                    ctx.block_size) {
                out.error = "phys * block_size overflows";
                return out;
            }
            if (e.phys >= ctx.block_count) {
                out.error = "extent physical block out of bounds";
                return out;
            }
            const std::uint64_t blocks =
                e.length / ctx.block_size +
                ((e.length % ctx.block_size) != 0 ? 1 : 0);
            if (blocks > ctx.block_count - e.phys) {
                out.error = "extent physical range out of bounds";
                return out;
            }
        }
    }

    // Coverage: leading gap, then full [0, dstream_size).
    if (sorted.front().logical != 0) {
        out.error = "extent coverage gap at logical offset 0";
        return out;
    }
    // Compute coverage with clipping at dstream_size.
    std::uint64_t expected = 0;
    for (const auto& e : sorted) {
        if (e.logical >= ctx.dstream_size) {
            break;
        }
        const std::uint64_t chunk = std::min(
            e.length, ctx.dstream_size - e.logical);
        expected = e.logical + chunk;
    }
    if (expected < ctx.dstream_size) {
        out.error = "extent coverage incomplete";
        return out;
    }

    out.complete = true;
    out.valid = true;
    return out;
}

} // namespace vphone
