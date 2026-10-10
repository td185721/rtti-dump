// rtti-dump — extract MSVC RTTI class hierarchies from an x64 PE file.
//
// Reads a Windows x64 .exe or .dll from disk, locates MSVC-emitted RTTI
// structures (Complete Object Locator, Class Hierarchy Descriptor, Base
// Class Descriptors, Type Descriptors), and prints the class names along
// with their base class lists.
//
// This is a learning tool for anyone studying how MSVC lays out RTTI on
// disk. See https://blog.quarkslab.com/visual-c-rtti-inspection.html and
// the Microsoft documentation on type_info for background.
//
// Build: CMake 3.15+, C++17 (MSVC, MinGW-w64, GCC or Clang). Reads x64 PE
// files on any host OS.

#include "pe_format.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace demangle {

// Simple MSVC type_info name demangler.
// Handles the common ".?A[VUW]Name@ns@...@@" form by stripping the
// RTTI prefix (`.?A`), stripping the trailing `@@`, splitting the body
// on `@`, reversing, and joining with `::`.
//
// Template names (identified by the `?$` sequence) are returned as-is;
// their parameter grammar is non-trivial to parse and out of scope here.
inline std::string type_info(const std::string& mangled) {
    if (mangled.size() < 6) return mangled;
    if (mangled[0] != '.' || mangled[1] != '?' || mangled[2] != 'A') return mangled;
    const char tag = mangled[3];
    if (tag != 'V' && tag != 'U' && tag != 'W') return mangled;
    if (mangled.compare(mangled.size() - 2, 2, "@@") != 0) return mangled;

    const auto body = mangled.substr(4, mangled.size() - 4 - 2);
    if (body.find("?$") != std::string::npos) return mangled;  // template, bail

    std::vector<std::string> parts;
    std::string cur;
    for (char c : body) {
        if (c == '@') {
            if (!cur.empty()) parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.empty()) return mangled;

    std::string out;
    for (std::size_t i = parts.size(); i > 0; --i) {
        if (!out.empty()) out += "::";
        out += parts[i - 1];
    }
    return out;
}

}  // namespace demangle

namespace {

// MSVC RTTI structures. Field layout is stable since VS2008.
#pragma pack(push, 1)
struct TypeDescriptor {
    std::uint64_t pVFTable;   // vtable of type_info (not used on disk)
    std::uint64_t spare;      // runtime scratch, zero on disk
    char          name[1];    // null-terminated mangled name, starts with ".?A"
};

struct PMD {
    std::int32_t mdisp;
    std::int32_t pdisp;
    std::int32_t vdisp;
};

struct BaseClassDescriptor {
    std::uint32_t pTypeDescriptor;  // RVA to TypeDescriptor
    std::uint32_t numContainedBases;
    PMD           where;
    std::uint32_t attributes;
    std::uint32_t pClassDescriptor; // RVA to parent ClassHierarchyDescriptor
};

struct ClassHierarchyDescriptor {
    std::uint32_t signature;
    std::uint32_t attributes;
    std::uint32_t numBaseClasses;
    std::uint32_t pBaseClassArray; // RVA to array of RVAs
};

struct CompleteObjectLocator {
    std::uint32_t signature;        // 1 for x64
    std::uint32_t offset;
    std::uint32_t cdOffset;
    std::uint32_t pTypeDescriptor;  // RVA
    std::uint32_t pClassDescriptor; // RVA
    std::uint32_t pSelf;            // RVA to this COL (x64 only)
};
#pragma pack(pop)

// NUL-terminated string at `offset`, cut off at the end of the file if the
// terminator is missing.
std::string cstr_at(const unsigned char* data, std::size_t size, std::size_t offset) {
    std::string out;
    for (std::size_t i = offset; i < size && data[i] != 0; ++i) {
        out.push_back(static_cast<char>(data[i]));
    }
    return out;
}

std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::fprintf(stderr, "error: cannot open '%s'\n", path.c_str());
        std::exit(1);
    }
    in.seekg(0, std::ios::end);
    const auto size = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<unsigned char> bytes(size);
    in.read(reinterpret_cast<char*>(bytes.data()), size);
    return bytes;
}

struct PEView {
    const unsigned char*               data;
    std::size_t                        size;
    const IMAGE_NT_HEADERS64*          nt;
    const IMAGE_SECTION_HEADER*        sections;
    WORD                               section_count;

    std::optional<std::size_t> rva_to_offset(std::uint32_t rva) const {
        for (WORD i = 0; i < section_count; ++i) {
            const auto& s = sections[i];
            if (rva >= s.VirtualAddress &&
                rva < s.VirtualAddress + s.Misc.VirtualSize) {
                const auto off = s.PointerToRawData + (rva - s.VirtualAddress);
                if (off < size) return off;
            }
        }
        return std::nullopt;
    }

    template <typename T>
    const T* at_rva(std::uint32_t rva) const {
        const auto off = rva_to_offset(rva);
        if (!off || *off + sizeof(T) > size) return nullptr;
        return reinterpret_cast<const T*>(data + *off);
    }

    template <typename T>
    const T* at_off(std::size_t off) const {
        if (off + sizeof(T) > size) return nullptr;
        return reinterpret_cast<const T*>(data + off);
    }
};

PEView load_pe(const std::vector<unsigned char>& image) {
    PEView view{image.data(), image.size(), nullptr, nullptr, 0};
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::fprintf(stderr, "error: file too small\n");
        std::exit(1);
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::fprintf(stderr, "error: not a PE file\n");
        std::exit(1);
    }
    const auto nt_off = static_cast<std::size_t>(static_cast<DWORD>(dos->e_lfanew));
    if (nt_off > image.size() || image.size() - nt_off < sizeof(IMAGE_NT_HEADERS64)) {
        std::fprintf(stderr, "error: NT headers lie outside the file\n");
        std::exit(1);
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: missing PE signature\n");
        std::exit(1);
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "error: only x64 PE files are supported\n");
        std::exit(1);
    }
    const auto sections_off = nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                              nt->FileHeader.SizeOfOptionalHeader;
    const auto sections_len = std::size_t{nt->FileHeader.NumberOfSections} *
                              sizeof(IMAGE_SECTION_HEADER);
    if (sections_off > image.size() || image.size() - sections_off < sections_len) {
        std::fprintf(stderr, "error: section table lies outside the file\n");
        std::exit(1);
    }
    view.nt            = nt;
    view.sections      = IMAGE_FIRST_SECTION(nt);
    view.section_count = nt->FileHeader.NumberOfSections;
    return view;
}

bool looks_like_type_descriptor(const PEView& view, std::size_t offset) {
    const auto* td = view.at_off<TypeDescriptor>(offset);
    if (!td) return false;
    if (offset + offsetof(TypeDescriptor, name) + 3 >= view.size) return false;
    const char* name = reinterpret_cast<const char*>(view.data + offset) +
                       offsetof(TypeDescriptor, name);
    if (name[0] != '.' || name[1] != '?' || name[2] != 'A') return false;
    // scan for a NUL within a reasonable bound
    for (std::size_t k = 3; k < 512 && offset + offsetof(TypeDescriptor, name) + k < view.size; ++k) {
        if (name[k] == 0) return true;
    }
    return false;
}

struct TypeHit {
    std::size_t  offset;
    std::uint32_t rva;
    std::string  mangled;
};

std::vector<TypeHit> scan_type_descriptors(const PEView& view) {
    std::vector<TypeHit> hits;
    for (WORD i = 0; i < view.section_count; ++i) {
        const auto& s = view.sections[i];
        char name[9] = {};
        std::memcpy(name, s.Name, 8);
        // RTTI type descriptors usually live in .data or .rdata on MSVC x64
        if (std::strncmp(name, ".data", 5) != 0 &&
            std::strncmp(name, ".rdata", 6) != 0) continue;

        const auto start = s.PointerToRawData;
        const auto end   = start + s.SizeOfRawData;
        for (std::size_t off = start;
             off + sizeof(TypeDescriptor) + 4 < end && off + sizeof(TypeDescriptor) + 4 < view.size;
             ++off) {
            if (!looks_like_type_descriptor(view, off)) continue;
            TypeHit hit;
            hit.offset = off;
            hit.rva    = static_cast<std::uint32_t>(
                s.VirtualAddress + (off - s.PointerToRawData));
            hit.mangled = reinterpret_cast<const char*>(view.data + off) +
                          offsetof(TypeDescriptor, name);
            hits.push_back(std::move(hit));
        }
    }
    return hits;
}

// Scan .rdata for Complete Object Locators that reference known type RVAs.
struct COLHit {
    std::size_t    offset;
    std::uint32_t  rva;
    std::uint32_t  type_rva;
    std::uint32_t  class_desc_rva;
};

std::vector<COLHit> scan_cols(const PEView& view,
                              const std::unordered_set<std::uint32_t>& type_rvas) {
    std::vector<COLHit> cols;
    for (WORD i = 0; i < view.section_count; ++i) {
        const auto& s = view.sections[i];
        char name[9] = {};
        std::memcpy(name, s.Name, 8);
        if (std::strncmp(name, ".rdata", 6) != 0) continue;

        const auto start = s.PointerToRawData;
        const auto end   = start + s.SizeOfRawData;
        for (std::size_t off = start;
             off + sizeof(CompleteObjectLocator) <= end &&
             off + sizeof(CompleteObjectLocator) <= view.size;
             off += 4) {
            const auto* col = reinterpret_cast<const CompleteObjectLocator*>(view.data + off);
            if (col->signature != 1) continue;
            if (col->pTypeDescriptor == 0 || col->pClassDescriptor == 0) continue;
            if (!type_rvas.count(col->pTypeDescriptor)) continue;
            const auto col_rva = static_cast<std::uint32_t>(
                s.VirtualAddress + (off - s.PointerToRawData));
            if (col->pSelf != col_rva) continue;
            cols.push_back(COLHit{off, col_rva, col->pTypeDescriptor, col->pClassDescriptor});
        }
    }
    return cols;
}

std::string type_name_from_rva(const PEView& view, std::uint32_t rva) {
    const auto off = view.rva_to_offset(rva);
    if (!off) return "<unresolved>";
    return cstr_at(view.data, view.size, *off + offsetof(TypeDescriptor, name));
}

}  // namespace

int main(int argc, char** argv) {
    bool demangle_names = false;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--demangle") == 0 ||
            std::strcmp(argv[i], "-d") == 0) {
            demangle_names = true;
        } else if (!path) {
            path = argv[i];
        }
    }

    if (!path) {
        std::fprintf(stderr,
                     "usage: %s [--demangle|-d] <file.exe|file.dll>\n",
                     argc ? argv[0] : "rtti-dump");
        return 2;
    }

    auto image = read_file(path);
    auto view  = load_pe(image);

    std::printf("[*] scanning for type descriptors in .data / .rdata ...\n");
    const auto types = scan_type_descriptors(view);
    std::printf("    found %zu candidate type descriptor(s)\n", types.size());

    std::unordered_set<std::uint32_t> type_rvas;
    for (const auto& t : types) type_rvas.insert(t.rva);

    std::printf("[*] scanning for Complete Object Locators ...\n");
    const auto cols = scan_cols(view, type_rvas);
    std::printf("    found %zu COL(s)\n\n", cols.size());

    const auto show = [&](const std::string& raw) {
        return demangle_names ? demangle::type_info(raw) : raw;
    };

    for (const auto& col : cols) {
        const auto raw = type_name_from_rva(view, col.type_rva);
        std::printf("class %s\n", show(raw).c_str());

        // Walk and print the base class list with the same demangle setting.
        const auto* chd = view.at_rva<ClassHierarchyDescriptor>(col.class_desc_rva);
        if (!chd) { std::printf("    <class hierarchy descriptor unresolved>\n\n"); continue; }
        const auto base_array_off = view.rva_to_offset(chd->pBaseClassArray);
        if (!base_array_off) { std::printf("    <base class array unresolved>\n\n"); continue; }
        if (chd->numBaseClasses > (view.size - *base_array_off) / sizeof(std::uint32_t)) {
            std::printf("    <base class array truncated>\n\n");
            continue;
        }
        const auto* base_rvas = reinterpret_cast<const std::uint32_t*>(
            view.data + *base_array_off);
        std::printf("    base classes (%u):\n", chd->numBaseClasses);
        for (std::uint32_t i = 0; i < chd->numBaseClasses; ++i) {
            const auto* bcd = view.at_rva<BaseClassDescriptor>(base_rvas[i]);
            if (!bcd) { std::printf("      [%u] <unresolved>\n", i); continue; }
            const auto base_name = type_name_from_rva(view, bcd->pTypeDescriptor);
            std::printf("      [%u] %s  (mdisp=%d pdisp=%d vdisp=%d)\n",
                        i, show(base_name).c_str(),
                        bcd->where.mdisp, bcd->where.pdisp, bcd->where.vdisp);
        }
        std::printf("\n");
    }

    return 0;
}
