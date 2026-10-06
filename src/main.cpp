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
// Build: CMake 3.15+, MSVC or MinGW-w64 (C++17). x64 PE only.

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

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
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::fprintf(stderr, "error: missing PE signature\n");
        std::exit(1);
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        std::fprintf(stderr, "error: only x64 PE files are supported\n");
        std::exit(1);
    }
    view.nt            = nt;
    view.sections      = IMAGE_FIRST_SECTION(nt);
    view.section_count = nt->FileHeader.NumberOfSections;
    return view;
}

const IMAGE_SECTION_HEADER* find_section(const PEView& view, const char* name) {
    for (WORD i = 0; i < view.section_count; ++i) {
        if (std::strncmp(reinterpret_cast<const char*>(view.sections[i].Name),
                         name, 8) == 0) {
            return &view.sections[i];
        }
    }
    return nullptr;
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
    const char* name = reinterpret_cast<const char*>(view.data + *off) +
                       offsetof(TypeDescriptor, name);
    return name;
}

void print_hierarchy(const PEView& view, const COLHit& col) {
    const auto* chd = view.at_rva<ClassHierarchyDescriptor>(col.class_desc_rva);
    if (!chd) {
        std::printf("    <class hierarchy descriptor unresolved>\n");
        return;
    }

    const auto base_array_off = view.rva_to_offset(chd->pBaseClassArray);
    if (!base_array_off) {
        std::printf("    <base class array unresolved>\n");
        return;
    }
    const auto* base_rvas = reinterpret_cast<const std::uint32_t*>(
        view.data + *base_array_off);
    const std::uint32_t total_bytes = chd->numBaseClasses * sizeof(std::uint32_t);
    if (*base_array_off + total_bytes > view.size) {
        std::printf("    <base class array truncated>\n");
        return;
    }

    std::printf("    base classes (%u):\n", chd->numBaseClasses);
    for (std::uint32_t i = 0; i < chd->numBaseClasses; ++i) {
        const auto* bcd = view.at_rva<BaseClassDescriptor>(base_rvas[i]);
        if (!bcd) {
            std::printf("      [%u] <unresolved>\n", i);
            continue;
        }
        const auto name = type_name_from_rva(view, bcd->pTypeDescriptor);
        std::printf("      [%u] %s  (mdisp=%d pdisp=%d vdisp=%d)\n",
                    i, name.c_str(), bcd->where.mdisp, bcd->where.pdisp, bcd->where.vdisp);
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <file.exe|file.dll>\n",
                     argc ? argv[0] : "rtti-dump");
        return 2;
    }

    auto image = read_file(argv[1]);
    auto view  = load_pe(image);

    std::printf("[*] scanning for type descriptors in .data / .rdata ...\n");
    const auto types = scan_type_descriptors(view);
    std::printf("    found %zu candidate type descriptor(s)\n", types.size());

    std::unordered_set<std::uint32_t> type_rvas;
    for (const auto& t : types) type_rvas.insert(t.rva);

    std::printf("[*] scanning for Complete Object Locators ...\n");
    const auto cols = scan_cols(view, type_rvas);
    std::printf("    found %zu COL(s)\n\n", cols.size());

    for (const auto& col : cols) {
        const auto name = type_name_from_rva(view, col.type_rva);
        std::printf("class %s\n", name.c_str());
        print_hierarchy(view, col);
        std::printf("\n");
    }

    return 0;
}
