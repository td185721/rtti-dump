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
#include "term.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <optional>
#include <set>
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

namespace {

struct BaseEntry {
    std::string   name;           // mangled type_info name
    std::uint32_t contained = 0;  // how many entries below this one are its own bases
    PMD           where{};
    bool          resolved = false;
};

struct ClassInfo {
    enum class Status { Ok, NoHierarchy, NoArray, Truncated };
    std::string            name;  // mangled type_info name
    Status                 status = Status::Ok;
    std::uint32_t          declared = 0;
    std::vector<BaseEntry> bases;  // pre-order: [0] is the class itself
};

ClassInfo read_class(const PEView& view, const COLHit& col) {
    ClassInfo info;
    info.name = type_name_from_rva(view, col.type_rva);
    const auto* chd = view.at_rva<ClassHierarchyDescriptor>(col.class_desc_rva);
    if (!chd) {
        info.status = ClassInfo::Status::NoHierarchy;
        return info;
    }
    const auto base_array_off = view.rva_to_offset(chd->pBaseClassArray);
    if (!base_array_off) {
        info.status = ClassInfo::Status::NoArray;
        return info;
    }
    if (chd->numBaseClasses > (view.size - *base_array_off) / sizeof(std::uint32_t)) {
        info.status = ClassInfo::Status::Truncated;
        return info;
    }
    info.declared = chd->numBaseClasses;
    const auto* base_rvas = reinterpret_cast<const std::uint32_t*>(view.data + *base_array_off);
    for (std::uint32_t i = 0; i < chd->numBaseClasses; ++i) {
        BaseEntry entry;
        if (const auto* bcd = view.at_rva<BaseClassDescriptor>(base_rvas[i])) {
            entry.name      = type_name_from_rva(view, bcd->pTypeDescriptor);
            entry.contained = bcd->numContainedBases;
            entry.where     = bcd->where;
            entry.resolved  = true;
        }
        info.bases.push_back(std::move(entry));
    }
    return info;
}

using Namer = std::string (*)(const std::string&);

std::string raw_name(const std::string& name) { return name; }
std::string pretty_name(const std::string& name) { return demangle::type_info(name); }

// Default view: every COL with its flat base class array.
void print_list(const ClassInfo& c, Namer show) {
    const auto *B = term::bold(), *C = term::cyan(), *D = term::dim(), *R = term::reset();
    std::printf("class %s%s%s\n", B, show(c.name).c_str(), R);
    switch (c.status) {
        case ClassInfo::Status::NoHierarchy:
            std::printf("    <class hierarchy descriptor unresolved>\n\n");
            return;
        case ClassInfo::Status::NoArray:
            std::printf("    <base class array unresolved>\n\n");
            return;
        case ClassInfo::Status::Truncated:
            std::printf("    <base class array truncated>\n\n");
            return;
        case ClassInfo::Status::Ok:
            break;
    }
    std::printf("    %sbase classes (%u):%s\n", D, c.declared, R);
    for (std::size_t i = 0; i < c.bases.size(); ++i) {
        const auto& e = c.bases[i];
        if (!e.resolved) {
            std::printf("      [%zu] <unresolved>\n", i);
            continue;
        }
        std::printf("      %s[%zu]%s %s%s%s  %s(mdisp=%d pdisp=%d vdisp=%d)%s\n", D, i, R, C,
                    show(e.name).c_str(), R, D, e.where.mdisp, e.where.pdisp, e.where.vdisp, R);
    }
    std::printf("\n");
}

// The base class array is a pre-order walk of the inheritance tree in which
// every entry records how many entries below it belong to it, so the tree
// can be rebuilt from it: entry i's direct bases start at i + 1 and each
// spans contained + 1 entries.
std::size_t subtree_end(const ClassInfo& c, std::size_t i, std::size_t limit) {
    return std::min<std::size_t>(limit, i + 1 + c.bases[i].contained);
}

std::size_t print_subtree(const ClassInfo& c, std::size_t i, std::size_t limit,
                          const std::string& prefix, bool last, Namer show) {
    const auto& e = c.bases[i];
    const auto end = subtree_end(c, i, limit);
    if (i == 0) {
        std::printf("%s%s%s\n", term::bold(), show(e.name).c_str(), term::reset());
    } else {
        std::printf("%s%s%s%s%s", prefix.c_str(), last ? "└── " : "├── ",
                    term::cyan(), e.resolved ? show(e.name).c_str() : "<unresolved>", term::reset());
        if (e.where.pdisp >= 0) {
            std::printf("  %s(virtual)%s", term::yellow(), term::reset());
        } else if (e.where.mdisp != 0) {
            std::printf("  %s+0x%x%s", term::dim(), static_cast<unsigned>(e.where.mdisp), term::reset());
        }
        std::printf("\n");
    }
    const std::string child_prefix = i == 0 ? "" : prefix + (last ? "    " : "│   ");
    for (std::size_t j = i + 1; j < end;) {
        const auto child_end = subtree_end(c, j, end);
        print_subtree(c, j, end, child_prefix, child_end >= end, show);
        j = child_end;
    }
    return end;
}

// Direct bases of the class at entry 0, with whether each is virtual.
std::vector<std::pair<const BaseEntry*, bool>> direct_bases(const ClassInfo& c) {
    std::vector<std::pair<const BaseEntry*, bool>> out;
    if (c.bases.empty()) return out;
    const auto end = subtree_end(c, 0, c.bases.size());
    for (std::size_t j = 1; j < end; j = subtree_end(c, j, end)) {
        if (c.bases[j].resolved) out.emplace_back(&c.bases[j], c.bases[j].where.pdisp >= 0);
    }
    return out;
}

std::string mermaid_id(const std::string& label) {
    std::string id = "c_";
    for (unsigned char ch : label) id += std::isalnum(ch) ? static_cast<char>(ch) : '_';
    return id;
}

std::string mermaid_label(const std::string& label) {
    std::string out;
    for (char ch : label) out += ch == '"' ? '\'' : ch;
    return out;
}

// Mermaid class diagram (renders natively on GitHub): one node per class,
// one inheritance edge per direct base.
void print_mermaid(const std::vector<ClassInfo>& classes) {
    std::printf("classDiagram\n");
    std::set<std::string> declared, edges;
    const auto declare = [&](const std::string& label) {
        const auto id = mermaid_id(label);
        if (declared.insert(id).second) {
            std::printf("    class %s[\"%s\"]\n", id.c_str(), mermaid_label(label).c_str());
        }
        return id;
    };
    for (const auto& c : classes) {
        if (c.status != ClassInfo::Status::Ok) continue;
        const auto child = declare(pretty_name(c.name));
        for (const auto& [base, is_virtual] : direct_bases(c)) {
            const auto parent = declare(pretty_name(base->name));
            std::string edge = "    " + parent + " <|-- " + child + (is_virtual ? " : virtual" : "");
            if (edges.insert(edge).second) std::printf("%s\n", edge.c_str());
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    enum class View { List, Tree, Mermaid };
    View view_mode = View::List;
    bool demangle_names = false;
    bool bad_flag = false;
    term::Mode color = term::Mode::Auto;
    const char* path = nullptr;

    for (int i = 1; i < argc; ++i) {
        const int cf = term::parse_flag(argc, argv, i, color);
        if (cf != 0) {
            bad_flag |= cf < 0;
        } else if (std::strcmp(argv[i], "--demangle") == 0 || std::strcmp(argv[i], "-d") == 0) {
            demangle_names = true;
        } else if (std::strcmp(argv[i], "--tree") == 0 || std::strcmp(argv[i], "-t") == 0) {
            view_mode = View::Tree;
        } else if (std::strcmp(argv[i], "--mermaid") == 0) {
            view_mode = View::Mermaid;
        } else if (!path) {
            path = argv[i];
        }
    }

    if (!path || bad_flag) {
        std::fprintf(stderr,
                     "usage: %s [--demangle|-d] [--tree|-t|--mermaid] [--color auto|always|never]"
                     " <file.exe|file.dll>\n",
                     argc ? argv[0] : "rtti-dump");
        return 2;
    }
    // Mermaid output is meant to be pasted into documents, so it is never colored.
    term::init(view_mode == View::Mermaid ? term::Mode::Never : color);
    if (view_mode == View::Tree) term::utf8_console();

    auto image = read_file(path);
    auto view  = load_pe(image);

    const auto *D = term::dim(), *R = term::reset();
    const bool progress = view_mode != View::Mermaid;
    if (progress) std::printf("%s[*] scanning for type descriptors in .data / .rdata ...%s\n", D, R);
    const auto types = scan_type_descriptors(view);
    if (progress) std::printf("%s    found %zu candidate type descriptor(s)%s\n", D, types.size(), R);

    std::unordered_set<std::uint32_t> type_rvas;
    for (const auto& t : types) type_rvas.insert(t.rva);

    if (progress) std::printf("%s[*] scanning for Complete Object Locators ...%s\n", D, R);
    const auto cols = scan_cols(view, type_rvas);
    if (progress) std::printf("%s    found %zu COL(s)%s\n\n", D, cols.size(), R);

    std::vector<ClassInfo> classes;
    for (const auto& col : cols) classes.push_back(read_class(view, col));

    if (view_mode == View::Mermaid) {
        print_mermaid(classes);
        return 0;
    }

    const Namer show = demangle_names ? pretty_name : raw_name;
    if (view_mode == View::List) {
        for (const auto& c : classes) print_list(c, show);
        return 0;
    }

    // Tree view: one tree per class (a class has one COL per vtable).
    std::set<std::string> seen;
    for (const auto& c : classes) {
        if (c.status != ClassInfo::Status::Ok || c.bases.empty() || !seen.insert(c.name).second) continue;
        print_subtree(c, 0, c.bases.size(), "", true, show);
        std::printf("\n");
    }
    return 0;
}
