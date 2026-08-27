#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace makima::kernel::symbols {

[[nodiscard]] std::string_view
cached_live_kernel_debug_directory_error() noexcept;
[[nodiscard]] std::string_view cached_live_kernel_codeview_error() noexcept;

struct CodeViewIdentity final {
    std::array<std::byte, 16> guid{};
    std::uint32_t age{};
    std::string pdb_name;
};

struct LoadedImageView final {
    std::uintptr_t image_begin{};
    std::uintptr_t image_base{};
};



struct KernelImageSnapshot final {
    std::uintptr_t virtual_base{};
    std::span<const std::byte> bytes;

    [[nodiscard]] bool read(
        std::uintptr_t address,
        std::span<std::byte> destination) const noexcept;
};

struct KernelModuleState final {
    std::array<std::byte, 0x10b0> discovery_and_reader_state{};
    std::uintptr_t ntoskrnl_base{};
    KernelImageSnapshot image;
};

static_assert(offsetof(KernelModuleState, ntoskrnl_base) == 0x10b0);




struct KernelMapperState final {
    std::array<std::byte, 0x10c0> mapper_and_transport_state{};
    std::uint32_t dbgkp_triage_dump_save_state_rva{};
    std::uint32_t dbgkp_triage_dump_restore_state_rva{};
};

static_assert(
    offsetof(KernelMapperState, dbgkp_triage_dump_save_state_rva) == 0x10c0);
static_assert(
    offsetof(KernelMapperState, dbgkp_triage_dump_restore_state_rva) == 0x10c4);





using DriverPatternOffsetResolver = std::int32_t(*)(
    void* native_context,
    const wchar_t* driver_relative_path,
    const std::byte* pattern,
    std::uint32_t pattern_size,
    std::uint32_t* pattern_offset);





[[nodiscard]] wchar_t* allocate_services_active_database_name(
    std::int64_t protected_source);

struct PdbStreamDirectory final {
    std::uint32_t block_size{};
    std::span<const std::byte> file;
    std::vector<std::uint32_t> sizes;
    std::vector<std::vector<std::uint32_t>> blocks;
};





struct MsfFileView final {
    const std::byte* data{};
    std::size_t size{};
};

struct MsfDirectoryState final {
    MsfFileView file;
    bool valid{};
    std::array<std::byte, 3> validity_padding{};
    std::uint32_t block_size{};
    std::uint32_t block_count{};
    std::uint32_t directory_bytes{};
    std::uint32_t directory_block_map{};
    std::vector<std::uint32_t> stream_sizes;
    std::vector<std::vector<std::uint32_t>> stream_blocks;
    std::string error;
};

static_assert(offsetof(MsfDirectoryState, valid) == 0x10);
static_assert(offsetof(MsfDirectoryState, block_size) == 0x14);
static_assert(offsetof(MsfDirectoryState, block_count) == 0x18);
static_assert(offsetof(MsfDirectoryState, directory_bytes) == 0x1c);
static_assert(offsetof(MsfDirectoryState, directory_block_map) == 0x20);
static_assert(offsetof(MsfDirectoryState, stream_sizes) == 0x28);
static_assert(offsetof(MsfDirectoryState, stream_blocks) == 0x40);
static_assert(offsetof(MsfDirectoryState, error) == 0x58);
static_assert(sizeof(MsfDirectoryState) == 0x78);




struct TpiStreamState final {
    std::byte* begin{};
    std::byte* end{};
    std::byte* capacity{};
    std::uint32_t header_size{};
    std::uint32_t type_index_begin{};
    std::uint32_t type_index_end{};
    std::uint32_t type_record_bytes{};
    std::vector<std::uint32_t> record_offsets;
    std::unordered_map<std::string, std::uint32_t> named_type_indices;
    bool records_ready{};
    std::array<std::byte, 7> ready_padding{};
    std::string error;

    ~TpiStreamState();
};

static_assert(offsetof(TpiStreamState, header_size) == 0x18);
static_assert(offsetof(TpiStreamState, type_index_begin) == 0x1c);
static_assert(offsetof(TpiStreamState, type_index_end) == 0x20);
static_assert(offsetof(TpiStreamState, type_record_bytes) == 0x24);
static_assert(offsetof(TpiStreamState, record_offsets) == 0x28);
static_assert(offsetof(TpiStreamState, named_type_indices) == 0x40);
static_assert(offsetof(TpiStreamState, records_ready) == 0x80);
static_assert(offsetof(TpiStreamState, error) == 0x88);
static_assert(sizeof(TpiStreamState) == 0xa8);

struct ParsedPdbState final {
    bool directory_valid{};
    bool public_symbols_ready{};
    PdbStreamDirectory directory;
    std::unique_ptr<TpiStreamState> type_information;
};







[[nodiscard]] MsfDirectoryState* initialize_msf_directory_state(
    MsfDirectoryState* output,
    const MsfFileView* file);
[[nodiscard]] bool validate_msf_superblock(
    MsfDirectoryState* state);
[[nodiscard]] bool validate_tpi_stream_header(
    TpiStreamState* state);


[[nodiscard]] TpiStreamState* initialize_tpi_stream_state(
    TpiStreamState* output,
    const MsfDirectoryState* directory);




[[nodiscard]] std::unordered_map<std::string, std::uint32_t>*
initialize_tpi_parser_subobject(
    std::unordered_map<std::string, std::uint32_t>* parser_subobject,
    std::uint32_t* seed,
    std::uint8_t* construction_flag);



[[nodiscard]] std::uint64_t parse_tpi_records(TpiStreamState* state);


extern const std::array<std::byte, 25>
    msf_size_block_count_mismatch_protected_source;
[[nodiscard]] char* allocate_msf_size_block_count_mismatch_message(
    const std::byte* protected_source);




[[nodiscard]] std::uint64_t parse_msf_directory_blocks(
    MsfDirectoryState* state);

struct PublicSymbolState final {
    std::unordered_map<std::string, std::uint32_t> rvas;
};



struct OwnedSymbolText final {
    std::array<std::byte, 0x18> owner_prefix{};
    union TextStorage {
        char inline_text[16];
        char* heap_text;

        constexpr TextStorage() noexcept : inline_text{} {}
    } text;
    std::size_t size{};
    std::size_t capacity{15};
};

static_assert(offsetof(OwnedSymbolText, text) == 0x18);
static_assert(offsetof(OwnedSymbolText, size) == 0x28);
static_assert(offsetof(OwnedSymbolText, capacity) == 0x30);




struct OwnedWideSymbolText final {
    union TextStorage {
        wchar_t inline_text[8];
        wchar_t* heap_text;

        constexpr TextStorage() noexcept : inline_text{} {}
    } text;
    std::size_t size{};
    std::size_t capacity{7};
};

static_assert(sizeof(OwnedWideSymbolText) == 0x20);
static_assert(offsetof(OwnedWideSymbolText, size) == 0x10);
static_assert(offsetof(OwnedWideSymbolText, capacity) == 0x18);

struct SymbolResolver final {





    std::uintptr_t constructor_cookie{};
    std::uintptr_t loaded_kernel_base{};
    std::vector<std::byte> program_database;
    std::unique_ptr<ParsedPdbState> parsed_database;
    std::unique_ptr<PublicSymbolState> public_symbols;
    std::array<std::byte, 0x40> parser_slots{};
    std::string error;

    [[nodiscard]] std::uintptr_t address_of(
        std::string_view symbol_name) const noexcept;
};

[[nodiscard]] std::uint64_t download_and_parse_matching_pdb(
    SymbolResolver& resolver,
    const CodeViewIdentity& identity);
[[nodiscard]] std::uint64_t microsoft_symbol_server_download(
    const std::wstring& request_path,
    std::vector<std::byte>& destination,
    std::string& error) noexcept;
[[nodiscard]] std::uint64_t load_encrypted_symbol_cache(
    const std::string& symbol_key,
    const std::string& pdb_name,
    std::vector<std::byte>& plaintext) noexcept;
[[nodiscard]] std::uint64_t save_encrypted_symbol_cache(
    const std::string& symbol_key,
    const std::string& pdb_name,
    std::span<const std::byte> plaintext) noexcept;
[[nodiscard]] std::uint32_t map_ntoskrnl_for_symbol_resolution(
    SymbolResolver& resolver,
    std::uintptr_t loaded_kernel_base,
    const wchar_t* installed_image = nullptr);
[[nodiscard]] std::uint32_t consume_live_kernel_and_pdb_data(
    SymbolResolver& resolver,
    KernelModuleState* const* module);
void initialize_pdb_symbol_resolver(
    KernelMapperState& mapper,
    std::uintptr_t loaded_kernel_base);

[[nodiscard]] bool read_codeview_from_loaded_module(
    const LoadedImageView& image,
    std::uintptr_t mapped_image_base,
    CodeViewIdentity& identity,
    std::string& error) noexcept;
[[nodiscard]] bool read_codeview_from_live_kernel(
    KernelModuleState* const* module,
    std::uintptr_t loaded_kernel_base,
    CodeViewIdentity& identity,
    std::string& error) noexcept;
[[nodiscard]] std::uintptr_t resolve_public_symbol(
    const SymbolResolver& resolver,
    std::string_view symbol_name) noexcept;


void reset_owned_symbol_text(OwnedSymbolText* owner) noexcept;



void destroy_owned_symbol_object(std::uintptr_t* object) noexcept;


void reset_owned_wide_symbol_text(OwnedWideSymbolText* owner) noexcept;




[[nodiscard]] std::uintptr_t cached_decoded_utf16_140770140() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_utf16_140771700() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_utf16_140774380() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140776a60() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140778380() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140779fc0() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_14077ca00() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_14077f600() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140782bc0() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140784ba0() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140787e00() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_14078ac80() noexcept;
[[nodiscard]] std::uintptr_t cached_decoded_bytes_14078d7a0() noexcept;
[[nodiscard]] std::byte* decode_protected_bytes_140642640(
    std::int64_t source);
[[nodiscard]] std::uintptr_t cached_decoded_bytes_140642640() noexcept;




[[nodiscard]] wchar_t* allocate_microsoft_symbol_server_host_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_winhttp_connect_failure_message(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pdb_stream_too_small_for_guid_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_pdb_guid_mismatch_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_dbi_stream_too_small_message(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dbi_symbol_record_stream_index_invalid_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_optional_debug_header_overflow_message(
    std::int64_t protected_source);
[[nodiscard]] char*
allocate_optional_debug_header_too_small_for_section_header_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_section_header_stream_index_invalid_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_section_header_stream_empty_or_too_small_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_symbol_record_stream_empty_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_no_symbols_found_in_symbol_record_stream_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_dbi_symbol_parse_failure_prefix(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_tpi_stream_two_empty_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_tpi_header_too_small_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bad_tpi_header_size_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_tpi_records_overflow_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_tpi_index_range_invalid_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_tpi_record_truncated_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_dbgkp_triage_dump_save_state_export_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_dbgkp_triage_dump_restore_state_export_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_kernel_base_zero_message(
    std::int64_t protected_source);



[[nodiscard]] std::uint64_t run_delayed_navigation_reveal(void** context) noexcept;

}
