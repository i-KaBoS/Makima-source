#include "makima/platform/platform.hpp"

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

int failures = 0;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "check failed: " #condition " at line " << __LINE__ << '\n'; ++failures; } } while (false)

std::vector<std::uint8_t> hex(std::string_view text) {
    const auto digit = [](char value) -> std::uint8_t {
        if (value >= '0' && value <= '9') return static_cast<std::uint8_t>(value - '0');
        if (value >= 'a' && value <= 'f') return static_cast<std::uint8_t>(value - 'a' + 10);
        if (value >= 'A' && value <= 'F') return static_cast<std::uint8_t>(value - 'A' + 10);
        return 0xff;
    };
    CHECK(text.size() % 2 == 0);
    std::vector<std::uint8_t> result;
    for (std::size_t index = 0; index + 1 < text.size(); index += 2) {
        const auto high = digit(text[index]);
        const auto low = digit(text[index + 1]);
        CHECK(high != 0xff && low != 0xff);
        result.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }
    return result;
}

template <std::size_t Size>
std::array<std::uint8_t, Size> hex_array(std::string_view text) {
    const auto bytes = hex(text);
    CHECK(bytes.size() == Size);
    std::array<std::uint8_t, Size> result{};
    std::copy_n(bytes.begin(), std::min(bytes.size(), result.size()), result.begin());
    return result;
}

std::span<const std::uint8_t> bytes(std::string_view text) {
    return {
        reinterpret_cast<const std::uint8_t*>(text.data()),
        text.size(),
    };
}

void test_crypto() {
    makima::platform::CngCryptoProvider crypto;
    const auto sha = crypto.sha256(bytes("abc"));
    CHECK(sha == hex_array<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const auto hmac = crypto.hmac_sha256(
        bytes("key"),
        bytes("The quick brown fox jumps over the lazy dog"));
    CHECK(hmac == hex_array<32>("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));

    makima::application::Hash256 zero_key{};
    std::array<std::uint8_t, 12> zero_nonce{};
    std::array<std::uint8_t, 16> zero_plaintext{};
    const auto encrypted = crypto.aes256_gcm_encrypt(
        zero_key,
        zero_nonce,
        zero_plaintext,
        {});
    CHECK(encrypted == hex(
        "cea7403d4d606b6e074ec5d3baf39d18"
        "d0d1c8a799996bf0265b98b5d48ab919"));
    CHECK(crypto.aes256_gcm_decrypt(zero_key, zero_nonce, encrypted, {}) ==
          makima::application::Bytes(zero_plaintext.begin(), zero_plaintext.end()));
    auto tampered = encrypted;
    tampered.back() ^= 1;
    try {
        static_cast<void>(crypto.aes256_gcm_decrypt(zero_key, zero_nonce, tampered, {}));
        CHECK(false);
    } catch (const makima::application::ApplicationError&) {
    }

    makima::application::Hash256 cbc_key{};
    std::array<std::uint8_t, 16> cbc_iv{};
    for (std::size_t index = 0; index < cbc_key.size(); ++index) {
        cbc_key[index] = static_cast<std::uint8_t>(index);
    }
    for (std::size_t index = 0; index < cbc_iv.size(); ++index) {
        cbc_iv[index] = static_cast<std::uint8_t>(index);
    }
    const auto cbc_plaintext = crypto.aes256_cbc_decrypt(
        cbc_key,
        cbc_iv,
        hex("b906c1a0293213c7d5fb7b6c06270e1e"));
    CHECK(std::string(cbc_plaintext.begin(), cbc_plaintext.end()) == "Makima CBC test");

    const auto alice_private = hex_array<32>(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto alice_public = hex_array<32>(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const auto bob_private = hex_array<32>(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto bob_public = hex_array<32>(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const auto shared = hex_array<32>(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    CHECK(crypto.x25519_exchange(alice_private, bob_public) == shared);
    CHECK(crypto.x25519_exchange(bob_private, alice_public) == shared);
    const auto generated_a = crypto.x25519_generate();
    const auto generated_b = crypto.x25519_generate();
    CHECK(generated_a.private_key.size() == 32);
    CHECK(crypto.x25519_exchange(generated_a.private_key, generated_b.public_key) ==
          crypto.x25519_exchange(generated_b.private_key, generated_a.public_key));

    const auto ed_public = hex_array<32>(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const auto ed_signature = hex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    CHECK(crypto.ed25519_verify(ed_public, ed_signature, {}));
    auto invalid_signature = ed_signature;
    invalid_signature[0] ^= 1;
    CHECK(!crypto.ed25519_verify(ed_public, invalid_signature, {}));

    const auto random = crypto.random_bytes(64);
    CHECK(random.size() == 64);
    CHECK(std::ranges::any_of(random, [](std::uint8_t value) { return value != 0; }));
}

class LoopbackServer final {
public:
    LoopbackServer() {
        WSADATA data{};
        CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0);
        socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        CHECK(socket_ != INVALID_SOCKET);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        CHECK(bind(socket_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0);
        CHECK(listen(socket_, 1) == 0);
        int length = sizeof(address);
        CHECK(getsockname(socket_, reinterpret_cast<sockaddr*>(&address), &length) == 0);
        port_ = ntohs(address.sin_port);
        thread_ = std::thread([this] { serve(); });
    }

    ~LoopbackServer() {
        if (thread_.joinable()) {
            thread_.join();
        }
        if (socket_ != INVALID_SOCKET) {
            closesocket(socket_);
        }
        WSACleanup();
    }

    [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
    [[nodiscard]] const std::string& request() {
        if (thread_.joinable()) {
            thread_.join();
        }
        return request_;
    }

private:
    void serve() {
        const auto client = accept(socket_, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            return;
        }
        std::array<char, 2048> buffer{};
        for (;;) {
            const auto count = recv(client, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (count <= 0) {
                break;
            }
            request_.append(buffer.data(), static_cast<std::size_t>(count));
            if (request_.find("\r\n\r\n") != std::string::npos &&
                request_.ends_with("payload")) {
                break;
            }
        }
        constexpr std::string_view response =
            "HTTP/1.1 201 Created\r\n"
            "Content-Length: 2\r\n"
            "Content-Type: application/octet-stream\r\n"
            "X-Test: passed\r\n"
            "Connection: close\r\n\r\nOK";
        send(client, response.data(), static_cast<int>(response.size()), 0);
        shutdown(client, SD_BOTH);
        closesocket(client);
    }

    SOCKET socket_{INVALID_SOCKET};
    std::uint16_t port_{};
    std::thread thread_;
    std::string request_;
};

void test_http() {
    LoopbackServer server;
    makima::application::WinHttpTransport transport;
    const auto url = "http://127.0.0.1:" + std::to_string(server.port()) + "/sync?test=1";
    const auto response = transport.post(url, bytes("payload"), std::chrono::seconds{5});
    CHECK(response.status == 201);
    CHECK(std::string(response.body.begin(), response.body.end()) == "OK");
    CHECK(server.request().find("POST /sync?test=1 HTTP/1.1") != std::string::npos);
    CHECK(server.request().find("payload") != std::string::npos);
}

template <typename T>
void write(std::vector<std::uint8_t>& image, std::size_t offset, const T& value) {
    CHECK(offset + sizeof(T) <= image.size());
    std::memcpy(image.data() + offset, &value, sizeof(value));
}

void write_text(std::vector<std::uint8_t>& image, std::size_t offset, std::string_view value) {
    CHECK(offset + value.size() + 1 <= image.size());
    std::memcpy(image.data() + offset, value.data(), value.size());
    image[offset + value.size()] = 0;
}

std::vector<std::uint8_t> mapping_image() {
    std::vector<std::uint8_t> image(0xE00);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    write(image, 0, dos);
    write<DWORD>(image, 0x80, IMAGE_NT_SIGNATURE);
    IMAGE_FILE_HEADER file{};
    file.Machine = IMAGE_FILE_MACHINE_AMD64;
    file.NumberOfSections = 3;
    file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;
    write(image, 0x84, file);
    IMAGE_OPTIONAL_HEADER64 optional{};
    optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    optional.AddressOfEntryPoint = 0x1000;
    optional.BaseOfCode = 0x1000;
    optional.ImageBase = 0x180000000ULL;
    optional.SectionAlignment = 0x1000;
    optional.FileAlignment = 0x200;
    optional.SizeOfImage = 0x4000;
    optional.SizeOfHeaders = 0x400;
    optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x2000, 40};
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x2100, 12};
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {0x2200, sizeof(IMAGE_TLS_DIRECTORY64)};
    optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {0x3000, sizeof(RUNTIME_FUNCTION)};
    write(image, 0x98, optional);

    const std::size_t section_offset = 0x98 + sizeof(optional);
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.Misc.VirtualSize = 0x200;
    text.VirtualAddress = 0x1000;
    text.SizeOfRawData = 0x200;
    text.PointerToRawData = 0x400;
    text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    write(image, section_offset, text);
    IMAGE_SECTION_HEADER rdata{};
    std::memcpy(rdata.Name, ".rdata", 6);
    rdata.Misc.VirtualSize = 0x600;
    rdata.VirtualAddress = 0x2000;
    rdata.SizeOfRawData = 0x600;
    rdata.PointerToRawData = 0x600;
    rdata.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    write(image, section_offset + sizeof(text), rdata);
    IMAGE_SECTION_HEADER pdata{};
    std::memcpy(pdata.Name, ".pdata", 6);
    pdata.Misc.VirtualSize = 0x200;
    pdata.VirtualAddress = 0x3000;
    pdata.SizeOfRawData = 0x200;
    pdata.PointerToRawData = 0xC00;
    pdata.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    write(image, section_offset + 2 * sizeof(text), pdata);

    IMAGE_IMPORT_DESCRIPTOR import{};
    import.OriginalFirstThunk = 0x2040;
    import.Name = 0x2080;
    import.FirstThunk = 0x2060;
    write(image, 0x600, import);
    write<std::uint64_t>(image, 0x640, 0x2090);
    write<std::uint64_t>(image, 0x648, IMAGE_ORDINAL_FLAG64 | 7);
    write<std::uint64_t>(image, 0x650, 0);
    write_text(image, 0x680, "kernel32.dll");
    write<std::uint16_t>(image, 0x690, 3);
    write_text(image, 0x692, "Sleep");

    IMAGE_BASE_RELOCATION relocation{};
    relocation.VirtualAddress = 0x1000;
    relocation.SizeOfBlock = 12;
    write(image, 0x700, relocation);
    write<std::uint16_t>(image, 0x708, static_cast<std::uint16_t>((IMAGE_REL_BASED_DIR64 << 12U) | 8));
    write<std::uint16_t>(image, 0x70A, 0);

    IMAGE_TLS_DIRECTORY64 tls{};
    tls.AddressOfCallBacks = optional.ImageBase + 0x2280;
    write(image, 0x800, tls);
    write<std::uint64_t>(image, 0x880, optional.ImageBase + 0x1000);
    write<std::uint64_t>(image, 0x888, 0);

    RUNTIME_FUNCTION function{};
    function.BeginAddress = 0x1000;
    function.EndAddress = 0x1010;
    function.UnwindData = 0x2050;
    write(image, 0xC00, function);
    return image;
}

void test_mapping_plan() {
    const auto image = mapping_image();
    const auto plan = makima::platform::PortableExecutableMappingPlanner{}.create_plan(image);
    CHECK(plan.preferred_image_base == 0x180000000ULL);
    CHECK(plan.entry_point_rva == 0x1000);
    CHECK(plan.sections.size() == 3);
    CHECK(plan.relocations.size() == 1 && plan.relocations[0].target_rva == 0x1008);
    CHECK(plan.imports.size() == 1 && plan.imports[0].name == "kernel32.dll");
    CHECK(plan.imports[0].symbols.size() == 2);
    CHECK(plan.imports[0].symbols[0].name == "Sleep");
    CHECK(plan.imports[0].symbols[1].by_ordinal && plan.imports[0].symbols[1].ordinal == 7);
    CHECK(plan.tls_callback_rvas == std::vector<std::uint32_t>{0x1000});
    CHECK(plan.exception_functions.size() == 1);
    CHECK(plan.unsupported_execution_steps.empty());

    makima::platform::PlanningManualMapper mapper;



    const auto result = mapper.map_image(0, image);
    CHECK(!result.success);
    CHECK(!mapper.last_plan().has_value());
    CHECK(result.message.find("cannot be zero") != std::string::npos);

    auto invalid = image;
    invalid[0] = 0;
    bool rejected = false;
    try {
        static_cast<void>(
            makima::platform::PortableExecutableMappingPlanner{}.create_plan(invalid));
    } catch (const std::exception&) {
        rejected = true;
    }
    CHECK(rejected);
}

void test_discovery_and_system() {
    std::array<wchar_t, 32768> executable{};
    const auto length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
    CHECK(length > 0 && length < executable.size());
    std::wstring image_name(executable.data(), length);
    const auto separator = image_name.find_last_of(L"\\/");
    image_name = separator == std::wstring::npos ? image_name : image_name.substr(separator + 1);
    makima::platform::ToolhelpTargetDiscovery discovery{{{"self", {image_name}}}};
    const auto self = discovery.wait_for_target("SELF", std::chrono::milliseconds{50});
    CHECK(self.has_value());
    CHECK(self->process_id == GetCurrentProcessId());
    CHECK(!discovery.wait_for_target("unknown", std::chrono::milliseconds{1}).has_value());

    makima::platform::WindowsEnvironmentInspector inspector;
    const auto report = inspector.inspect();
    CHECK(report.physical_memory_bytes > 0);
    CHECK(report.native_machine != 0);
    makima::platform::WindowsSystemService system{1};
    CHECK(system.check_ram().bool_or("success"));
    CHECK(system.check_vm().bool_or("success"));
    CHECK(system.check_connection().find("connected") != nullptr);

    makima::platform::TokenPrivilegeManager privileges;
    const auto missing = privileges.enable(L"SePrivilegeThatDoesNotExist");
    CHECK(!missing.success);
    static_cast<void>(privileges.current_process_is_elevated());
}

void test_win32_lifecycle() {
    const auto name = L"Local\\MakimaPlatformTest-" + std::to_wstring(GetCurrentProcessId()) +
                      L"-" + std::to_wstring(GetTickCount64());
    bool initialized = false;
    bool shutdown = false;
    makima::platform::Win32ApplicationPlatform first{
        name,
        [&] { initialized = true; },
        [&] { shutdown = true; },
    };
    makima::platform::Win32ApplicationPlatform second{name};
    CHECK(first.acquire_single_instance());
    CHECK(!second.acquire_single_instance());
    first.initialize();
    CHECK(initialized);
    first.shutdown();
    CHECK(shutdown);
    CHECK(second.acquire_single_instance());
    second.shutdown();
}

void test_composition_services() {
    CHECK(!makima::platform::default_credential_file().empty());

    makima::platform::AccountExtensionConfiguration account_configuration;
    account_configuration.discord_user = makima::application::Json::Object{{"name", "Test User"}};
    account_configuration.redemption_products.emplace("test", "Test Product");
    account_configuration.changelogs.emplace(
        "test-product",
        makima::application::Json::Array{
            makima::application::Json::Object{{"type", "update"}, {"title", "Test"}}});
    makima::platform::ConfiguredAccountExtension account_extension{
        std::move(account_configuration)};
    CHECK(account_extension.discord_start().bool_or("success"));
    CHECK(account_extension.discord_poll().string_or("status") == "success");
    CHECK(account_extension.redeem("test").bool_or("success"));
    CHECK(!account_extension.redeem("test").bool_or("success"));
    CHECK(account_extension.user().is_object());
    CHECK(account_extension.changelogs("test-product").is_array());

    makima::platform::LocalUpdateSource updates{"3.0.0-test"};
    const auto offer = updates.check();
    CHECK(!offer.available);
    CHECK(offer.current_version == "3.0.0-test");
    CHECK(offer.offered_version == offer.current_version);
    try {
        static_cast<void>(updates.download(offer, {}));
        CHECK(false);
    } catch (const makima::application::ApplicationError&) {
    }
}

void test_recovered_support_modules() {
    const auto endpoint = makima::platform::loader_control_endpoint("a b/+");
    CHECK(endpoint.host == L"makima.rip");
    CHECK(endpoint.port == 443 && endpoint.secure);
    CHECK(endpoint.path == L"/api/v3/loader/session-ws?ticket=a%20b%2F%2B");

    const auto processes = makima::platform::ProcessInventory{}.snapshot();
    CHECK(!processes.empty());
    CHECK(std::ranges::any_of(processes, [](const auto& process) {
        return process.process_id == GetCurrentProcessId();
    }));

    const auto environment = makima::platform::WindowsEnvironmentInspector{}.inspect();
    CHECK(environment.graphics_scheduling.size() <= 128);
    const std::array<std::uint8_t, 3> screenshot{0x01, 0x02, 0x03};
    makima::application::Json event_details{makima::application::Json::Object{}};
    const auto event = makima::platform::build_security_event(
        "platform_test",
        makima::platform::SecurityEventSeverity::critical,
        std::move(event_details),
        processes,
        screenshot,
        "S-1-5-21-test");
    CHECK(event.string_or("event_type") == "platform_test");
    CHECK(event.string_or("severity") == "critical");
    CHECK(event.string_or("details") == "{}");
    CHECK(event.find("process_list") != nullptr && event.find("process_list")->is_string());
    CHECK(event.string_or("screenshot_b64") == "AQID");
    CHECK(event.string_or("sid") == "S-1-5-21-test");
    CHECK(makima::platform::exception_event_name(EXCEPTION_ACCESS_VIOLATION) ==
          "access_violation");
    const auto exception = makima::platform::format_unhandled_exception_event(
        EXCEPTION_ACCESS_VIOLATION, 0x1234, 7);
    CHECK(exception.string_or("event") == "access_violation");
    CHECK(exception.bool_or("critical"));
    CHECK(makima::platform::current_thread_id() == GetCurrentThreadId());
    bool monitor_installed = false;
    {
        makima::platform::UnhandledExceptionMonitor monitor{
            [&](makima::application::Json) { monitor_installed = true; }};
        CHECK(!monitor_installed);
    }
    makima::platform::CodeViewIdentity codeview{
        .guid = {0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
        .age = 2,
        .pdb_name = "ntkrnlmp.pdb",
    };
    CHECK(makima::platform::microsoft_symbol_url(codeview) ==
          "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/00112233445566778899AABBCCDDEEFF2/ntkrnlmp.pdb");

    const auto missing_service = makima::platform::query_service_status(
        L"MakimaServiceNameThatMustNotExist");
    CHECK(!missing_service.installed);
}

}

int main() {
    test_crypto();
    test_http();
    test_mapping_plan();
    test_discovery_and_system();
    test_win32_lifecycle();
    test_composition_services();
    test_recovered_support_modules();
    return failures == 0 ? 0 : 1;
}
