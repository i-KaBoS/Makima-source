#include "makima/application/catalog.hpp"
#include "makima/application/command_dispatcher.hpp"
#include "makima/application/credential_store.hpp"
#include "makima/application/identity.hpp"
#include "makima/application/launch_coordinator.hpp"
#include "makima/application/protocol.hpp"
#include "makima/application/ui_host.hpp"
#include "makima/application/update_coordinator.hpp"

#include <algorithm>
#include <iostream>
#include <set>

using namespace makima::application;

namespace {

int failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "check failed: " #condition " at line " << __LINE__ << '\n'; ++failures; } } while (false)

std::span<const std::uint8_t> text_bytes(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

class FakeCrypto final : public ICryptoProvider {
public:
    Bytes random_bytes(std::size_t count) override {
        Bytes result(count);
        for (auto& value : result) value = next_++;
        return result;
    }

    Hash256 sha256(std::span<const std::uint8_t> input) override {
        Hash256 result{};
        std::uint32_t state = 2166136261U;
        for (const auto value : input) state = (state ^ value) * 16777619U;
        for (std::size_t i = 0; i < result.size(); ++i) {
            state = state * 1664525U + 1013904223U + static_cast<std::uint32_t>(i);
            result[i] = static_cast<std::uint8_t>(state >> 24);
        }
        return result;
    }

    Hash256 hmac_sha256(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> input) override {
        Bytes combined(key.begin(), key.end());
        combined.push_back(0x5c);
        combined.insert(combined.end(), input.begin(), input.end());
        return sha256(combined);
    }

    Bytes aes256_gcm_encrypt(
        const Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> associated_data) override {
        Bytes authenticated(associated_data.begin(), associated_data.end());
        authenticated.insert(authenticated.end(), nonce.begin(), nonce.end());
        authenticated.insert(authenticated.end(), plaintext.begin(), plaintext.end());
        const Hash256 tag = hmac_sha256(key, authenticated);
        Bytes result(plaintext.begin(), plaintext.end());
        result.insert(result.end(), tag.begin(), tag.begin() + 16);
        return result;
    }

    Bytes aes256_gcm_decrypt(
        const Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext_and_tag,
        std::span<const std::uint8_t> associated_data) override {
        if (ciphertext_and_tag.size() < 16) throw ApplicationError("fake GCM tag is missing");
        const auto plaintext = ciphertext_and_tag.first(ciphertext_and_tag.size() - 16);
        Bytes expected = aes256_gcm_encrypt(key, nonce, plaintext, associated_data);
        if (!std::equal(expected.end() - 16, expected.end(), ciphertext_and_tag.end() - 16))
            throw ApplicationError("fake GCM tag mismatch");
        return Bytes(plaintext.begin(), plaintext.end());
    }

    Bytes aes256_cbc_decrypt(
        const Hash256&,
        std::span<const std::uint8_t, 16>,
        std::span<const std::uint8_t> ciphertext) override {
        return Bytes(ciphertext.begin(), ciphertext.end());
    }

    KeyPair x25519_generate() override {
        KeyPair result;
        result.private_key.assign(32, 0x24);
        result.public_key.fill(0x42);
        return result;
    }

    Hash256 x25519_exchange(
        std::span<const std::uint8_t> private_key,
        const Hash256& peer_public_key) override {
        Bytes combined(private_key.begin(), private_key.end());
        combined.insert(combined.end(), peer_public_key.begin(), peer_public_key.end());
        return sha256(combined);
    }

    bool ed25519_verify(
        const Hash256&,
        std::span<const std::uint8_t> signature,
        std::span<const std::uint8_t> message) override {
        return signature.size() == 64 && message.size() == 64;
    }

private:
    std::uint8_t next_{1};
};

class MemoryCredentials final : public ICredentialStorage {
public:
    void write(std::span<const std::uint8_t> bytes) override { value = Bytes(bytes.begin(), bytes.end()); }
    std::optional<Bytes> read() const override { return value; }
    void erase() override { value.reset(); }
    std::optional<Bytes> value;
};

class LabelProtector final : public ISecretProtector {
public:
    Bytes protect(std::span<const std::uint8_t> input, std::string_view purpose) override {
        last_purpose = purpose;
        Bytes result(input.begin(), input.end());
        for (auto& byte : result) byte ^= 0xa5;
        return result;
    }
    Bytes unprotect(std::span<const std::uint8_t> input, std::string_view purpose) override {
        return protect(input, purpose);
    }
    std::string last_purpose;
};

class ThrowingIdentity final : public IHardwareIdentity {
public:
    std::string current_user_sid() const override { throw ApplicationError("no token"); }
};

class RecordingTarget final : public ICommandTarget {
public:
    Json execute(UiCommand command, const Json::Object&) override {
        calls.push_back(command);
        return Json::Object{{"success", true}};
    }
    std::vector<UiCommand> calls;
};

class RecordingBridge final : public IWebViewBridge {
public:
    void post_json(std::string_view json) override { messages.emplace_back(json); }
    std::vector<std::string> messages;
};

class Events final : public IEventSink {
public:
    void publish(std::string_view event, const Json& data) override {
        values.emplace_back(std::string(event), data);
    }
    std::vector<std::pair<std::string, Json>> values;
};

Bytes pe_image() {
    Bytes image(128, 0);
    image[0] = 'M'; image[1] = 'Z'; image[0x3c] = 0x40;
    image[0x40] = 'P'; image[0x41] = 'E';
    return image;
}

class Payloads final : public IAuthorizedPayloadSource {
public:
    AuthorizedPayload download_authorized(std::string_view slug, std::string_view branch) override {
        seen_slug = slug; seen_branch = branch;
        return {pe_image(), {}, {}};
    }
    std::string seen_slug, seen_branch;
};

class Discovery final : public ITargetDiscovery {
public:
    std::optional<TargetProcess> wait_for_target(std::string_view slug, std::chrono::milliseconds) override {
        seen_slug = slug; return TargetProcess{77, "target.exe"};
    }
    std::string seen_slug;
};

class Mapper final : public IManualMapper {
public:
    OperationResult map_image(std::uint32_t process_id, std::span<const std::uint8_t> image) override {
        pid = process_id; size = image.size(); return OperationResult::ok();
    }
    std::uint32_t pid{}; std::size_t size{};
};

class UpdateSource final : public IUpdateSource {
public:
    UpdateOffer check() override { return {true, "1.0", "1.1", 1234}; }
    UpdatePackage download(const UpdateOffer&, Progress progress) override {
        progress(50, "Downloading"); return {"update.exe", {}};
    }
};

class Installer final : public IUpdateInstaller {
public:
    void verify_stage_and_restart(const UpdatePackage&) override { called = true; }
    bool called{};
};

void test_json() {
    const Json value = Json::parse(R"({"name":"a\n\u263a","ok":true,"items":[1,null]})");
    CHECK(value.string_or("name") == "a\n\xe2\x98\xba");
    CHECK(value.bool_or("ok"));
    CHECK(Json::parse(value.dump()).find("items")->as_array().size() == 2);
}

void test_protocol() {
    FakeCrypto crypto;
    ProtocolCodec codec(crypto);
    const Hash256 key = crypto.sha256(text_bytes("key"));
    const Bytes payload{1, 2, 3};
    const Bytes packed = codec.pack_frame(key, 9, Opcode::login, payload, 123456);
    const Frame frame = codec.unpack_frame(key, packed);
    CHECK(frame.sequence == 9 && frame.timestamp_ms == 123456);
    CHECK(frame.opcode == Opcode::login && frame.payload == payload);
    CHECK(ProtocolCodec::pack_text("abc") == Bytes({3, 0, 'a', 'b', 'c'}));

    HandshakeAttempt attempt = codec.begin_handshake("S-1-5-21", 50);
    CHECK(attempt.request.size() == 156);
    Bytes hello_payload(96, 0x77);
    const Hash256 bootstrap = crypto.sha256(text_bytes(bootstrap_secret));
    const Bytes hello = codec.pack_frame(bootstrap, 1, Opcode::server_hello, hello_payload, 51);
    const Hash256 session = codec.finish_handshake(attempt, hello);
    CHECK(std::any_of(session.begin(), session.end(), [](auto byte) { return byte != 0; }));

    LaunchTicket ticket;
    ticket.salt.fill(0x11);
    Bytes plaintext = pe_image();
    ticket.expected_sha256 = crypto.sha256(plaintext);
    const Hash256 binding = crypto.hmac_sha256(text_bytes("hwid"), text_bytes("S-1-5-21"));
    const Hash256 bound = codec.hkdf(binding, ticket.salt, binding_label);
    const std::array<std::uint8_t, 32> zeros{};
    const Hash256 mac_key = codec.hkdf(bound, zeros, authentication_label);
    Bytes inner(16, 0x22);
    inner.insert(inner.end(), plaintext.begin(), plaintext.end());
    const Hash256 mac = crypto.hmac_sha256(mac_key, inner);
    inner.insert(inner.end(), mac.begin(), mac.end());
    const Hash256 payload_key = codec.hkdf(session, ticket.salt, payload_label);
    Bytes nonce(12, 0x33);
    Bytes outer = crypto.aes256_gcm_encrypt(payload_key, nonce, inner, {});
    Bytes response{1};
    response.insert(response.end(), nonce.begin(), nonce.end());
    response.insert(response.end(), outer.begin(), outer.end());
    CHECK(codec.decrypt_payload(response, session, ticket, "S-1-5-21") == plaintext);
}

void test_catalog() {
    Bytes payload{1, 42, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    for (std::string_view field : {"Makima", "makima", "image", "premium", "active",
            "2030-01-01", "undetected"}) {
        const Bytes packed = ProtocolCodec::pack_text(field);
        payload.insert(payload.end(), packed.begin(), packed.end());
    }
    const LoginModel model = parse_login_payload(payload);
    CHECK(model.user_id == 42);
    CHECK(model.subscriptions.size() == 1);
    CHECK(model.subscriptions[0].slug == "makima");

    LoginModel enriched;
    enriched.user_id = 42;
    enriched.fields.push_back(Json::parse(
        R"({"user":{"name":"Alice","email":"a@example.com","discord_avatar":"avatar"},"products":[{"slug":"makima","changelogs":[{"type":"update","title":"v2"}]}]})"));
    const auto user = find_user_profile(enriched);
    CHECK(user.has_value() && user->string_or("name") == "Alice");
    const auto cached_changelogs = find_product_changelogs(enriched, "makima");
    CHECK(cached_changelogs.has_value() && cached_changelogs->as_array().size() == 1);

    const auto changelogs = parse_changelogs(Json::parse(
        R"([{"type":"update","title":"v1","message":"done","publisher":"Makima","created_at":"now","is_resolved":true}])"));
    CHECK(changelogs.size() == 1 && changelogs[0].is_resolved);
}

void test_credentials_and_identity() {
    MemoryCredentials storage;
    LabelProtector protector;
    CredentialRepository credentials(storage, protector);
    credentials.save({"a@example.com", "secret"});
    CHECK(protector.last_purpose == credential_protection_label);
    CHECK(storage.value.has_value());
    const auto loaded = credentials.load();
    CHECK(loaded && loaded->email == "a@example.com" && loaded->password == "secret");
    credentials.erase();
    CHECK(!credentials.load());
    CHECK(resolve_hwid(ThrowingIdentity{}) == "anon");
}

void test_dispatcher() {
    RecordingTarget target;
    RecordingBridge bridge;
    WebViewCommandDispatcher dispatcher(target, bridge);
    std::set<std::string> names;
    for (unsigned value = static_cast<unsigned>(UiCommand::ready);
         value <= static_cast<unsigned>(UiCommand::do_update); ++value) {
        const auto command = static_cast<UiCommand>(value);
        const std::string name(WebViewCommandDispatcher::name_for_command(command));
        CHECK(!name.empty());
        CHECK(names.insert(name).second);
        CHECK(WebViewCommandDispatcher::command_for_name(name) == command);
    }
    CHECK(names.size() == 22);
    dispatcher.receive(R"({"ready":true})");
    CHECK(target.calls.back() == UiCommand::ready && bridge.messages.empty());
    dispatcher.receive(R"({"id":"abc","name":"login","args":{"email":"a","password":"b"}})");
    CHECK(target.calls.back() == UiCommand::login);
    CHECK(Json::parse(bridge.messages.back()).string_or("id") == "abc");
    dispatcher.receive(R"({"id":"bad","name":"not_a_command","args":{}})");
    CHECK(Json::parse(bridge.messages.back()).find("result")->find("error") != nullptr);
}

void test_coordinators_and_assets() {
    Payloads payloads; Discovery discovery; Mapper mapper; Events launch_events;
    AuthorizedLaunchCoordinator launches(payloads, discovery, mapper, launch_events);
    const OperationResult launched = launches.launch("product", "beta");
    CHECK(launched.success && payloads.seen_slug == "product" && payloads.seen_branch == "beta");
    CHECK(discovery.seen_slug == "product" && mapper.pid == 77 && mapper.size == pe_image().size());
    CHECK(launch_events.values.size() == 5);

    UpdateSource source; Installer installer; Events update_events;
    UpdateCoordinator updates(source, installer, update_events);
    CHECK(updates.check().available);
    CHECK(updates.install().success && installer.called);
    CHECK(update_events.values.size() == 2);

    MemoryAssetProvider assets;
    assets.add("index.html", "text/html", Bytes{'o', 'k'});
    const auto asset = assets.get("/index.html");
    CHECK(asset && asset->mime_type == "text/html" && asset->content == Bytes({'o', 'k'}));
}

}

int main() {
    test_json();
    test_protocol();
    test_catalog();
    test_credentials_and_identity();
    test_dispatcher();
    test_coordinators_and_assets();
    if (failures) std::cerr << failures << " test checks failed\n";
    return failures ? 1 : 0;
}
