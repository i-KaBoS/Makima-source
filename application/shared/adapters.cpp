#include "pipelines.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>

namespace makima::application::shared {

const char* sync_service_origin() {
    static const char* const origin = [] {
        constexpr char value[] = "https://makima.rip";
        auto* const storage = static_cast<char*>(::operator new(sizeof(value)));
        std::memcpy(storage, value, sizeof(value));
        return storage;
    }();
    return origin;
}

std::array<std::byte, 32>* xor_authenticated_transport_state(
    const AuthenticatedTransportState* state,
    std::array<std::byte, 32>* output) noexcept {
    if (output == nullptr) return nullptr;
    output->fill(std::byte{});
    if (state == nullptr || state->left == nullptr || state->right == nullptr) return output;
    for (std::size_t index = 0; index < output->size(); ++index) {
        (*output)[index] = state->left[index] ^ state->right[index];
    }
    return output;
}




void cleanup_ecdh_session_import_bindings(
    ::makima::payload::crypto::EcdhSession& session) noexcept {
    if (session.private_key != nullptr) {
        if (const auto destroy_key = resolve_bcrypt_destroy_key()) {
            destroy_key(static_cast<BCRYPT_KEY_HANDLE>(session.private_key));
        }
        session.private_key = nullptr;
    }
    if (session.algorithm != nullptr) {
        if (const auto close_algorithm =
                resolve_bcrypt_close_algorithm_provider()) {
            close_algorithm(static_cast<BCRYPT_ALG_HANDLE>(session.algorithm), 0);
        }
        session.algorithm = nullptr;
    }
    session.public_component.fill(std::byte{});
    session.initialized = false;
}

}
