#include "makima/application/winhttp_certificate.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <memory>
#include <climits>
#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace makima::application {
namespace {

struct CertificateDeleter final {
    void operator()(const CERT_CONTEXT* certificate) const noexcept {
        if (certificate != nullptr) {
            CertFreeCertificateContext(certificate);
        }
    }
};

struct ChainDeleter final {
    void operator()(const CERT_CHAIN_CONTEXT* chain) const noexcept {
        if (chain != nullptr) {
            CertFreeCertificateChain(chain);
        }
    }
};

using Certificate = std::unique_ptr<const CERT_CONTEXT, CertificateDeleter>;
using CertificateChain = std::unique_ptr<const CERT_CHAIN_CONTEXT, ChainDeleter>;

std::wstring widen_host(std::string_view host) noexcept {
    try {
        if (host.empty() || host.size() > static_cast<std::size_t>(INT_MAX)) return {};
        const int count = MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, host.data(), static_cast<int>(host.size()),
            nullptr, 0);
        if (count <= 0) return {};
        std::wstring result(static_cast<std::size_t>(count), L'\0');
        if (MultiByteToWideChar(
                CP_UTF8, MB_ERR_INVALID_CHARS, host.data(), static_cast<int>(host.size()),
                result.data(), count) != count) {
            return {};
        }
        return result;
    } catch (...) {
        return {};
    }
}

std::string certificate_issuer(PCCERT_CONTEXT certificate) {
    const DWORD count = CertGetNameStringA(
        certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
        nullptr, nullptr, 0);
    if (count <= 1) return {};
    std::string issuer(count, '\0');
    if (CertGetNameStringA(
            certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
            nullptr, issuer.data(), count) != count) {
        return {};
    }
    issuer.resize(count - 1);
    std::transform(issuer.begin(), issuer.end(), issuer.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return issuer;
}

bool accepted_certificate_authority(PCCERT_CONTEXT certificate) {



    constexpr std::array<std::string_view, 9> authorities{
        "DigiCert", "Cloudflare", "Let's Encrypt", "Google Trust Services",
        "Baltimore CyberTrust", "ISRG Root", "Internet Security Research Group",
        "GTS CA", "GTS Root",
    };
    const std::string issuer = certificate_issuer(certificate);
    return std::ranges::any_of(authorities, [&](std::string_view authority) {
        std::string lower{authority};
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
        return issuer.find(lower) != std::string::npos;
    });
}

}

bool verify_winhttp_server_certificate(
    void* request_handle,
    std::string_view expected_host) noexcept {
    if (request_handle == nullptr || expected_host.empty()) return false;

    PCCERT_CONTEXT raw_certificate = nullptr;
    DWORD certificate_size = sizeof(raw_certificate);
    if (WinHttpQueryOption(
            static_cast<HINTERNET>(request_handle),
            WINHTTP_OPTION_SERVER_CERT_CONTEXT,
            &raw_certificate,
            &certificate_size) == FALSE ||
        raw_certificate == nullptr) return false;
    Certificate certificate{raw_certificate};

    CERT_CHAIN_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    PCCERT_CHAIN_CONTEXT raw_chain = nullptr;
    if (CertGetCertificateChain(
            nullptr,
            certificate.get(),
            nullptr,
            certificate->hCertStore,
            &parameters,
            0,
            nullptr,
            &raw_chain) == FALSE ||
        raw_chain == nullptr) return false;
    CertificateChain chain{raw_chain};
    const std::wstring host = widen_host(expected_host);
    if (host.empty()) return false;

    HTTPSPolicyCallbackData https{};
    https.cbStruct = sizeof(https);
    https.dwAuthType = AUTHTYPE_SERVER;
    https.fdwChecks = 0;
    https.pwszServerName = const_cast<wchar_t*>(host.c_str());
    CERT_CHAIN_POLICY_PARA policy_parameters{};
    policy_parameters.cbSize = sizeof(policy_parameters);
    policy_parameters.pvExtraPolicyPara = &https;
    CERT_CHAIN_POLICY_STATUS policy_status{};
    policy_status.cbSize = sizeof(policy_status);
    return CertVerifyCertificateChainPolicy(
               CERT_CHAIN_POLICY_SSL, chain.get(), &policy_parameters, &policy_status) != FALSE &&
           policy_status.dwError == S_OK && accepted_certificate_authority(certificate.get());
}

}
