#include "makima/platform/bitmap_capture.hpp"

#include <windows.h>
#include <gdiplus.h>
#include <objidl.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <optional>
#include <string_view>
#include <vector>

namespace makima::platform {
namespace {

constexpr ULONG jpeg_quality = 70;
constexpr std::wstring_view jpeg_mime_type = L"image/jpeg";

[[nodiscard]] bool gdiplus_ready() noexcept {
    struct State final {
        ULONG_PTR token{};
        bool ready{};
    };

    static State state;
    if (!state.ready) {
        Gdiplus::GdiplusStartupInput input{};
        input.GdiplusVersion = 1;
        if (Gdiplus::GdiplusStartup(&state.token, &input, nullptr) == Gdiplus::Ok) {
            state.ready = true;
        }
    }
    return state.ready;
}

class ScreenDeviceContext final {
public:
    ScreenDeviceContext() noexcept : value_(GetDC(nullptr)) {}
    ~ScreenDeviceContext() {
        if (value_ != nullptr) {
            ReleaseDC(nullptr, value_);
        }
    }
    ScreenDeviceContext(const ScreenDeviceContext&) = delete;
    ScreenDeviceContext& operator=(const ScreenDeviceContext&) = delete;
    [[nodiscard]] HDC get() const noexcept { return value_; }

private:
    HDC value_{};
};

class MemoryDeviceContext final {
public:
    explicit MemoryDeviceContext(HDC compatible) noexcept
        : value_(CreateCompatibleDC(compatible)) {}
    ~MemoryDeviceContext() {
        if (value_ != nullptr) {
            DeleteDC(value_);
        }
    }
    MemoryDeviceContext(const MemoryDeviceContext&) = delete;
    MemoryDeviceContext& operator=(const MemoryDeviceContext&) = delete;
    [[nodiscard]] HDC get() const noexcept { return value_; }

private:
    HDC value_{};
};

class OwnedBitmap final {
public:
    OwnedBitmap(HDC compatible, int width, int height) noexcept
        : value_(CreateCompatibleBitmap(compatible, width, height)) {}
    ~OwnedBitmap() {
        if (value_ != nullptr) {
            DeleteObject(value_);
        }
    }
    OwnedBitmap(const OwnedBitmap&) = delete;
    OwnedBitmap& operator=(const OwnedBitmap&) = delete;
    [[nodiscard]] HBITMAP get() const noexcept { return value_; }

private:
    HBITMAP value_{};
};

class SelectedBitmap final {
public:
    SelectedBitmap(HDC context, HBITMAP bitmap) noexcept
        : context_(context), previous_(SelectObject(context, bitmap)) {}
    ~SelectedBitmap() {
        SelectObject(context_, previous_);
    }
    SelectedBitmap(const SelectedBitmap&) = delete;
    SelectedBitmap& operator=(const SelectedBitmap&) = delete;
private:
    HDC context_{};
    HGDIOBJ previous_{};
};

class GdiPlusImage final {
public:
    explicit GdiPlusImage(HBITMAP bitmap) noexcept {
        Gdiplus::DllExports::GdipCreateBitmapFromHBITMAP(bitmap, nullptr, &value_);
    }
    ~GdiPlusImage() {
        Gdiplus::DllExports::GdipDisposeImage(value_);
    }
    GdiPlusImage(const GdiPlusImage&) = delete;
    GdiPlusImage& operator=(const GdiPlusImage&) = delete;
    [[nodiscard]] Gdiplus::GpImage* get() const noexcept { return value_; }

private:
    Gdiplus::GpBitmap* value_{};
};

class MemoryStream final {
public:
    MemoryStream() noexcept {
        if (CreateStreamOnHGlobal(nullptr, TRUE, &value_) != S_OK) {
            value_ = nullptr;
        }
    }
    ~MemoryStream() {
        if (value_ != nullptr) {
            value_->Release();
        }
    }
    MemoryStream(const MemoryStream&) = delete;
    MemoryStream& operator=(const MemoryStream&) = delete;
    [[nodiscard]] IStream* get() const noexcept { return value_; }

private:
    IStream* value_{};
};

[[nodiscard]] std::optional<CLSID> jpeg_encoder() {
    UINT count = 0;
    UINT bytes = 0;
    Gdiplus::DllExports::GdipGetImageEncodersSize(&count, &bytes);
    if (bytes == 0) {
        return std::nullopt;
    }

    auto* codecs = static_cast<Gdiplus::ImageCodecInfo*>(std::malloc(bytes));
    if (codecs == nullptr) {
        return std::nullopt;
    }
    Gdiplus::DllExports::GdipGetImageEncoders(count, bytes, codecs);
    for (UINT index = 0; index < count; ++index) {
        if (std::wcscmp(codecs[index].MimeType, jpeg_mime_type.data()) == 0) {
            const CLSID encoder = codecs[index].Clsid;
            std::free(codecs);
            return encoder;
        }
    }
    std::free(codecs);
    return std::nullopt;
}

[[nodiscard]] std::vector<std::uint8_t> stream_bytes(IStream* stream) {
    HGLOBAL memory = nullptr;
    if (GetHGlobalFromStream(stream, &memory) != S_OK) {
        return {};
    }
    const auto size = GlobalSize(memory);
    const auto* data = static_cast<const std::uint8_t*>(GlobalLock(memory));
    std::vector<std::uint8_t> result;
    if (size != 0 && data != nullptr) {
        result.assign(data, data + size);
    }
    GlobalUnlock(memory);
    return result;
}

}


std::vector<std::uint8_t> capture_virtual_desktop_jpeg() {
    if (!gdiplus_ready()) {
        return {};
    }

    const int left = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int top = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (width <= 0 || height <= 0) {
        return {};
    }

    ScreenDeviceContext screen;
    if (screen.get() == nullptr) {
        return {};
    }
    MemoryDeviceContext compatible{screen.get()};
    if (compatible.get() == nullptr) {
        return {};
    }
    OwnedBitmap bitmap{screen.get(), width, height};
    if (bitmap.get() == nullptr) {
        return {};
    }

    {
        SelectedBitmap selected{compatible.get(), bitmap.get()};
        BitBlt(
            compatible.get(), 0, 0, width, height,
            screen.get(), left, top, SRCCOPY | CAPTUREBLT);
    }

    const auto encoder = jpeg_encoder();
    if (!encoder) {
        return {};
    }
    GdiPlusImage image{bitmap.get()};
    MemoryStream stream;
    if (stream.get() == nullptr) {
        return {};
    }

    ULONG quality = jpeg_quality;
    Gdiplus::EncoderParameters parameters{};
    parameters.Count = 1;
    parameters.Parameter[0].Guid = Gdiplus::EncoderQuality;
    parameters.Parameter[0].NumberOfValues = 1;
    parameters.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    parameters.Parameter[0].Value = &quality;
    if (Gdiplus::DllExports::GdipSaveImageToStream(
            image.get(), stream.get(), &*encoder, &parameters) != Gdiplus::Ok) {
        return {};
    }
    return stream_bytes(stream.get());
}

}
