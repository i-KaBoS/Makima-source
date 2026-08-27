#pragma once

#include "makima/application/common.hpp"
#include "makima/application/json.hpp"

#include <string_view>

namespace makima::application {

class IEventSink {
public:
    virtual ~IEventSink() = default;
    virtual void publish(std::string_view event, const Json& data) = 0;
    virtual void publish_serialized(std::string_view document) {
        const Json envelope = Json::parse(document);
        if (!envelope.is_object())
            throw ApplicationError("serialized event is not an object");
        const Json* data = envelope.find("data");
        if (data == nullptr)
            throw ApplicationError("serialized event is missing event/data fields");
        publish(envelope.string_or("event"), *data);
    }
};

}
