#include "kernel/silo/silo.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <span>
#include <utility>
#include <vector>

namespace makima::kernel::silo {



std::vector<std::uint64_t> collect_active_record_keys(
    std::span<const SiloRecord> records) {
    std::vector<std::uint64_t> keys;
    keys.reserve(records.size());
    for (const auto& record : records) {
        if (record.active()) {
            keys.push_back(record.key);
        }
    }
    return keys;
}



void sort_records_by_key(std::vector<SiloRecord>& records) {
    std::stable_sort(
        records.begin(),
        records.end(),
        [](const SiloRecord& left, const SiloRecord& right) {
            if (left.key != right.key) {
                return left.key < right.key;
            }
            return left.value < right.value;
        });
}



const SiloRecord* find_record(
    std::span<const SiloRecord> records,
    std::uint64_t key) noexcept {
    const auto found = std::find_if(
        records.begin(),
        records.end(),
        [key](const SiloRecord& record) {
            return record.active() && record.key == key;
        });
    return found == records.end() ? nullptr : &*found;
}





std::uint64_t checksum_active_records(std::span<const SiloRecord> records) noexcept {
    std::uint64_t checksum = 0xCBF29CE484222325ULL;
    for (const auto& record : records) {
        if (!record.active()) {
            continue;
        }
        checksum = fold_silo_record_key(checksum ^ record.key, record.value);
        checksum = hash_silo_payload(record.payload, checksum);
    }
    return checksum;
}



std::vector<SiloRecord> merge_records(
    std::span<const SiloRecord> base_records,
    std::span<const SiloRecord> replacement_records) {
    std::vector<SiloRecord> merged(base_records.begin(), base_records.end());
    append_unique_records(merged, replacement_records);
    sort_records_by_key(merged);
    return merged;
}


std::vector<SiloRecord> copy_active_records(std::span<const SiloRecord> records) {
    std::vector<SiloRecord> active_records;
    active_records.reserve(records.size());
    std::copy_if(
        records.begin(),
        records.end(),
        std::back_inserter(active_records),
        [](const SiloRecord& record) { return record.active(); });
    return active_records;
}


void append_unique_records(
    std::vector<SiloRecord>& destination,
    std::span<const SiloRecord> source) {
    for (const auto& record : source) {
        const auto existing = std::find_if(
            destination.begin(),
            destination.end(),
            [&](const SiloRecord& candidate) { return candidate.key == record.key; });
        if (existing == destination.end()) {
            destination.push_back(record);
        } else {
            *existing = record;
        }
    }
}

}
