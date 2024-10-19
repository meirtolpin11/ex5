//
// Created by Mher Tolpin on 26/09/2024.
//

#include "request.h"

#include <boost/asio/connect.hpp>

#include "response.h"

std::vector<char> base_request::serialize() {
    std::vector<char> out_buffer;

    // copy client id as 16 bytes string
    char client_id[16] = {};
    std::copy(this->client_id.begin(), this->client_id.end(), client_id);
    out_buffer.insert(out_buffer.end(), client_id, client_id + 16);

    out_buffer.push_back(static_cast<char>(this->version));

    char code[2];
    std::memcpy(code, &this->code, 2);
    out_buffer.insert(out_buffer.end(), code, code + 2);

    std::vector<char> payload = this->serialize_payload();

    const uint payload_size = payload.size();
    char payload_size_c[4];
    std::memcpy(payload_size_c, &payload_size, 4);

    out_buffer.insert(out_buffer.end(), payload_size_c, payload_size_c + 4);

    out_buffer.insert(out_buffer.end(), payload.begin(), payload.end());

    return out_buffer;
}

std::vector<char> register_request::serialize_payload() {
    char user_name[255] = {};
    std::copy(this->user_name.begin(), this->user_name.end(), user_name);

    std::vector<char> payload;
    payload.insert(payload.end(), user_name, user_name + 255);

    return payload;
}

std::vector<char> public_key_upload_request::serialize_payload() {
    char user_name[255] = {};
    std::copy(this->client_id.begin(), this->client_id.end(), user_name);

    std::vector<char> payload;
    payload.insert(payload.end(), user_name, user_name + 255);

    char pubkey[160] = {};
    std::copy(this->public_key.begin(), this->public_key.end(), pubkey);
    payload.insert(payload.end(), pubkey, pubkey + 160);

    return payload;
}

std::vector<char> login_request::serialize_payload() {
    return register_request::serialize_payload();
}

std::vector<char> upload_file_request::serialize_payload() {
    std::vector<char> payload;
    char content_size[4] = {};
    char original_file_size[4] = {};
    char packet_number[2] = {};
    char total_packets[2] = {};
    char file_name[255] = {};

    std::memcpy(content_size, &this->content_size, 4);
    std::memcpy(original_file_size, &this->orig_file_size, 4);
    std::memcpy(packet_number, &this->packet_number, 2);
    std::memcpy(total_packets, &this->total_packets, 2);
    std::copy(this->file_name.begin(), this->file_name.end(), file_name);

    payload.insert(payload.end(), content_size, content_size + 4);
    payload.insert(payload.end(), original_file_size, original_file_size + 4);
    payload.insert(payload.end(), packet_number, packet_number + 2);
    payload.insert(payload.end(), total_packets, total_packets + 2);
    payload.insert(payload.end(), file_name, file_name + 255);

    payload.insert(payload.end(), this->content.begin(), this->content.end());

    return payload;
}

std::vector<char> correct_crc_request::serialize_payload() {
    std::vector<char> payload;
    char file_name[255];
    std::copy(this->file_name.begin(), this->file_name.end(), file_name);
    payload.insert(payload.end(), file_name, file_name + 255);
    return payload;
}

std::vector<char> unexpected_crc_request::serialize_payload() {
    return correct_crc_request::serialize_payload();
}

std::vector<char> unexpected_crc_request_fourth_time::serialize_payload() {
    return unexpected_crc_request::serialize_payload();
}


