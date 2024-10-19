//
// Created by Mher Tolpin on 26/09/2024.
//

#include "response.h"

response_header::response_header(const std::vector<char> &header) {
    this->version = static_cast<uint8_t>(header[0]);
    this->received_code = 0;
    this->payload_size = 0;
    std::memcpy(&this->received_code, header.data() + 1, sizeof(received_code));
    std::memcpy(&payload_size, header.data() + 3, sizeof(payload_size));
}

base_response * response_header::get_child_request_class(const std::vector<char> &payload) const {
    switch (this->received_code) {
        case response_type::REGISTRATION_SUCCESS:
            return new registration_success_response(payload);
        case response_type::REGISTRATION_FAILURE:
            return new registration_failure_response(payload);
        case response_type::LOGIN_SUCCESS:
            return new login_success_response(payload);
        case response_type::LOGIN_FAILURE:
            return new login_failure_response(payload);
        case response_type::PUBKEY_RECEIVED:
            return new pubkey_received_response(payload);
        case response_type::ACK:
            return new ack_response(payload);
        case response_type::FILE_RECEIVED:
            return new file_received_response(payload);
        case response_type::GENERAL_ERROR:
            return new general_error_response(payload);
        default:
            throw std::runtime_error("Unsupported response code.");;
    }
}
