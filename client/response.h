//
// Created by Mher Tolpin on 26/09/2024.
//

#ifndef RESPONSE_H
#define RESPONSE_H
#include <vector>

enum response_type{
    REGISTRATION_SUCCESS = 1600,
    REGISTRATION_FAILURE = 1601,
    PUBKEY_RECEIVED = 1602,
    FILE_RECEIVED = 1603,
    ACK = 1604,
    LOGIN_SUCCESS = 1605,
    LOGIN_FAILURE = 1606,
    GENERAL_ERROR = 1607
};

class base_response {
protected:
    response_type code;
    std::vector<char> client_id;
    std::vector<char> payload;
public:
    explicit base_response(const std::vector<char> &payload, const response_type resp_code): code(resp_code) {
        this->payload = payload;
        if (this->payload.size() >= 16) {
            this->client_id = std::vector<char>(16);
            std::copy_n(this->payload.begin(), 16, this->client_id.begin());
        }
    }

    [[nodiscard]] std::vector<char> get_client_id() const {
        return this->client_id;
    }

    [[nodiscard]] response_type get_code() const {
        return this->code;
    }
};


class registration_success_response : public base_response {
public:
    explicit registration_success_response(const std::vector<char> &payload) :
                            base_response(payload, REGISTRATION_SUCCESS) {}
    explicit registration_success_response(const std::vector<char> &payload, response_type resp_type) :
                            base_response(payload, resp_type) {}
};

class registration_failure_response : public registration_success_response {
public:
    explicit registration_failure_response(const std::vector<char> &payload) :
                                registration_success_response(payload, REGISTRATION_FAILURE) {}
};

class  pubkey_received_response : public base_response {
protected:
    std::vector<char> enc_aes_key;
public:
    explicit pubkey_received_response(const std::vector<char> &payload) : base_response(payload, PUBKEY_RECEIVED) {
        this->enc_aes_key = std::vector<char>(this->payload.size() - 16);
        std::copy(this->payload.begin() + 16, this->payload.end(), this->enc_aes_key.begin());
    }

    explicit pubkey_received_response(const std::vector<char> &payload, const response_type resp_code) :
            base_response(payload, resp_code) {
        this->enc_aes_key = std::vector<char>(this->payload.size());
        std::copy(this->payload.begin() + 16, this->payload.end(), this->enc_aes_key.begin());
    }

    [[nodiscard]] std::vector<char> get_enc_aes_key() const {
        return this->enc_aes_key;
    }
};

class file_received_response : public base_response {
protected:
    uint32_t content_size;
    std::vector<char> file_name;
    uint32_t checksum;
public:
    explicit file_received_response(const std::vector<char> &payload) : base_response(payload, FILE_RECEIVED) {
        this->content_size = 0;
        this->checksum = 0;
        this->file_name = std::vector<char>(255);
        std::memcpy(&this->content_size, this->payload.data() + 16, sizeof(this->content_size));
        std::copy_n(this->payload.begin() + 20, 255, this->file_name.begin());
        std::memcpy(&this->checksum, this->payload.data() + 275, sizeof(this->checksum));
    }

    uint32_t get_checksum() { return this->checksum; };
};

class ack_response : public base_response {
public:
    explicit ack_response(const std::vector<char> &payload)
        : base_response(payload, ACK) {
    }
};

class login_success_response : public pubkey_received_response {
public:
    explicit login_success_response(const std::vector<char> &payload) : pubkey_received_response(payload, LOGIN_SUCCESS) {
    }
};

class login_failure_response : public base_response {
public:
    explicit login_failure_response(const std::vector<char> &payload) : base_response(payload, LOGIN_FAILURE) {};
};

class general_error_response : public base_response {
public:
    explicit general_error_response(const std::vector<char> &payload) : base_response(payload, GENERAL_ERROR) {};
};

class response_header {
protected:
    uint8_t version;
    uint16_t received_code;
    uint32_t payload_size;

public:
    explicit response_header(const std::vector<char> &header);

    [[nodiscard]] uint32_t get_payload_size() const {
        return this->payload_size;
    }

    [[nodiscard]] base_response* get_child_request_class(const std::vector<char> &payload) const;
};


#endif //RESPONSE_H
