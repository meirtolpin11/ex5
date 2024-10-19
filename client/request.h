//
// Created by Mher Tolpin on 26/09/2024.
//

#ifndef REQUEST_H
#define REQUEST_H

#include <vector>

constexpr uint CLIENT_VERSION = 3;

enum request_type {
    REGISTER = 825,
    PUBLIC_KEY = 826,
    LOGIN = 827,
    UPLOAD_FILE = 828,
    CORRECT_CRC = 900,
    UNEXPECTED_CRC = 901,
    UNEXPECTED_CRC_FORTH_TIME = 902
};


class base_request {
protected:
    request_type code;
    uint version = CLIENT_VERSION;
    std::vector<char> client_id;

public:
    virtual ~base_request() = default;

    explicit base_request (const std::vector<char> &client_id, request_type req_code) : code(req_code)  {
        this->client_id = client_id;
    }

    std::vector<char> serialize();
    virtual std::vector<char> serialize_payload() = 0;

    // Method to get the integer value of code
    int get_code() const {
        return static_cast<int>(code);
    }
};

class register_request : public base_request {
private:
    std::vector<char> user_name;
public:
    explicit register_request(const std::vector<char> &user_name) : base_request(user_name, REGISTER) {
        this->user_name = user_name;
    }
    explicit register_request(const std::vector<char> &user_name, const std::vector<char> &client_id, request_type req_code) :
        base_request(client_id, req_code) {
        this->user_name = user_name;
    }
    std::vector<char> serialize_payload() override;
};


class public_key_upload_request final : public base_request {
private:
    std::vector<char> public_key;
public:
    explicit public_key_upload_request(const std::vector<char> &client_id,
        const std::vector<char> &public_key) : base_request(client_id, PUBLIC_KEY) {
        this->public_key = public_key;
    }
    std::vector<char> serialize_payload() override;
};

class login_request final : public register_request {
public:
    explicit login_request(const std::vector<char> &user_name, const std::vector<char> &client_id) :
    register_request(user_name, client_id, LOGIN) {}
    std::vector<char> serialize_payload() override;
};

class upload_file_request : public base_request {
private:

    uint content_size;
    uint orig_file_size;
    uint packet_number;
    uint total_packets;
    std::vector<char> file_name;
    std::vector<char> content;

public:
    explicit upload_file_request(const std::vector<char> &client_id, const uint content_size, const uint orig_file_size,
        const uint packet_number, const uint total_packets, const std::vector<char> &file_name,
        const std::vector<char> &content) : base_request(client_id, UPLOAD_FILE) {
        // after encryption
        this->content = content;
        this->content_size = content_size;
        this->orig_file_size = orig_file_size;
        this->packet_number = packet_number;
        this->total_packets = total_packets;
        this->file_name = file_name;
    }
    std::vector<char> serialize_payload() override;
};

class correct_crc_request : public base_request {
private:
    std::vector<char> file_name;
public:
    explicit correct_crc_request (const std::vector<char> &client_id,
        const std::vector<char> &file_name) : base_request(client_id, CORRECT_CRC) {
        this->file_name = file_name;
    }
    explicit correct_crc_request (const std::vector<char> &client_id,
        const std::vector<char> &file_name, const request_type req_code) : base_request(client_id, req_code) {
        this->file_name = file_name;
    }
    std::vector<char> serialize_payload() override;
};

class unexpected_crc_request : public correct_crc_request {
public:
    explicit unexpected_crc_request (const std::vector<char> &client_id,
        const std::vector<char> &file_name) : correct_crc_request(client_id, file_name, UNEXPECTED_CRC) {}
    explicit unexpected_crc_request (const std::vector<char> &client_id,
    const std::vector<char> &file_name, const request_type req_code) : correct_crc_request(client_id, file_name, req_code) {}
    std::vector<char> serialize_payload() override;
};


class unexpected_crc_request_fourth_time final : public unexpected_crc_request {
   public:
    explicit unexpected_crc_request_fourth_time(const std::vector<char> &client_id, const std::vector<char> &file_name) :
        unexpected_crc_request(client_id, file_name, UNEXPECTED_CRC_FORTH_TIME) {};
    std::vector<char> serialize_payload() override;
};


#endif //REQUEST_H
