//
// Created by Mher Tolpin on 27/09/2024
//

#include "session.h"
#include "request.h"
#include "response.h"
#include "me.h"
#include "transfer.h"
#include "crc/crc.cpp"
#include "crypto_wrapper/RSAWrapper.h"
#include <boost/asio.hpp>
#include <vector>
#include <fstream>
#include <iostream>
#include "utils.h"
#include "crypto_wrapper/AESWrapper.h"

std::vector<char> session::recv(tcp::socket& sock, const int size) {
    std::vector<char> buffer(size);
    size_t total_bytes_read = 0;

    while (total_bytes_read < size) {
        try {
            // Read into the buffer starting from the total bytes read
            size_t bytes_read = boost::asio::read(sock,
                boost::asio::buffer(buffer.data() + total_bytes_read, size - total_bytes_read));
            total_bytes_read += bytes_read;
        } catch (const boost::system::system_error &e) {
            throw std::runtime_error("Socket read error: " + std::string(e.what()));
        }
    }

    return buffer;
}


void session::send(tcp::socket& sock, const std::vector<char> &payload) {
    if (!sock.is_open()) {
        throw std::runtime_error("Socket is not open before sending upload file request.");
    }
    boost::asio::write(sock, boost::asio::buffer(payload));
}



void session::login_or_register(tcp::socket &sock) {

    if (this->me_file.is_exist()) {
        login_request req(string_to_vector(this->transfer_file.get_user_name()),
            string_to_vector(this->me_file.get_uuid()));

        base_response *resp = this->send_and_get_resp(sock, &req);

        if (resp->get_code() != LOGIN_SUCCESS) {
            if (resp->get_code() != LOGIN_FAILURE) {
                throw std::runtime_error("Expected Login success or failure message but received unexpected code");
            }
            this->me_file.mark_corrupted();
            // Try to register instead of logging in
        } else {
            this->is_authenticated = true;

            // fetch the aes key from the login request
            this->aes_key = ((login_success_response*) resp)->get_enc_aes_key();
            return;
        }

    }

    register_request request(string_to_vector(this->transfer_file.get_user_name()));

    const base_response *resp = this->send_and_get_resp(sock, &request);

    if (resp->get_code() != REGISTRATION_SUCCESS) {
        throw std::runtime_error("Unable to Register to the remote server");
    }

    this->is_authenticated = true;
    this->client_id = resp->get_client_id();
}

void session::send_pubkey_and_fetch_aes_key(tcp::socket &sock) {

    public_key_upload_request pub_rsa_upload_request(this->client_id, this->pub_key);

    base_response* resp = this->send_and_get_resp(sock, &pub_rsa_upload_request);

    if (resp->get_code() != PUBKEY_RECEIVED) {
        return;
    }

    this->aes_key = ((pubkey_received_response*) resp)->get_enc_aes_key();
    this->decrypt_aes_key();
}

void session::generate_or_load_rsa() {

    if (this->me_file.is_exist()) {
        this->rsapriv = new RSAPrivateWrapper(this->me_file.get_priv_key());
    } else {
        this->rsapriv = new RSAPrivateWrapper();
    }

    char pubkeybuff[RSAPublicWrapper::KEYSIZE];
    this->rsapriv->getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);


    // Clear the vector and resize it
    this->pub_key.clear();
    this->pub_key.resize(RSAPublicWrapper::KEYSIZE);


    // Use std::copy to copy the contents
    std::copy_n(pubkeybuff, RSAPublicWrapper::KEYSIZE, this->pub_key.begin());

    // saving the private key to priv.key, I don't know why to do so but it is
    // listed in the requirements in of the MAMAN
    if (std::ofstream me_file("priv.key"); me_file) {
        me_file << Base64Wrapper::encode(this->rsapriv->getPrivateKey());
    }

}

void session::decrypt_aes_key() {
    std::string temp = this->rsapriv->decrypt(this->aes_key.data(), 128);
    this->aes_key.clear();
    this->aes_key.resize(32);
    std::copy(temp.begin(), temp.end(), this->aes_key.begin());
}

void session::serialize_cache_file() {
    me new_me_file(
        this->transfer_file.get_user_name(),
        vector_to_string(this->client_id),
        this->rsapriv->getPrivateKey()
        );

    new_me_file.serialize();
}

/**
 * This function handeles a simple two way communication
 * it receives a request that should be sent, sending it and then waiting for an answer from the server
 * @param sock - the socket to use for the communication
 * @param req - the request to send
 * @return - an object representing the received answer from the server
 */
base_response* session::send_and_get_resp(tcp::socket& sock, base_request *req) {
    int counter = 0;
    std::vector<char> header_buf;
    base_response* resp;

    for(;;) {
        if (counter == 3) {
            throw std::runtime_error( "Received a General Error 3 time - exiting." );
        }

        this->send(sock, req->serialize());

        // Handle the response and parse it
        header_buf = this->recv(sock, 7);
        response_header header(header_buf);

        resp = header.get_child_request_class(this->recv(sock, header.get_payload_size()));

        if (resp->get_code() != GENERAL_ERROR) {
            // in case it's not an error we can continue to the next step
            // in case it's an error we will try to communicate again
            return resp;
        }

        std::cout << "Server responded with an error" << std::endl;
        counter += 1;
    }
}

session::session() {
    // these are configuration files
    // we load them into object in their constructors
    // me file is optional and can be missing
    // while transfer file is always required
    this->me_file = me();

    this->transfer_file = transfer();
}

void session::encrypt_and_send_file(tcp::socket &sock) {
    auto _aes_key = reinterpret_cast<const unsigned char*>(this->aes_key.data());
    AESWrapper aes_wrapper(_aes_key, 32);


    // calculate CRC using provided code
    unsigned long crc = calculate_crc(this->transfer_file.get_file_name());

    // read the file in chunks of 1024 bytes each time
    std::ifstream file(this->transfer_file.get_file_name(), std::ios::binary);
    size_t size = std::filesystem::file_size(this->transfer_file.get_file_name());
    size_t bytes_read;
    char* buffer = new char[1024];
    int packet_counter = 1;

    size_t total_packets = size / 1024;
    if (size % 1024 != 0) {
        total_packets += 1;
    }

    std::vector<char> header_buf;
    std::filesystem::path path = this->transfer_file.get_file_name();

    std::string base_file_name = path.filename().string();

    for(;;) {
        file.read(buffer, 1024);
        bytes_read = file.gcount();

        std::string encrypted_data = aes_wrapper.encrypt(buffer, bytes_read);
        std::vector<char> encrypted_data_vector(encrypted_data.begin(), encrypted_data.end());

        upload_file_request upload_file(this->client_id, encrypted_data.size(), bytes_read, packet_counter, total_packets,
            string_to_vector(base_file_name), encrypted_data_vector);

        packet_counter += 1;

        base_response* resp = this->send_and_get_resp(sock, &upload_file);

        if (resp->get_code() != ACK) {
            throw std::runtime_error("expected ACK response, but unexpected response is received");
        }

        if (bytes_read != 1024) {
            // finished reading the file
            break;
        }
    }

    delete[] buffer;

    this->receive_and_check_crc(sock, crc);
}


void session::receive_and_check_crc(tcp::socket &sock, unsigned long crc) {
    std::cout << "checking uploaded file crc" << std::endl;
    std::vector<char> header_buf;
    base_response* resp;

    // Handle the response
    header_buf = this->recv(sock, 7);
    response_header header(header_buf);
    resp = header.get_child_request_class(this->recv(sock, header.get_payload_size()));

    if (resp->get_code() != FILE_RECEIVED) {
        return;
    }

    auto file_received = (file_received_response*) resp;

    // check CRC
    if(file_received->get_checksum() == crc) {
        std::cout << "The received CRC value is correct" << std::endl;
        correct_crc_request req(this->client_id, string_to_vector(this->transfer_file.get_file_name()));
        base_response* resp = this->send_and_get_resp(sock, &req);
        if (resp->get_code() != ACK) {
            throw std::runtime_error("Expected to receive ACK but unexpected code is received");
        }

    } else {
        std::cout << "The received CRC is not correct" << std::endl;
        // the retransmission counter is used for trying to send a file whose crc was corrupted
        // up to 3 times
        if (this->file_retransmission_counter < 3) {
            std::cout << "trying to retrasmit file (" << this->file_retransmission_counter << "/3)" << std::endl;
            unexpected_crc_request req(this->client_id, string_to_vector(this->transfer_file.get_file_name()));

            base_response* resp = this->send_and_get_resp(sock, &req);
            if (resp->get_code() != ACK) {
                throw std::runtime_error("Excepted to receive ACK but unexpected message is received, aborting");
                return;
            }

            // retramsmit the file
            this->file_retransmission_counter += 1;
            this->encrypt_and_send_file(sock);
            return;
        }

        std::cout << "Reached the retransmission limit - aborting" << std::endl;

        unexpected_crc_request_fourth_time req(this->client_id, string_to_vector(this->transfer_file.get_file_name()));

        base_response* resp = this->send_and_get_resp(sock, &req);
        if (resp->get_code() != ACK) {
            throw std::runtime_error("Expected to receive ACK but unexpected code is received");
        }
    }
}


void session::communicate() {
    std::cout << "Starting communication" << std::endl;
    std::vector<char> payload_buf;

    boost::asio::io_service io_service;
    tcp::socket sock(io_service);

    try {
        sock.connect(tcp::endpoint(
            boost::asio::ip::address::from_string("127.0.0.1"),
            8080
        ));
        std::cout << "Successfully connected to server" << std::endl;
    } catch (const boost::system::system_error& e) {
        throw std::runtime_error("Failed to connect: " + std::string(e.what()));
    }

    std::cout << "Registering or Signing in" << std::endl;
    // login or register to the server (login if me.info exist)
    this->login_or_register(sock);

    // the following step is not needed in case we
    // are re-connecting to the server as we already got
    // the aes key during the login process and now can use
    // it to encrypt and send the encrypted file.
    if(!this->me_file.is_exist()) {
        std::cout << "Looks like we are in registration flow, so exchanging keys" << std::endl;

        // load rsa ley from me.info or create a new one
        this->generate_or_load_rsa();

        // fetch new aes key for file encryption
        this->send_pubkey_and_fetch_aes_key(sock);
    }

    std::cout  << "Uploading encrypted file" << std::endl;
    // encode the file with aes and send it to the server
    this->encrypt_and_send_file(sock);

    // write the me.info string file
    this->serialize_cache_file();

}
