//
// Created by Mher Tolpin on 27/09/2024.
//

#ifndef SESSION_H
#define SESSION_H

#include <boost/asio.hpp>
#include <string>
#include <vector>
#include "crypto_wrapper/RSAWrapper.h"
#include "me.h"
#include "transfer.h"
#include "response.h"
#include "request.h"

using boost::asio::ip::tcp;

class session {
private:
    bool is_authenticated = false;
    std::vector<char> client_id;
    std::vector<char> aes_key;

    RSAPrivateWrapper* rsapriv = nullptr;
    std::vector<char> pub_key;

    me me_file;
    transfer transfer_file;

    int file_retransmission_counter = 0;

    static std::vector<char> recv(tcp::socket& sock, int size);

    static void send(tcp::socket& sock, const std::vector<char> &payload);

    // communicate
    void login_or_register(tcp::socket &sock);
    void send_pubkey_and_fetch_aes_key(tcp::socket &sock);
    void encrypt_and_send_file(tcp::socket &sock);
    void receive_and_check_crc(tcp::socket &sock, unsigned long crc);

    // encrytion stuff
    void generate_or_load_rsa();
    void decrypt_aes_key();

    // other stuff
    void serialize_cache_file();

    base_response* send_and_get_resp(tcp::socket &sock, base_request* req);

public:
    session ();
    void communicate();

};



#endif //SESSION_H
