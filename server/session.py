import os
import zlib
import random
import logging
from crc import *
from request import *
from response import *
from Crypto.PublicKey import RSA
from users import registered_users
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


HEADER_SIZE = 23
MAX_RETRIES = 4


class Session:
    """
        This class represents user session.
        The flow is as follows -
        1. Authenticate - Login/Register
        2. Receive an RSA key - generate AES key and send it to client
        3. Receive AES encrypted file
    """
    def __init__(self, socket):
        self.__user_name = None
        self.__pubkey = None
        self.socket = socket
        self.__authenticated = False
        self.__client_id = None
        self.__aes_key = None

        # this is a singleton object
        self.__registered_users = registered_users

        # whatever to use has logged in or registered
        self.__registration_workflow = True

    def recv_request(self):
        """
        Receives and parses the message header of fixed size, then receives that message
        payload and returns an object that represents the message.
        :return: An object of type ParsedRequest that represents the received message.
        """
        req_header = self.socket.recv(HEADER_SIZE)
        req = Request(req_header)
        payload = self.socket.recv(req.get_payload_size())
        return req.get_parsed_request(payload)

    def __send_response(self, response):
        self.socket.sendall(response.serialize())

    def authenticate(self, req):
        if isinstance(req, LoginRequest):
            if self.__registered_users.is_user_registered(req.get_username()):
                logging.info("Client successfully logged in: %s", req.get_username())
                self.__authenticated = True
                self.__registration_workflow = False
                self.__user_name = req.get_username()

                self.__client_id = self.__registered_users.get_client_id(req.get_username())
                self.__aes_key = os.urandom(32)

                self.__pubkey = self.__registered_users.get_public_key(req.get_username())

                # send response
                resp = LoginSuccessResponse(self.__client_id, self.__aes_key)
                self.__send_response(resp)
                return True
            else:
                # send response
                logging.info("Client not registered: %s", req.get_username())
                resp = LoginFailureResponse(req.get_username())
                self.__send_response(resp)
                return True

        elif isinstance(req, RegistrationRequest):
            if self.__registered_users.is_user_registered(req.get_username()):
                logging.info("Unable to register client - the client is already registered: %s",
                             req.get_username())
                # send response
                resp = RegistrationFailureResponse(req.get_username())
                self.__send_response(resp)
                return False
            else:
                logging.info("Client successfully registered: %s", req.get_username())
                self.__authenticated = True
                self.__user_name = req.get_username()

                # create a new user
                self.__registered_users.add_new_user(req.get_username())
                self.__client_id = self.__registered_users.get_client_id(req.get_username())

                # send response
                resp = RegistrationSuccessResponse(self.__client_id)
                self.__send_response(resp)
                return True

    def __send_general_error(self):
        """
        Sends a general error message to client
        :return: nothing
        """
        logging.error("Error is detected, sending a general error message")
        resp = GeneralErrorResponse()
        self.__send_response(resp)

    @staticmethod
    def check_authenticated(func):
        """
        Decorator that checks if the user is authenticated.
        In case the user is not authenticated the server will respond with general error message
        :param func: function to decorate
        :return: decorated function
        """
        def wrapper(self, *args, **kwargs):
            if not self.__authenticated:
                self.__send_general_error()
                return False
            else:
                return func(self, *args, **kwargs)
        return wrapper

    @staticmethod
    def only_for_new_user(func):
        def wrapper(self, *args, **kwargs):
            if not self.__registration_workflow:
                return True
            return func(self, *args, **kwargs)
        return wrapper

    @check_authenticated
    @only_for_new_user
    def recv_and_parse_pubkey(self, req):
        """
        Receives and parses the pubkey, if the request is not PubkeyRequest that the server
        will send a general error message to client.
        sets the private pubkey variable to the received pubkey
        :return: nothing
        """
        if not isinstance(req, PublicKeyRequest):
            self.__send_general_error()
            return False

        self.__pubkey = req.get_public_key()
        self.__registered_users.add_user_public_key(self.__user_name, self.__pubkey)
        logging.info("Received client public key")
        return True

    # No need to try this function three time as we are not receiving anything here
    # but just sending a response to the client.
    @check_authenticated
    @only_for_new_user
    def generate_and_send_aes_key(self):
        """
        Generates a random AES key and then sends it to the client (after encryption the key with received
        AES pubkey)
        :return: nothing
        """
        self.__aes_key = os.urandom(32)

        # Encrypt the aes key and send to the client
        rsa_key = RSA.import_key(self.__pubkey)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(self.__aes_key)

        logging.info("Sending generated aes key")
        resp = PubkeyReceivedResponse(self.__client_id, aes_key=encrypted_aes_key)
        self.__send_response(resp)
        return True

    def __send_ack(self):
        """
        Sending the ACK response
        :return: nothing
        """
        resp = AckResponse(self.__client_id)
        self.__send_response(resp)

    @staticmethod
    def is_legitimate_path(user_folder, given_path):

        user_folder = os.path.normpath(user_folder)
        given_path = os.path.normpath(given_path)

        # Check if the given path starts with the user folder
        if not given_path.startswith(user_folder):
            return False

        # Check for path traversal patterns (e.g., ..)
        if '..' in os.path.normpath(given_path).split(os.sep):
            return False

        # Check if the given path is a valid path by trying to resolve it
        resolved_path = os.path.realpath(given_path)
        return resolved_path.startswith(os.path.realpath(user_folder))

    @check_authenticated
    def recv_and_parse_file(self, req):
        """
        Looping and receiving encrypted data chunks, each chunk is decrypted and written to a file
        the loop breaks when we receive that last package
        """
        os.makedirs(self.__client_id, exist_ok=True)

        expected_packet_number = 1

        while True:

            if not isinstance(req, UploadFileRequest):
                self.__send_general_error()
                return False

            file_name = f"{self.__client_id}/{req.get_file_name()}"

            if req.get_packet_number() != expected_packet_number:
                logging.error("Unexpected packet number is received, expecting %s", expected_packet_number)
                self.__send_general_error()

                # give another try without crashing
                continue

            expected_packet_number += 1

            # check that the path is legitimate
            if not Session.is_legitimate_path(f"{self.__client_id}/", file_name):
                logging.error("The given path is not safe to use %s", file_name)
                self.__send_general_error()

                # give another try without crashing
                continue

            if req.is_first_part():
                """
                We allow customers to overwrite files, so to make sure that 
                the new file is not affected buy the old one - we are removing the old one 
                when receiving a new packet that wants to override the packet.
                """
                if os.path.exists(file_name):
                    os.remove(file_name)

            if isinstance(req, UploadFileRequest):
                with open(file_name, 'ab') as f:
                    f.write(self.decrypt_block(req.get_encrypted_content()))

            self.__send_ack()

            if req.is_final_part():
                break

            # wait for the next request in case this was not the final one
            req = self.recv_request()

        checksum = calculate_crc(file_name)
        logging.info("Checksum: %s", checksum)

        resp = FileReceivedWithCorrectCRC(self.__client_id, os.path.getsize(file_name),
                                          file_name, checksum)
        self.__send_response(resp)

        req = self.recv_request()
        if isinstance(req, CorrectCRCRequest):
            logging.info("File uploaded with correct CRC value")
            self.__send_ack()
            return True

        elif isinstance(req, UnexpectedCRCRequest):
            """
            If the CRC was unexpected we will try to receive it again up to MAX_RETRIES times
            """
            logging.error("The received file's CRC was unexpected")
            self.__send_ack()
            return False

        elif isinstance(req, UnexpectedCRCForthTimeRequest):
            logging.error("The received file's CRC was unexpected - already 4 times, giving up...")
            self.__send_ack()
            return True

    @check_authenticated
    def decrypt_block(self, block) -> bytes:
        iv = bytes([0] * 16)
        cipher = AES.new(self.__aes_key, AES.MODE_CBC, iv)

        decrypted_data = cipher.decrypt(block)
        chunk = unpad(decrypted_data, AES.block_size)
        return chunk


