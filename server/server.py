import sys
import socket
import logging
import concurrent.futures
from time import sleep

from request import *
from session import Session
from users import registered_users

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

PORT_FILENAME = 'port.info'
SERVER_VERSION = 3


class Server:
    HOSTNAME = '0.0.0.0'

    def __init__(self):
        self.__session = None
        self.__get_port_from_file()

    def __get_port_from_file(self):
        """
        Parse the port.info file and extract the port number to bind on
        :return: nothing
        """
        self.port = 1256
        try:
            with open(PORT_FILENAME, 'r') as f:
                self.port = int(f.readline())
        except:
            logging.error("Unable to parse port file")

    def handle_connection(self, sock):
        self.__session = Session(sock)

        file_upload_counter = 0

        # 1 time original upload, and 3 retransmissions
        while file_upload_counter < 4:
            req = self.__session.recv_request()

            if isinstance(req, LoginRequest) or isinstance(req, RegistrationRequest):
                logging.info("Received authentication request: %s", req.__class__.__name__)
                self.__session.authenticate(req)
            elif isinstance(req, PublicKeyRequest):
                logging.info("Received public key request: %s", req.__class__.__name__)
                # these function are decorated and will
                # be executed only in case of registration
                # in case it's already registered user we will skip this function
                self.__session.recv_and_parse_pubkey(req)
                self.__session.generate_and_send_aes_key()
            elif isinstance(req, UploadFileRequest):
                logging.info("Received file upload request: %s", req.__class__.__name__)
                file_upload_counter += 1
                # If we want to allow the client upload of multiple files
                # we can add a while True loop here.
                if self.__session.recv_and_parse_file(req):
                    logging.info("File successfully uploaded, or crc was wrong for 4 times, existing")
                    # the file were uploaded successfully or
                    # the crc was wrong for 4 times
                    break

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((Server.HOSTNAME, self.port))

        logging.info(f"Server started on {Server.HOSTNAME}:{self.port}")

        s.listen(5)

        executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)

        while True:
            user_sock, addr = s.accept()
            logging.info("New connection from {}".format(addr))
            # self.handle_connection(user_sock)
            executor.submit(self.handle_connection, user_sock)

        s.close()


s = Server()
s.start()
