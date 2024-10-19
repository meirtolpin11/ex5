import struct
from enum import Enum


class RequestType(Enum):
    REGISTER = 825
    PUBLIC_KEY = 826
    LOGIN = 827
    UPLOAD_FILE = 828

    CORRECT_CRC = 900
    UNEXPECTED_CRC = 901
    UNEXPECTED_CRC_FOURTH_TIME = 902


class ParsedRequest(object):
    ...


class RegistrationRequest(ParsedRequest):
    PAYLOAD_FORMAT = '<255s'

    def __init__(self, payload):
        self.payload = payload
        unpacked = struct.unpack(RegistrationRequest.PAYLOAD_FORMAT, self.payload)
        self.username = unpacked[0].decode('ascii').rstrip('\x00')

    def get_username(self):
        return self.username


class PublicKeyRequest(ParsedRequest):
    PAYLOAD_FORMAT = '<255s160s'

    def __init__(self, payload):
        self.payload = payload
        unpacked = struct.unpack(PublicKeyRequest.PAYLOAD_FORMAT, self.payload)
        self.username = unpacked[0]
        self.public_key = unpacked[1]

    def get_username(self):
        return self.username

    def get_public_key(self):
        return self.public_key


class LoginRequest(RegistrationRequest):
    ...


class UploadFileRequest(ParsedRequest):
    PAYLOAD_FORMAT = '<IIHH255s'

    def __init__(self, payload):
        self.payload = payload
        upload_file_header = self.payload[0: struct.calcsize(UploadFileRequest.PAYLOAD_FORMAT)]
        unpacked = struct.unpack(UploadFileRequest.PAYLOAD_FORMAT, upload_file_header)
        self.content_size = unpacked[0]
        self.orig_file_size = unpacked[1]
        self.packet_number = unpacked[2]
        self.total_packets = unpacked[3]
        self.file_name = unpacked[4].decode('ascii').rstrip('\x00')
        self.encrypted_content = self.payload[struct.calcsize(UploadFileRequest.PAYLOAD_FORMAT):]

    def get_content_size(self):
        return self.content_size

    def get_orig_file_size(self):
        return self.orig_file_size

    def get_packet_number(self):
        return self.packet_number

    def get_total_packets(self):
        return self.total_packets

    def is_first_part(self):
        return self.packet_number == 1

    def is_final_part(self):
        return self.packet_number == self.total_packets

    def get_file_name(self):
        return self.file_name

    def get_encrypted_content(self):
        return self.encrypted_content


class CorrectCRCRequest(ParsedRequest):
    ...


class UnexpectedCRCRequest(ParsedRequest):
    ...


class UnexpectedCRCForthTimeRequest(ParsedRequest):
    ...


class Request:
    HEADER_FORMAT_STR = '<16sBHI'
    EXPECTED_SIZE = struct.calcsize(HEADER_FORMAT_STR)

    def __init__(self, data):
        self.payload = ""
        self.__parse_header(data)

    def __parse_header(self, data):
        if len(data) < Request.EXPECTED_SIZE:
            raise Exception("Not enough data to parse the header")

        header_data = data[0:Request.EXPECTED_SIZE]
        unpacked = struct.unpack(Request.HEADER_FORMAT_STR, header_data)

        self.client_id = unpacked[0].decode('ascii').rstrip('\x00')
        self.version = unpacked[1]
        self.code = unpacked[2]
        self.payload_size = unpacked[3]

    def get_payload_size(self):
        return self.payload_size

    def get_code(self):
        return self.code

    def get_parsed_request(self, payload):
        self.payload = payload
        if self.code == RequestType.REGISTER.value:
            return RegistrationRequest(self.payload)
        elif self.code == RequestType.PUBLIC_KEY.value:
            return PublicKeyRequest(self.payload)
        elif self.code == RequestType.LOGIN.value:
            return LoginRequest(self.payload)
        elif self.code == RequestType.UPLOAD_FILE.value:
            return UploadFileRequest(self.payload)
        elif self.code == RequestType.CORRECT_CRC.value:
            return CorrectCRCRequest()
        elif self.code == RequestType.UNEXPECTED_CRC.value:
            return UnexpectedCRCRequest()
        elif self.code == RequestType.UNEXPECTED_CRC_FOURTH_TIME.value:
            return UnexpectedCRCForthTimeRequest()

