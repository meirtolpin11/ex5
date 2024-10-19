import struct
from enum import Enum


VERSION = 3


class ResponseType(Enum):
    REGISTRATION_SUCCESS = 1600
    REGISTRATION_FAILURE = 1601
    PUBKEY_RECEIVED = 1602
    FILE_RECEIVED = 1603
    ACK = 1604
    LOGIN_SUCCESS = 1605
    LOGIN_FAILURE = 1606
    GENERAL_ERROR = 1607


class Response:
    def _serialize_header(self, payload_size):
        header = struct.pack(
            "<BHI", VERSION, self._code.value, payload_size
        )
        return header

    def _serialize_payload(self):
        ...

    def serialize(self):
        payload = self._serialize_payload()
        return self._serialize_header(len(payload)) + payload


class RegistrationSuccessResponse(Response):
    _code = ResponseType.REGISTRATION_SUCCESS

    def __init__(self, client_id):
        super().__init__()
        self._client_id = client_id

    def _serialize_payload(self):
        return struct.pack("<16s", self._client_id.encode())


class RegistrationFailureResponse(RegistrationSuccessResponse):
    _code = ResponseType.REGISTRATION_FAILURE


class PubkeyReceivedResponse(Response):
    _code = ResponseType.PUBKEY_RECEIVED

    def __init__(self, client_id, aes_key):
        super().__init__()
        self._client_id = client_id
        self._aes_key = aes_key

    def _serialize_payload(self):
        return struct.pack("<16s", self._client_id.encode("ascii")) + self._aes_key


class FileReceivedWithCorrectCRC(Response):
    _code = ResponseType.FILE_RECEIVED

    def __init__(self, client_id, content_size, file_name, checksum):
        super().__init__()
        self._client_id = client_id
        self._content_size = content_size
        self._file_name = file_name
        self._checksum = checksum

    def _serialize_payload(self):
        return struct.pack("<16sI255sI", self._client_id.encode("ascii"), self._content_size,
                           self._file_name.encode("ascii"), self._checksum)


class AckResponse(Response):
    _code = ResponseType.ACK

    def __init__(self, client_id):
        super().__init__()
        self._client_id = client_id

    def _serialize_payload(self):
        return struct.pack("<16s", self._client_id.encode("ascii"))


class LoginSuccessResponse(Response):
    _code = ResponseType.LOGIN_SUCCESS

    def __init__(self, client_id, aes_key):
        super().__init__()
        self._client_id = client_id
        self._aes_key = aes_key

    def _serialize_payload(self):
        return struct.pack("<16s", self._client_id.encode("ascii")) + self._aes_key


class LoginFailureResponse(LoginSuccessResponse):
    _code = ResponseType.LOGIN_FAILURE

    def __init__(self, client_id):
        super().__init__(client_id, "".encode())


class GeneralErrorResponse(Response):
    _code = ResponseType.GENERAL_ERROR

    def _serialize_payload(self):
        return "".encode("ascii")
