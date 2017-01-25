from .exceptions import ServerError


class HttpResponse(object):
    __slots__ = [
        'headers',
        'status',
        'server_protocol',
        'bytes_remaining',
        'headers_sent',
        'transport',
        'bytes_remaining',
    ]

    def __init__(self, headers, status, server_protocol, transport):
        self.headers = headers
        self.status = status
        self.server_protocol = server_protocol
        self.bytes_remaining = None
        self.headers_sent = False
        self.transport = transport

    @property
    def header_bytes(self):
        header_bytes = b'%b %b\r\n' % (self.server_protocol, self.status)
        for name, value in self.headers:
            # Headers should have already been encoded in start_response
            header_bytes += b'%b: %b\r\n' % (name, value)
            if name == b'content-length':
                self.bytes_remaining = int(value)
        header_bytes += b'\r\n'
        return header_bytes

    def write(self, chunk):
        if not self.headers_sent:
            self.transport.write(self.header_bytes)
            self.headers_sent = True

        chunk_length = len(chunk)
        if (self.bytes_remaining is not None and
                chunk_length > self.bytes_remaining):
            raise ServerError(
                'Application wanted more bytes than allocated for')

        self.transport.write(chunk)

        if self.bytes_remaining is not None:
            self.bytes_remaining -= chunk_length
            if self.bytes_remaining < 0:
                raise ServerError(
                    'Response body exceeds declared Content-Length')

