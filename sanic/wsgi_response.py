from .exceptions import ServerError


class HttpResponse(object):

    def __init__(self, status, server_protocol, transport):
        self.headers = []
        self.status = status
        self.server_protocol = server_protocol
        self.content_length = 0
        self.bytes_remaining = 0
        self.headers_sent = False
        self.transport = transport
        self.bytes_remaining = 0

    def set_content_length(self, content_length):
        # I know it's a setter, I know we're in python
        self.content_length = content_length
        self.bytes_remaining = content_length

    @property
    def header_bytes(self):
        header_bytes = b''
        for name, value in self.headers:
            # Headers should have already been encoded in start_response
            header_bytes += b'%b: %b\r\n' % (name, value)
        return (
            b'%b %b\r\n'
            b'%b\r\n'
        ) % (
            self.server_protocol,
            self.status,
            header_bytes
        )

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
                    'Response body exceeds decalred Content-Length')
