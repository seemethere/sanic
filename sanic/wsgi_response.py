class HttpResponse(object):
    __slots__ = [
        'header_bytes',
        'headers_sent'
    ]

    def __init__(self, status, transport):
        self.headers = []
        self.status = status
        self.content_type = b'type/plain'
        self.content_length = 0
        self.headers_sent = False
        self.transport = transport
        self.bytes_remaining = 0

    def header_bytes(
            self,
            server_protocol: bytes,
            keep_alive: bool=False,
            timeout: int=0):
        header_bytes = b''
        if keep_alive is True and timeout is not 0:
            header_bytes += b'Keep-Alive: timeout=%d\r\n' % timeout
        for name, value in self.headers:
            # Headers should have already been encoded in start_response
            header_bytes += b'%b: %b\r\n' % (name, value)
        return (
            b'%b %b\r\n'
            b'%b'
        ) % (
            server_protocol,
            self.status,
            header_bytes
        )

    def write_headers(self, keep_alive: bool=False, timeout: int=0):
        self.transport.write(self.header_bytes(keep_alive, timeout))
        self.headers_sent = True


    def to_html(
            self,
            body: bytes,
            server_protocol: bytes,
            keep_alive: bool=False,
            timeout: int=0):
        timeout_header = b''
        if keep_alive is True and timeout is not 0:
            timeout_header = b'Keep-Alive: timeout=%d\r\n' % timeout
        headers = b''
        if len(self.headers) != 0:
            for name, value in self.headers:
                # Headers should have already been encoded in start_response
                headers += b'%b: %b\r\n' % (name, value)
        return (
            b'%b %b\r\n'
            b'Content-Type: %b\r\n'
            b'Content-Length: %d\r\n'
            b'Connection: %b\r\n'
            b'%b%b\r\n'
            b'%b'
        ) % (
            server_protocol,
            self.status,
            self.content_type,
            len(body),
            b'keep-alive' if keep_alive else b'close',
            timeout_header,
            headers,
            body
        )
