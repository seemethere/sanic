import asyncio
import functools
import os
import signal
from collections import defaultdict
from io import BytesIO
from inspect import isawaitable

from httptools import HttpRequestParser, HttpParserError, parse_url
import uvloop

from .log import log


def bytes_to_native(byte_string, encoding='ISO-8859-1'):
    return byte_string.decode(encoding)


class ServerDefaults:
    HOST = '0.0.0.0'
    PORT = 8080
    SERVER_PROTOCOL = 'HTTP/1.1'
    MAX_REQUEST_SIZE = 100000
    URL_SCHEME = 'http'


class WSGIFields:
    # TODO: Eventually move these to a wsgi_utils package
    SERVER_NAME = 'SERVER_NAME'
    SERVER_PORT = 'SERVER_PORT'
    SERVER_PROTOCOL = 'SERVER_PROTOCOL'
    REQUEST_METHOD = 'REQUEST_METHOD'
    SCRIPT_NAME = 'SCRIPT_NAME'
    PATH_INFO = 'PATH_INFO'
    QUERY_STRING = 'QUERY_STRING'
    CONTENT_TYPE = 'CONTENT_TYPE'
    CONTENT_LENGTH = 'CONTENT_LENGTH'
    VERSION = 'wsgi.version'
    URL_SCHEME = 'wsgi.url_scheme'
    INPUT = 'wsgi.input'
    ERROR_STREAM = 'wsgi.errors'
    MULTITHREAD = 'wsgi.multithread'
    MULTIPROCESS = 'wsgi.multiprocess'
    RUN_ONCE = 'wsgi.run_once'


class WSGIHttpProtocol(asyncio.Protocol):
    connections = set()

    def __init__(
            self, loop, application, base_env,
            max_request_size=ServerDefaults.MAX_REQUEST_SIZE,
            port=ServerDefaults.PORT):
        self.loop = loop
        self.application = application
        self.base_env = base_env
        self.port = port
        # Request variables
        self.current_request_size = 0
        self.max_request_size = max_request_size
        self.parser = None
        self.env = self.fresh_env()

    @classmethod
    def register_connection(cls, connection):
        cls.connections.add(connection)

    @classmethod
    def deregister_connection(cls, connection):
        cls.connections.discard(connection)

    def fresh_env(self):
        """Returns a base environment to work with"""
        return {
            # Add environment variables
            **os.environ,
            # Add base environment variables
            **self.base_env
        }

    # Connections
    def connection_made(self, transport):
        log.debug('Connection Made!')
        self.transport = transport
        self.register_connection(self)

    def connection_lost(self, exc):
        self.transport = None
        self.deregister_connection(self)

    # Data
    def data_received(self, data):
        log.debug('Data recieved!')
        self.current_request_size += len(data)
        if self.current_request_size > self.max_request_size:
            # TODO: Write error handling for payload too large
            pass
        if self.parser is None:
            self.headers = []
            self.parser = HttpRequestParser(self)

        try:
            self.parser.feed_data(data)
        except HttpParserError:
            pass
            # TODO: Handle error

    def on_url(self, url):
        parsed_url = parse_url(url)
        self.env[WSGIFields.PATH_INFO] = parsed_url.path
        self.env[WSGIFields.QUERY_STRING] = parsed_url.query or ''

    def on_header(self, name, value):
        log.info(f'Got a header {name}: {value}')
        translated_name = bytes_to_native(name).upper().replace("-", "_")
        if name == b'Content-Length' and int(value) > self.max_request_size:
            ...
            # TODO: Handle Error, payload too large
        if name in {b'Content-Length' or b'Content-Type'}:
            self.env[translated_name] = bytes_to_native(value)
        else:
            self.env['HTTP_' + translated_name] = bytes_to_native(value)

    def on_headers_complete(self):
        log.info(f'HEADERS FINISHED')
        remote_addr = self.transport.get_extra_info('peername')
        if remote_addr:
            self.env['HTTP_REMOTE_ADDR'] = '%s:%s' % remote_addr

    def on_body(self, body):
        log.info(f'GOT A BODY: {body}')
        try:
            self.env[WSGIFields.INPUT].write(body)
        except KeyError:
            self.env[WSGIFields.INPUT] = BytesIO(body)

    def on_message_complete(self):
        # TODO: Add things to write out response for WSGI
        self.transport.write()
        self.transport.close()



def serve(
        host=ServerDefaults.HOST, port=ServerDefaults.PORT,
        url_scheme=ServerDefaults.URL_SCHEME,
        server_protocol=ServerDefaults.SERVER_PROTOCOL,):
    loop = uvloop.new_event_loop()
    asyncio.set_event_loop(loop)

    server = loop.create_server(
        protocol_factory=functools.partial(
            WSGIHttpProtocol,
            loop=loop,
            application=None,
            base_env={
                WSGIFields.SERVER_NAME: host,
                WSGIFields.SERVER_PORT: port,
                WSGIFields.SERVER_PROTOCOL: server_protocol,
                WSGIFields.URL_SCHEME: url_scheme
            }
        ),
        host=host,
        port=port,
    )

    log.info('Starting server')
    loop.run_until_complete(server)
    loop.add_signal_handler(signal.SIGINT, loop.stop)
    loop.add_signal_handler(signal.SIGTERM, loop.stop)
    try:
        loop.run_forever()
    finally:
        log.info('Exiting...')
