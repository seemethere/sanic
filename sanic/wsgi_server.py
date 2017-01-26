import asyncio
import functools
import io
import os
import signal
import sys
import traceback
from inspect import isawaitable

from httptools import HttpRequestParser, HttpParserError, parse_url
import uvloop

from .log import log
from .wsgi_response import HttpResponse

DEFAULT_ENCODING = 'utf-8'


def bytes_to_str(byte_string, encoding=DEFAULT_ENCODING, lower=False):
    ret_str = byte_string
    if hasattr(byte_string, 'decode'):
        ret_str = byte_string.decode(encoding)
    if lower:
        ret_str = ret_str.casefold()
    return ret_str


def str_to_bytes(native_string, encoding=DEFAULT_ENCODING, lower=False):
    ret_str = native_string
    if hasattr(native_string, 'encode'):
        ret_str = native_string.encode(encoding)
    if lower:
        ret_str = ret_str.lower()
    return ret_str


class ServerDefaults:
    HOST = '0.0.0.0'
    PORT = 8000
    SERVER_PROTOCOL = b'HTTP/1.1'
    MAX_REQUEST_SIZE = 100000
    URL_SCHEME = 'http'
    TIMEOUT = 60


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
    ERROR = 'wsgi.errors'
    MULTITHREAD = 'wsgi.multithread'
    MULTIPROCESS = 'wsgi.multiprocess'
    RUN_ONCE = 'wsgi.run_once'
    SANIC_LOOP = 'sanic.loop'


class WSGIHttpProtocol(asyncio.Protocol):
    __slots__ = [
        'loop',
        'application',
        'base_env',
        'port',
        'current_request_size',
        'max_request_size',
        'request_body',
        'parser',
        'timeout',
        'env',
        'response',
        'profile'
    ]
    connections = set()

    def __init__(
            self, loop, application, base_env,
            max_request_size=ServerDefaults.MAX_REQUEST_SIZE,
            port=ServerDefaults.PORT,
            timeout=ServerDefaults.TIMEOUT):
        self.loop = loop
        self.application = application
        self.base_env = base_env
        self.port = port
        # Request variables
        self.current_request_size = 0
        self.max_request_size = max_request_size
        self.request_body = b''
        self.parser = None
        self.timeout = timeout
        self.transport = None
        self.env = {}
        # Empty response object at first
        self.response = None

    @classmethod
    def register_connection(cls, connection):
        cls.connections.add(connection)

    @classmethod
    def unregister_connection(cls, connection):
        cls.connections.discard(connection)

    # Connections
    def connection_made(self, transport):
        # log.debug('Connection Made!')
        self.transport = transport
        self.register_connection(self)

    def connection_lost(self, exc):
        self.transport.close()
        self.unregister_connection(self)

    # Data
    def data_received(self, data):
        self.current_request_size += len(data)
        if self.current_request_size > self.max_request_size:
            # TODO: Write error handling for payload too large
            pass
        if self.parser is None:
            self.parser = HttpRequestParser(self)
        # if not hasattr(self, 'profile'):
        #     import cProfile
        #     self.profile = cProfile.Profile()
        #     self.profile.enable()
        try:
            self.parser.feed_data(data)
        except HttpParserError:
            pass
            # TODO: Handle error

    def on_url(self, url):
        try:
            parsed_url = parse_url(url)
            self.env[WSGIFields.PATH_INFO] = bytes_to_str(parsed_url.path)
            self.env[WSGIFields.QUERY_STRING] = bytes_to_str(
                parsed_url.query or b'')
        except:
            log.error(traceback.format_exc())

    def on_header(self, name, value):
        try:
            translated_name = bytes_to_str(name).replace("-", "_").upper()
            if name == b'Content-Length':
                if int(value) > self.max_request_size:
                    ...
                    # TODO: Handle Error, payload too large
                self.env[translated_name] = bytes_to_str(value)
            if name == b'Content-Type':
                self.env[translated_name] = bytes_to_str(value)
            else:
                self.env['HTTP_' + translated_name] = bytes_to_str(value)
        except:
            log.error(traceback.format_exc())

    def on_body(self, body):
        try:
            self.request_body += body
        except:
            log.error(traceback.format_exc())

    def start_response(self, status, headers, exc_info=None):
        def convert_name_and_value(header):
            return (str_to_bytes(header[0], lower=True),
                    str_to_bytes(header[1]))

        try:
            self.response = HttpResponse(
                map(convert_name_and_value, headers),
                str_to_bytes(status),
                self.base_env[WSGIFields.SERVER_PROTOCOL],
                self.transport
            )
            return self.response.write
        except:
            log.error(traceback.format_exc())

    async def write_response(self):
        try:
            self.env[WSGIFields.ERROR] = sys.stderr
            self.env[WSGIFields.REQUEST_METHOD] = bytes_to_str(
                self.parser.get_method())
            self.env[WSGIFields.INPUT] = io.BytesIO(self.request_body)
            self.env.update(self.base_env)
            try:
                chunks = self.application(self.env, self.start_response)
                import pudb; pu.db
                if isawaitable(chunks):
                    try:
                        chunks = await chunks
                    except StopIteration:
                        pass
                for chunk in chunks:
                    self.response.write(chunk)
            except:
                log.error(traceback.format_exc())
            finally:
                self.current_request_size = 0
                self.parser = None
                self.response = None
                self.env = {}
        except:
            log.error(traceback.format_exc())

    def on_message_complete(self):
        # self.profile.disable()
        # self.profile.print_stats()
        self.loop.create_task(self.write_response())


def serve(
        application,
        host=ServerDefaults.HOST, port=ServerDefaults.PORT,
        url_scheme=ServerDefaults.URL_SCHEME,
        server_protocol=ServerDefaults.SERVER_PROTOCOL):
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = uvloop.new_event_loop()
    # loop.set_debug(True)

    base_env = {
        WSGIFields.SERVER_NAME: host,
        WSGIFields.SERVER_PORT: port,
        WSGIFields.SERVER_PROTOCOL: server_protocol,
        WSGIFields.URL_SCHEME: url_scheme,
        WSGIFields.SANIC_LOOP: loop,
        **os.environ
    }
    protocol_factory = functools.partial(
        WSGIHttpProtocol,
        loop=loop,
        application=application,
        base_env=base_env
    )
    server = loop.create_server(
        protocol_factory=protocol_factory,
        host=host,
        port=port,
    )

    log.info('Starting server @ {}://{}:{} with pid {}'.format(
        url_scheme, host, port, os.getpid()))
    loop.run_until_complete(server)
    loop.add_signal_handler(signal.SIGINT, loop.stop)
    loop.add_signal_handler(signal.SIGTERM, loop.stop)
    try:
        loop.run_forever()
    finally:
        log.info('Stopping server @ {}:{} with pid {}'.format(
            host, port, os.getpid()))
