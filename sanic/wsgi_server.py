import asyncio
import cProfile
import functools
import io
import os
import signal
import sys
import traceback

from httptools import HttpRequestParser, HttpParserError, parse_url
import uvloop

from .log import log
from .wsgi_response import HttpResponse

DEFAULT_ENCODING = 'ISO-8859-1'


@functools.lru_cache()
def bytes_to_native(byte_string, encoding=DEFAULT_ENCODING):
    return byte_string.decode(encoding)


@functools.lru_cache()
def native_to_bytes(native_string, encoding=DEFAULT_ENCODING):
    return native_string.encode(encoding)


def check_if_bytes(*objs):
    try:
        for obj in objs:
            obj.decode
    except AttributeError:
        raise TypeError('Type must be bytes found: {}'.format(type(obj)))


class ServerDefaults:
    HOST = '0.0.0.0'
    PORT = 8080
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


class WSGIHttpProtocol(asyncio.Protocol):
    server_protocol_bytes = b''
    connections = set()

    def __init__(
            self, loop, application, base_env,
            max_request_size=ServerDefaults.MAX_REQUEST_SIZE,
            response_type=HttpResponse, port=ServerDefaults.PORT,
            timeout=ServerDefaults.TIMEOUT):
        self.loop = loop
        self.application = application
        self.base_env = base_env
        self.port = port
        # Request variables
        self.current_request_size = 0
        self.max_request_size = max_request_size
        self.parser = None
        self.timeout = timeout
        self.env = self.base_env.copy()
        # Empty response object at first
        self.response = None
        self.response_type = response_type
        self.bytes_remaining = None

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
        # log.debug('Connection Made!')
        self.transport = transport
        self.register_connection(self)
        # self.profile.enable()

    def connection_lost(self, exc):
        self.transport.close()
        self.deregister_connection(self)

    # Data
    def data_received(self, data):
        self.current_request_size += len(data)
        if not self.env.get(WSGIFields.INPUT):
            self.env[WSGIFields.INPUT] = io.BytesIO()
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
        try:
            parsed_url = parse_url(url)
            self.env[WSGIFields.PATH_INFO] = parsed_url.path.decode('latin1')
            self.env[WSGIFields.QUERY_STRING] = parsed_url.query or ''
        except:
            log.error(traceback.format_exc())

    def on_header(self, name, value):
        translated_name = bytes_to_native(
            name,
            encoding='latin1'
        ).casefold().replace("-", "_")
        if (translated_name == 'content_length' and
                int(value) > self.max_request_size):
            ...
            # TODO: Handle Error, payload too large
        if translated_name in {'content_length' or 'content_type'}:
            self.env[translated_name] = bytes_to_native(
                value, encoding='latin1'
            )
        else:
            self.env['HTTP_' + translated_name] = bytes_to_native(value)

    def on_headers_complete(self):
        pass
        # remote_addr = self.transport.get_extra_info('peername')
        # if remote_addr:
        #     self.env['HTTP_REMOTE_ADDR'] = '%s:%s' % remote_addr

    def on_body(self, body):
        self.env[WSGIFields.INPUT].write(body)

    def start_response(self, status, headers, exc_info=None):
        try:
            status = native_to_bytes(status)
        except AttributeError:
            pass

        self.response = HttpResponse(
            status,
            self.env[WSGIFields.SERVER_PROTOCOL],
            self.transport
        )

        for key, value in headers:
            try:
                key = native_to_bytes(key)
            except AttributeError:
                pass
            try:
                value = native_to_bytes(value)
            except AttributeError:
                pass
            self.response.headers.append((key, value))
            if key.lower() == b'content-length':
                self.response.set_content_length(int(value))
        return self.response.write

    def on_message_complete(self):
        self.env[WSGIFields.ERROR] = sys.stderr
        self.env[WSGIFields.REQUEST_METHOD] = bytes_to_native(
            self.parser.get_method())
        self.env[WSGIFields.INPUT].seek(0)
        try:
            # TODO: Figure out why POST requests aren't working
            for chunk in self.application(self.env, self.start_response):
                self.response.write(chunk)
        except Exception as e:
            log.error(traceback.format_exc())
        finally:
            self.env[WSGIFields.INPUT] = io.BytesIO()
            # self.profile.disable()
            # self.profile.print_stats()


def serve(
        application,
        host=ServerDefaults.HOST, port=ServerDefaults.PORT,
        url_scheme=ServerDefaults.URL_SCHEME,
        server_protocol=ServerDefaults.SERVER_PROTOCOL):
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    loop.set_debug(True)

    server = loop.create_server(
        protocol_factory=functools.partial(
            WSGIHttpProtocol,
            loop=loop,
            application=application,
            base_env={
                WSGIFields.SERVER_NAME: host,
                WSGIFields.SERVER_PORT: port,
                WSGIFields.SERVER_PROTOCOL: server_protocol,
                WSGIFields.URL_SCHEME: url_scheme,
                **os.environ
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
