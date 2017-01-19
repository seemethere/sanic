import asyncio
import functools
import os
import signal
import traceback
from io import BytesIO

from httptools import HttpRequestParser, HttpParserError, parse_url
import uvloop

from .log import log
from .wsgi_response import HttpResponse

DEFAULT_ENCODING = 'ISO-8859-1'


def bytes_to_native(byte_string, encoding=DEFAULT_ENCODING):
    return byte_string.decode(encoding)


class ServerDefaults:
    HOST = '0.0.0.0'
    PORT = 8080
    SERVER_PROTOCOL = 'HTTP/1.1'
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
    ERROR_STREAM = 'wsgi.errors'
    MULTITHREAD = 'wsgi.multithread'
    MULTIPROCESS = 'wsgi.multiprocess'
    RUN_ONCE = 'wsgi.run_once'


class WSGIHttpProtocol(asyncio.Protocol):
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
        self.env = self.fresh_env()
        # Empty response object at first
        self.response = None
        self.response_type = response_type

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
        log.debug('MESSAGE COMPLETE ATTEMPTING TO WRITE')
        self.env[WSGIFields.ERROR_STREAM] = BytesIO()
        try:
            body = self.application(self.env, self.start_response)
            try:
                body.decode
            except AttributeError:
                body = body.encode(DEFAULT_ENCODING)
            log.debug('GETTING TO WRITE TO THE SERVER!')
            self.transport.write(
                self.response.to_html(
                    body,
                    self.server_protocol,
                    (self.parser.should_keep_alive() and not self.signal.stopped),
                    self.timeout
                )
            )
            log.debug('WROTE TO THE SERVER!')
        except:
            log.debug(traceback.format_exception())
        finally:
            self.transport.flush()
            self.transport.close()

        # TODO: Add things to write out response for WSGI
        # self.transport.write()
        # self.transport.close()

    def start_response(self, status, headers, exc_info=None):
        try:
            self.response = HttpResponse(status.encode(DEFAULT_ENCODING))
        except AttributeError:
            raise TypeError('Status must be of type str')
        for key, value in headers:
            try:
                encoded_key = key.encode(DEFAULT_ENCODING)
                encoded_value = value.encode(DEFAULT_ENCODING)
            except AttributeError:
                # Handle places where the the key, value isn't a str
                key, value = str(key), str(value)
                encoded_key = key.encode(DEFAULT_ENCODING)
                encoded_value = value.encode(DEFAULT_ENCODING)
            except:
                # TODO: Add unexpected error handling here
                pass
            self.response.headers.append((encoded_key, encoded_value))
            if key.casefold() == 'content-length':
                self.response.content_length = int(value)
            elif key.casefold() == 'content-type':
                self.response.content = encoded_value
        return self.write

    def write(self, chunk):
        if self.response is None:
            # TODO: Replace with custom exception
            raise Exception('WSGI write called before start_response')
        pass


def serve(
        application,
        host=ServerDefaults.HOST, port=ServerDefaults.PORT,
        url_scheme=ServerDefaults.URL_SCHEME,
        server_protocol=ServerDefaults.SERVER_PROTOCOL):
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
