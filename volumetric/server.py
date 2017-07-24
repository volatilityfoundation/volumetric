import argparse

import cherrypy


class VolumetricServer(object):
    def __init__(self, arguments):
        self.port = arguments.port
        self.ssl = arguments.ssl
        self.thread_pool_size = 10  # arguments.thread_pool_size or 100
        self.log_location = arguments.log
        self.server = None

    @classmethod
    def get_argument_parser(cls):
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--ssl", action = "store_true", help = "Enable SSL for the server", default = False)
        parser.add_argument("-p", "--port", metavar = "PORT", type = int, help = "Port on which the server will run",
                            default = 8443)
        parser.add_argument("-l", "--log", default = None, help = "Log file location")
        return parser

    def run(self):
        print("Blah")
        configuration = {'server.socket_port': self.port,
                         'server.thread_pool': self.thread_pool_size}
        #  'environment': 'development',

        cherrypy.config.update(configuration)

        cherrypy.quickstart(self)

        if self.ssl:
            cherrypy.server.ssl_certificate = "cert.pem"
            cherrypy.server.ssl_private_key = "privkey.pem"
            cherrypy.server.ssl_certificate_chain = "certchain.pem"
            cherrypy.server.ssl_module = 'builtin'

    @cherrypy.expose
    def index(self):
        return "Hello world!"
