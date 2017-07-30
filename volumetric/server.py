import argparse
import os

import cherrypy
from cherrypy.lib.static import serve_file

import volumetric.api

basedir = os.path.dirname(os.path.dirname(__file__))


class VolumetricServer(object):
    def __init__(self, arguments):
        self.debug = arguments.debug
        self.ssl = arguments.ssl
        self.port = arguments.port
        self.thread_pool_size = 10  # arguments.thread_pool_size or 100
        self.log_location = arguments.log
        self.server = None
        self.api = volumetric.api.Api()

    @classmethod
    def get_argument_parser(cls):
        parser = argparse.ArgumentParser()
        parser.add_argument("-d", "--debug", action = "store_true", help = "Enable debugging information",
                            default = False)
        parser.add_argument("-s", "--ssl", action = "store_true", help = "Enable SSL for the server", default = False)
        parser.add_argument("-p", "--port", metavar = "PORT", type = int, help = "Port on which the server will run",
                            default = 8000)
        parser.add_argument("-l", "--log", default = None, help = "Log file location")
        return parser

    def run(self):
        configuration = {'server.socket_port': self.port,
                         'server.thread_pool': self.thread_pool_size,
                         'tools.sessions.locking': 'explicit',
                         'tools.sessions.on': True}
        if not self.debug:
            configuration.update({'environment': 'production'})

        cherrypy.config.update(configuration)

        site_config = {'/': {},
                       '/resources': {'tools.staticdir.on': True,
                                      'tools.staticdir.dir': os.path.join(
                                          os.path.dirname(os.path.dirname(__file__)), 'resources')}}

        cherrypy.quickstart(self, '/', site_config)

        if self.ssl:
            cherrypy.server.ssl_certificate = "cert.pem"
            cherrypy.server.ssl_private_key = "privkey.pem"
            cherrypy.server.ssl_certificate_chain = "certchain.pem"
            cherrypy.server.ssl_module = 'builtin'

    @cherrypy.expose
    def index(self):
        return serve_file(os.path.join(basedir, 'volumetric', 'index.html'))
