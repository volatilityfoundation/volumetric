# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#


import argparse
import logging
import os

import cherrypy
from cherrypy.lib.static import serve_file

import volumetric.api

logging.basicConfig(level=0)

vollog = logging.getLogger("volatility")
vollog.setLevel(0)
vollog.info("Logging started")

basedir = os.path.dirname(os.path.dirname(__file__))


class VolumetricServer(object):
    def __init__(self, arguments):
        self.quiet = arguments.quiet
        self.ssl = arguments.ssl
        self.port = arguments.port
        self.thread_pool_size = 10  # arguments.thread_pool_size or 100
        self.server = None
        self.api = volumetric.api.Api()
        if arguments.log_file:
            self.setup_logging(arguments.log_file)

    def setup_logging(self, filename):
        file_logger = logging.FileHandler(filename)
        file_logger.setLevel(0)
        file_formatter = logging.Formatter(
            datefmt="%y-%m-%d %H:%M:%S",
            fmt="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        )
        file_logger.setFormatter(file_formatter)
        vollog.addHandler(file_logger)

    @classmethod
    def get_argument_parser(cls):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-q",
            "--quiet",
            action="store_true",
            help="Disable debugging output",
            default=False,
        )
        parser.add_argument(
            "-s",
            "--ssl",
            action="store_true",
            help="Enable SSL for the server",
            default=False,
        )
        parser.add_argument(
            "-l",
            "--log-file",
            metavar="FILENAME",
            help="Log volatility output to FILENAME",
            default=None,
        )
        parser.add_argument(
            "-p",
            "--port",
            metavar="PORT",
            type=int,
            help="Port on which the server will run",
            default=8000,
        )
        return parser

    def run(self):
        # TODO: Convert to gunicorn or something with better asynchronicity

        configuration = {
            "log.screen": False,
            "server.socket_port": self.port,
            "server.thread_pool": self.thread_pool_size,
            "tools.sessions.locking": "explicit",
            "tools.sessions.on": True,
        }
        if self.quiet:
            configuration.update({"environment": "production"})

        cherrypy.config.update(configuration)

        site_config = {
            "/": {},
            "/resources": {
                "tools.staticdir.on": True,
                "tools.staticdir.debug": True,
                "tools.staticdir.dir": os.path.join(
                    os.path.dirname(os.path.dirname(__file__)), "resources"
                ),
            },
        }

        cherrypy.quickstart(self, "/", site_config)

        if self.ssl:
            cherrypy.server.ssl_certificate = "cert.pem"
            cherrypy.server.ssl_private_key = "privkey.pem"
            cherrypy.server.ssl_certificate_chain = "certchain.pem"
            cherrypy.server.ssl_module = "builtin"

    @cherrypy.expose
    def index(self):
        return serve_file(os.path.join(basedir, "volumetric", "index.html"))
