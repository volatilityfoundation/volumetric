# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#


import argparse
import os

import cherrypy
from cherrypy.lib.static import serve_file

import volumetric.api

basedir = os.path.dirname(os.path.dirname(__file__))


class VolumetricServer(object):

    def __init__(self, arguments):
        self.quiet = arguments.quiet
        self.ssl = arguments.ssl
        self.port = arguments.port
        self.thread_pool_size = 10  # arguments.thread_pool_size or 100
        self.server = None
        self.api = volumetric.api.Api()

    @classmethod
    def get_argument_parser(cls):
        parser = argparse.ArgumentParser()
        parser.add_argument("-q", "--quiet", action = "store_true", help = "Disable debugging output", default = False)
        parser.add_argument("-s", "--ssl", action = "store_true", help = "Enable SSL for the server", default = False)
        parser.add_argument(
            "-p", "--port", metavar = "PORT", type = int, help = "Port on which the server will run", default = 8000)
        return parser

    def run(self):
        # TODO: Convert to gunicorn or something with better asynchronicity

        configuration = {
            'server.socket_port': self.port,
            'server.thread_pool': self.thread_pool_size,
            'tools.sessions.locking': 'explicit',
            'tools.sessions.on': True
        }
        if self.quiet:
            configuration.update({'environment': 'production'})

        cherrypy.config.update(configuration)

        site_config = {
            '/': {},
            '/resources': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': os.path.join(os.path.dirname(os.path.dirname(__file__)), 'resources')
            }
        }

        cherrypy.quickstart(self, '/', site_config)

        if self.ssl:
            cherrypy.server.ssl_certificate = "cert.pem"
            cherrypy.server.ssl_private_key = "privkey.pem"
            cherrypy.server.ssl_certificate_chain = "certchain.pem"
            cherrypy.server.ssl_module = 'builtin'

    @cherrypy.expose
    def index(self):
        return serve_file(os.path.join(basedir, 'volumetric', 'index.html'))
