import json

import cherrypy

import volatility
from volatility import framework, plugins
from volatility.framework import constants, interfaces

framework.require_interface_version(0, 0, 0)


class Api(object):
    def __init__(self):
        self.plugins = PluginsApi()


class PluginsApi(object):
    @cherrypy.expose
    def list(self):
        """List the available plugins"""
        volatility.plugins.__path__ = cherrypy.session.get('plugin_dir', '').split(";") + constants.PLUGINS_PATH
        volatility.framework.import_files(volatility.plugins)  # Will not log as console's default level is WARNING

        plugin_list = []
        for plugin in volatility.framework.class_subclasses(interfaces.plugins.PluginInterface):
            plugin_name = plugin.__module__ + "." + plugin.__name__
            if plugin_name.startswith("volatility.plugins."):
                plugin_name = plugin_name[len("volatility.plugins."):]
            plugin_list.append(plugin_name)

        return json.dumps(plugin_list)
