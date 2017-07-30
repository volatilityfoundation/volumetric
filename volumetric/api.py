import hashlib
import json

import cherrypy

import volatility
from volatility import framework, plugins
from volatility.framework import constants, interfaces, contexts, automagic
from volatility.framework.interfaces import configuration

framework.require_interface_version(0, 0, 0)


class Api(object):
    def __init__(self):
        self.plugins = PluginsApi()
        self.automagics = AutomagicApi()


class AutomagicApi(object):
    def _get_automagics(self):
        """Returns an automagic list of all the automagic objects"""
        seen_automagics = set()
        ctx = cherrypy.session.get('context', contexts.Context())
        cherrypy.session['context'] = ctx
        automagics = automagic.available(ctx)
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            yield amagic

    @cherrypy.expose
    def list(self):
        """Returns an automagic list of all the automagic objects"""
        amagics = self._get_automagics()
        result = []
        for amagic in amagics:
            amagic_name = amagic.__class__.__name__
            amagic_item = {'name': amagic_name,
                           'full_name': amagic.__class__.__module__ + "." + amagic_name,
                           'description': amagic.__doc__[:amagic.__doc__.find("\n")],
                           'priority': amagic.priority}
            result.append(amagic_item)
        return json.dumps(result)

    @cherrypy.expose
    def get_requirements(self):
        """Returns the requirements for each automagic"""
        result = []
        for amagic in self._get_automagics():
            for req in amagic.get_requirements():
                if isinstance(req, configuration.InstanceRequirement):
                    automagic_config_path = interfaces.configuration.path_join('automagics', amagic.__class__.__name__)
                    reqment = {'name': automagic_config_path + '.' + req.name,
                               'description': req.description,
                               'default': req.default,
                               'type': req.__class__.__name__,
                               'optional': req.optional,
                               'automagic': amagic.__class__.__name__}
                    result.append(reqment)
        return json.dumps(result)


class PluginsApi(object):
    def get_plugins(self):
        plugin_list = {}
        for plugin in volatility.framework.class_subclasses(interfaces.plugins.PluginInterface):
            plugin_name = plugin.__module__ + "." + plugin.__name__
            if plugin_name.startswith("volatility.plugins."):
                plugin_name = plugin_name[len("volatility.plugins."):]
            plugin_list[plugin_name] = plugin
        return plugin_list

    @cherrypy.expose
    def list(self):
        """List the available plugins"""
        volatility.plugins.__path__ = cherrypy.session.get('plugin_dir', '').split(";") + constants.PLUGINS_PATH
        volatility.framework.import_files(volatility.plugins)  # Will not log as console's default level is WARNING
        plugin_list = self.get_plugins()

        return json.dumps([name for name in plugin_list])

    @cherrypy.expose
    def get_requirements(self, plugin_name):
        """Returns a JSON object containing requirements"""
        plugin_list = self.get_plugins()
        plugin = plugin_list[plugin_name]
        plugin_config_path = interfaces.configuration.path_join('plugins', plugin.__name__)
        reqs = []
        for req in plugin.get_requirements():
            if isinstance(req, configuration.InstanceRequirement):
                reqment = {'name': plugin_config_path + '.' + req.name,
                           'description': req.description,
                           'default': req.default,
                           'optional': req.optional,
                           'type': req.__class__.__name__}
                reqs.append(reqment)
        return json.dumps(reqs)

    @cherrypy.expose
    def create_job(self, plugin, automagics, global_config, plugin_config):
        """Stores the details locally"""
        job = {'plugin': plugin,
               'automagics': json.loads(automagics),
               'global_config': json.loads(global_config),
               'plugin_config': json.loads(plugin_config)}
        hash = hashlib.sha1(bytes(json.dumps(job), 'latin-1')).hexdigest()
        jobs = cherrypy.session.get('jobs', {})
        jobs[hash] = job
        cherrypy.session['jobs'] = jobs
        return json.dumps(hash)
