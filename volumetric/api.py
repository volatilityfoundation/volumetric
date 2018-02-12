import hashlib
import json
import logging
import queue

import cherrypy

import volatility
from volatility import framework, plugins
from volatility.framework import constants, interfaces, contexts, automagic
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import configuration
from volatility.framework.interfaces.configuration import HierarchicalDict
from volatility.framework.renderers import ColumnSortKey
from volumetric.backqueue import BackgroundTaskQueue

vollog = logging.getLogger('volatility')
vollog.setLevel(0)

file_logger = logging.FileHandler('logs.txt')
file_logger.setLevel(0)
file_formatter = logging.Formatter(datefmt = '%y-%m-%d %H:%M:%S',
                                   fmt = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
file_logger.setFormatter(file_formatter)
vollog.addHandler(file_logger)
vollog.info("Logging started")

framework.require_interface_version(0, 0, 0)


class Api(object):
    def __init__(self):
        self.plugins = PluginsApi()
        self.automagics = AutomagicApi()
        self.results = ResultsApi()


class AutomagicApi(object):
    @classmethod
    def get_automagics(cls):
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
    @cherrypy.tools.json_out()
    def list(self):
        """Returns an automagic list of all the automagic objects"""
        amagics = self.get_automagics()
        result = []
        for amagic in amagics:
            amagic_name = amagic.__class__.__name__
            amagic_item = {'name': amagic_name,
                           'full_name': amagic.__class__.__module__ + "." + amagic_name,
                           'description': amagic.__doc__[:amagic.__doc__.find("\n")],
                           'priority': amagic.priority}
            result.append(amagic_item)
        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_requirements(self):
        """Returns the requirements for each automagic"""
        result = []
        for amagic in self.get_automagics():
            for req in amagic.get_requirements():
                if isinstance(req, (configuration.InstanceRequirement, requirements.ListRequirement)):
                    automagic_config_path = interfaces.configuration.path_join('automagic', amagic.__class__.__name__)
                    reqment = {'name': automagic_config_path + '.' + req.name,
                               'description': req.description,
                               'default': req.default,
                               'type': req.__class__.__name__,
                               'optional': req.optional,
                               'automagic': amagic.__class__.__name__}
                    result.append(reqment)
        return result


class PluginsApi(object):
    @classmethod
    def get_plugins(cls):
        volatility.plugins.__path__ = cherrypy.session.get('plugin_dir', '').split(";") + constants.PLUGINS_PATH
        volatility.framework.import_files(volatility.plugins)  # Will not log as console's default level is WARNING
        if cherrypy.session.get('plugins', None):
            return cherrypy.session.get('plugins', None)
        plugin_list = {}
        for plugin in volatility.framework.class_subclasses(interfaces.plugins.PluginInterface):
            plugin_name = plugin.__module__ + "." + plugin.__name__
            if plugin_name.startswith("volatility.plugins."):
                plugin_name = plugin_name[len("volatility.plugins."):]
            plugin_list[plugin_name] = plugin
        cherrypy.session['plugins'] = plugin_list
        return plugin_list

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list(self):
        """List the available plugins"""
        plugin_list = self.get_plugins()

        return [name for name in plugin_list]

    @cherrypy.expose
    @cherrypy.tools.json_out()
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
        return reqs

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_job(self, plugin, automagics, global_config, plugin_config):
        """Stores the details locally"""
        job = {'plugin': plugin,
               'automagics': json.loads(automagics),
               'global_config': json.loads(global_config),
               'plugin_config': json.loads(plugin_config),
               'result': None}
        hash = hashlib.sha1(bytes(json.dumps(job, sort_keys = True), 'latin-1')).hexdigest()
        jobs = cherrypy.session.get('jobs', {})
        jobs[hash] = job
        cherrypy.session['jobs'] = jobs
        return hash

    @cherrypy.expose
    def run_job(self, job_id):
        """Runs a plugin, providing progress reports and storing the results"""
        cherrypy.response.headers["Content-Type"] = "text/event-stream;charset=utf-8"

        def generator():
            def respond(item):
                print("RESPONSE", item)
                return "retry: 1000\nevent: {}\ndata: {}\n\n".format(item['type'], json.dumps(item['data']))

            jobs = cherrypy.session.get('jobs', {})
            if job_id not in jobs:
                yield respond({'type': 'error',
                               'data': {'message': 'Failed to locate prepared job'}})
                raise StopIteration
            job = jobs[job_id]

            if job['result'] is None:
                ctx = cherrypy.session.get('context', contexts.Context())

                plugins = self.get_plugins()
                if job['plugin'] not in plugins:
                    yield respond({'type': 'error',
                                   'data': {'message': 'Invalid plugin selected'}})
                    raise StopIteration
                plugin = plugins[job['plugin']]
                plugin_config_path = interfaces.configuration.path_join('plugins', plugin.__name__)

                automagics = []
                for amagic in AutomagicApi.get_automagics():
                    if amagic.__class__.__name__ in job['automagics']:
                        automagics.append(amagic)

                ctx.config = HierarchicalDict(job['global_config'])
                ctx.config.splice(plugin_config_path, HierarchicalDict(job['plugin_config']))

                threadrunner.put(generate_plugin, automagics, ctx, plugin, plugin_config_path, progress_queue)

                finished = False
                while not finished:
                    try:
                        progress = progress_queue.get(0.1)
                        if (progress['type'] == 'finished' or progress['type'] == 'error'):
                            if progress['type'] == 'finished':
                                job['result'] = progress['result']
                                break
                            else:
                                yield respond(progress)
                                break
                        if progress:
                            yield respond(progress)
                    except TimeoutError:
                        pass
            yield (respond({'type': 'complete-output',
                            'data': 'complete'}))

        return generator()

    run_job._cp_config = {'response.stream': True, 'tools.encode.encoding': 'utf-8'}


def generate_plugin(automagics, ctx, plugin, plugin_config_path, progress_queue):
    def progress_callback(value, message = None):
        progress_queue.put({'type': 'progress',
                            'data': {'value': value,
                                     'message': message}
                            })

    def visit(node, accumulator):
        accumulator.put({'type': 'partial-output',
                         'data': [node.path_depth] + list(node.values)})
        return accumulator

    # Disable multi-processing using multiple multi-processes doesn't have any issues
    volatility.framework.constants.DISABLE_MULTITHREADED_SCANNING = True

    try:
        automagic.run(automagics, ctx, plugin, "plugins", progress_callback = progress_callback)
    except Exception as e:
        progress_queue.put({'type': 'warning',
                            'data': {'message': 'Running automagic failed: {}'.format(repr(e))}})

    unsatisfied = plugin.unsatisfied(ctx, plugin_config_path)
    if unsatisfied:
        progress_queue.put({'type': 'error',
                            'data': {'message': 'Plugin requirements not satisfied'}})
        return None

    try:
        constructed = plugin(ctx, plugin_config_path)
        result = constructed.run()

        progress_queue.put({'type': 'columns',
                            'data': [(-1, 'depth', 'int')] +
                                    [(column.index, column.name, column.type.__name__) for column in result.columns]
                            })

        result.populate(visit, progress_queue)
    except Exception as e:
        progress_queue.put({'type': 'error',
                            'data': {'message': 'Exception: {}'.format(e)}})
        return None

    progress_queue.put({'type': 'finished',
                        'data': {'message': 'Complete'},
                        'result': result})


threadrunner = BackgroundTaskQueue(cherrypy.engine)
threadrunner.subscribe()
progress_queue = queue.Queue()


class ResultsApi(object):
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list(self):
        jobs = cherrypy.session.get('jobs', {})
        return list(jobs)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get(self, job_id, index = None, page_size = None, sort_property = None, sort_direction = None):
        if index is not None:
            index = json.loads(index)
        if page_size is not None:
            page_size = json.loads(page_size)
        if sort_property is not None:
            sort_property = sort_property
        if sort_direction is not None:
            sort_direction = (sort_direction.lower() == 'asc')
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        if not job.get('result', None):
            return None

        result = job['result']
        sort_key = None
        if sort_property is not None:
            sort_key = ColumnSortKey(result, sort_property, sort_direction)

        def visitor(node, accumulator):
            item_dict = {'depth': result.path_depth(node)}
            item_dict.update(dict(node.values._asdict()))
            accumulator.append(item_dict)
            return accumulator

        return list(result.visit(None, visitor, initial_accumulator = [], sort_key = sort_key)[index:index + page_size])

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def metadata(self, job_id):
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        if not job['result']:
            return None
        return {'size': job['result'].row_count,
                'columns': [{'index': column.index, 'name': column.name, 'type': column.type.__name__} for column in
                            job['result'].columns]}
