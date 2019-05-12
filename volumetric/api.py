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
import csv
import hashlib
import io
import json
import logging
import os
import queue
from typing import List, Tuple, Dict, Type, Generator

import cherrypy

import volatility
from volatility import framework, plugins
from volatility.framework import constants, interfaces, contexts, automagic
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import configuration, renderers
from volatility.framework.interfaces.configuration import HierarchicalDict
from volatility.framework.renderers import ColumnSortKey
from volumetric import jsonvol
from volumetric.backqueue import BackgroundTaskQueue

logging.basicConfig(filename = 'logs.txt', level = 0)

vollog = logging.getLogger('volatility')
vollog.setLevel(0)

# file_logger = logging.FileHandler('logs.txt')
# file_logger.setLevel(0)
# file_formatter = logging.Formatter(
#     datefmt = '%y-%m-%d %H:%M:%S', fmt = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
# file_logger.setFormatter(file_formatter)
# vollog.addHandler(file_logger)
vollog.info("Logging started")

framework.require_interface_version(0, 0, 0)


class Api:

    def __init__(self):
        self.plugins = PluginsApi()
        self.automagics = AutomagicApi()
        self.results = ResultsApi()


class AutomagicApi:

    @classmethod
    def get_automagics(cls, context: interfaces.context.ContextInterface = None) -> Generator[
        interfaces.automagic.AutomagicInterface, None, None]:
        """Returns an automagic list of all the automagic objects"""
        seen_automagics = set()
        ctx = context
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
            amagic_item = {
                'name': amagic_name,
                'full_name': amagic.__class__.__module__ + "." + amagic_name,
                'description': amagic.__doc__[:amagic.__doc__.find("\n")],
                'priority': amagic.priority
            }
            result.append(amagic_item)
        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_requirements(self):
        """Returns the requirements for each automagic"""
        result = []
        for amagic in self.get_automagics():
            for req in amagic.get_requirements():
                if isinstance(req, (configuration.SimpleTypeRequirement, requirements.ListRequirement)):
                    automagic_config_path = interfaces.configuration.path_join('automagic', amagic.__class__.__name__)
                    reqment = {
                        'name': automagic_config_path + '.' + req.name,
                        'description': req.description,
                        'default': req.default,
                        'type': req.__class__.__name__,
                        'optional': req.optional,
                        'automagic': amagic.__class__.__name__
                    }
                    result.append(reqment)
        return result


class PluginsApi:

    @classmethod
    def get_plugins(cls) -> Dict[str, Type[interfaces.plugins.PluginInterface]]:
        volatility.plugins.__path__ = constants.PLUGINS_PATH
        failures = volatility.framework.import_files(volatility.plugins,
                                                     True)  # Will not log as console's default level is WARNING
        plugin_list = {}
        for plugin in volatility.framework.class_subclasses(interfaces.plugins.PluginInterface):
            plugin_name = plugin.__module__ + "." + plugin.__name__
            if plugin_name.startswith("volatility.plugins."):
                plugin_name = plugin_name[len("volatility.plugins."):]
            plugin_list[plugin_name] = plugin
        return plugin_list

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list(self) -> List[Tuple[str, bytes]]:
        """List the available plugins"""
        plugin_list = self.get_plugins()

        return [(name, plugin_list[name].__doc__) for name in plugin_list]

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def get_requirements(self, plugin_name):
        """Returns a JSON object containing requirements"""
        plugin_list = self.get_plugins()
        if plugin_name not in plugin_list:
            return None
        plugin = plugin_list[plugin_name]
        plugin_config_path = interfaces.configuration.path_join('plugins', plugin.__name__)
        reqs = []
        for req in plugin.get_requirements():
            if isinstance(req, configuration.SimpleTypeRequirement):
                reqment = {
                    'name': plugin_config_path + '.' + req.name,
                    'description': req.description,
                    'default': req.default,
                    'optional': req.optional,
                    'type': req.__class__.__name__
                }
                reqs.append(reqment)
        return reqs

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def create_job(self, plugin, automagics, global_config, plugin_config):
        """Stores the details locally"""

        # Ensure that non-list items that should be lists are turned into lists
        global_config = json.loads(global_config)
        plugin_config = json.loads(plugin_config)

        # Clean out the plugin_config
        mark_for_deletion = []
        for item in plugin_config:
            if plugin_config[item] is None:
                mark_for_deletion.append(item)
        for item in mark_for_deletion:
            del plugin_config[item]

        for automagic_req in AutomagicApi().get_requirements():
            if automagic_req['type'] == 'ListRequirement':
                if not isinstance(global_config.get(automagic_req['name'], []), list):
                    global_config[automagic_req['name']] = [global_config[automagic_req['name']]]
        for req in self.get_requirements(plugin):
            short_req_name = req['name'].split(configuration.CONFIG_SEPARATOR)[-1]
            if req['type'] == 'ListRequirement':
                if not isinstance(plugin_config.get(req['name'], []), list):
                    plugin_config[req['name']] = [plugin_config[req['name']]]
            if req['type'] == 'IntRequirement':
                try:
                    plugin_config[short_req_name] = int(plugin_config[short_req_name])
                except (TypeError, KeyError):
                    pass
            if req['type'] == 'BooleanRequirement':
                plugin_config[short_req_name] = bool(plugin_config.get(short_req_name, req['default']))

        job = {
            'plugin': plugin,
            'automagics': json.loads(automagics),
            'global_config': global_config,
            'plugin_config': plugin_config,
            'result': None
        }
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
                return "retry: 1000\nevent: {}\ndata: {}\n\n".format(
                    item['type'], json.dumps(item['data'], cls = jsonvol.JSONEncoder))

            jobs = cherrypy.session.get('jobs', {})
            if job_id not in jobs:
                yield respond({'type': 'error', 'data': {'message': 'Failed to locate prepared job'}})
                raise StopIteration
            job = jobs[job_id]

            if job['result'] is None:
                ctx = cherrypy.session.get('context', contexts.Context())

                plugins = self.get_plugins()
                if job['plugin'] not in plugins:
                    yield respond({'type': 'error', 'data': {'message': 'Invalid plugin selected'}})
                    raise StopIteration
                plugin = plugins[job['plugin']]
                plugin_config_path = interfaces.configuration.path_join('plugins', plugin.__name__)

                ctx.config = HierarchicalDict(job['global_config'])
                ctx.config.splice(plugin_config_path, HierarchicalDict(job['plugin_config']))

                automagics = []
                for amagic in AutomagicApi.get_automagics(ctx):
                    if amagic.__class__.__name__ in job['automagics']:
                        automagics.append(amagic)

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
                        elif (progress['type'] == 'config'):
                            job['config'] = progress['data']
                        elif (progress['type'] == 'files'):
                            job['files'] = progress['data']
                        elif progress:
                            yield respond(progress)
                    except TimeoutError:
                        pass
            yield (respond({'type': 'complete-output', 'data': 'complete'}))

        return generator()

    run_job._cp_config = {'response.stream': True, 'tools.encode.encoding': 'utf-8'}

    def sanitize(self, text):
        output = ""
        for char in text:
            if char in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.':
                output += char
            else:
                output += '_'
        return output

    @cherrypy.expose
    def upload(self, uploaded):
        fileval = uploaded.file.read()
        dirname = os.path.join(os.path.dirname(__file__), '..', 'uploads')
        filename = os.path.join(dirname, "{}".format(self.sanitize(uploaded.filename)))

        if not os.path.exists(dirname):
            os.makedirs(dirname)

        count = 0
        while os.path.exists(filename + ".{}.dat".format(count)):
            count += 1

        with open(filename + ".{}.dat".format(count), 'wb') as f:
            f.write(fileval)


class FileConsumer(interfaces.plugins.FileConsumerInterface):

    def __init__(self):
        self.files = []

    def consume_file(self, file: interfaces.plugins.FileInterface):
        # TODO: Consider writing these to disk to free up memory
        self.files.append(file)


def generate_plugin(automagics, ctx, plugin, plugin_config_path, progress_queue):
    def progress_callback(value, message = None):
        progress_queue.put({'type': 'progress', 'data': {'value': value, 'message': message}})

    def visit(node, accumulator):
        accumulator.put({'type': 'partial-output', 'data': [node.path_depth] + list(node.values)})
        return accumulator

    # Disable multi-processing using multiple multi-processes doesn't have any issues
    volatility.framework.constants.PARALLELISM = volatility.framework.constants.PARALLELISM_OFF

    for automagic_req in AutomagicApi().get_requirements():
        if automagic_req['type'] == 'ListRequirement':
            if not isinstance(ctx.config.get(automagic_req['name'], []), list):
                ctx.config[automagic_req['name']] = [ctx.config[automagic_req['name']]]

    consumer = FileConsumer()
    try:
        constructed = framework.plugins.run_plugin(ctx, automagics, plugin, plugin_config_path, progress_callback,
                                                   consumer)
        progress_queue.put({'type': 'config', 'data': dict(constructed.build_configuration())})
        result = constructed.run()

        progress_queue.put({
            'type':
                'columns',
            'data':
                [(-1, 'depth', 'int')] + [(column.index, column.name, column.type.__name__) for column in
                                          result.columns]
        })

        result.populate(visit, progress_queue)
    except Exception as e:
        progress_queue.put({'type': 'error', 'data': {'message': "Exception: {}".format(str(e))}})
        return None

    if consumer.files:
        progress_queue.put({'type': 'files', 'data': consumer.files})
    progress_queue.put({'type': 'finished', 'data': {'message': 'Complete'}, 'result': result})


threadrunner = BackgroundTaskQueue(cherrypy.engine)
threadrunner.subscribe()
progress_queue = queue.Queue()


class ResultsApi:

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list(self):
        jobs = cherrypy.session.get('jobs', {})
        return list(jobs)

    @cherrypy.expose
    @cherrypy.tools.json_out(handler = jsonvol.json_handler)
    def get(self, job_id, index = None, page_size = None, parent_row_id = None, sort_property = None,
            sort_direction = None):
        if index is not None:
            index = json.loads(index)
        if page_size is not None:
            page_size = json.loads(page_size)
        if sort_property is not None:
            sort_property = sort_property
        if sort_direction is not None:
            sort_direction = (sort_direction.lower() == 'asc')
        if parent_row_id == '':
            parent_row_id = None
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
            # We append "h" to ensure the value is treated as a string when it's returned to python
            item_dict = {'volumetric_id': "h" + str(node.__hash__()),
                         'volumetric_parent': ("h" + str(node.parent.__hash__())) if node.parent else None,
                         'hasChildren': bool(result.children(node))}
            item_dict.update(dict(node.values._asdict()))
            for key, value in item_dict.items():
                if isinstance(value, renderers.BaseAbsentValue):
                    # TODO: Further differentiate between AbsentValues
                    item_dict[key] = "-"
            if ((node.parent is None and parent_row_id is None) or
                    (node.parent and "h" + str(node.parent.__hash__()) == parent_row_id)):
                accumulator.append(item_dict)
            return accumulator

        return list(
            result.visit(None, visitor, initial_accumulator = [], sort_key = sort_key)[index:index + page_size])

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def metadata(self, job_id):
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        if not job.get('result', None):
            return None
        return {
            'size':
                job['result'].row_count,
            'columns': [{
                'index': column.index,
                'name': column.name,
                'type': column.type.__name__
            } for column in job['result'].columns]
        }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list_files(self, job_id):
        """Lists files available from this job"""
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return []
        job = jobs[job_id]
        result = []
        for file_index in range(len(job.get('files', []))):
            filedata = job['files'][file_index]
            result.append({'id': file_index, 'name': filedata.preferred_filename})
        return result

    @cherrypy.expose
    def download_file(self, job_id, file_id):
        """Downloads a generated file from a particular job"""
        cherrypy.response.headers['Content-Type'] = 'application/octet-stream'
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        files = job.get('files', [])
        file_id = json.loads(file_id)
        if file_id > len(files) or 0 > file_id:
            return None
        cherrypy.response.headers['Content-Disposition'] = "inline; filename=\"{}\" ".format(
            files[file_id].preferred_filename)
        return files[file_id].data.getvalue()

    @cherrypy.expose
    def download_config(self, job_id):
        """Allows the configuration to be downloaded"""
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        if "config" not in job:
            return None
        cherrypy.response.headers['Content-Type'] = 'application/octet-stream'
        return bytes(json.dumps(job['config'], sort_keys = True, indent = 2), "utf-8")

    @cherrypy.expose
    def download_results(self, job_id):
        """Allows the results table to be downloaded as CSV"""
        jobs = cherrypy.session.get('jobs', {})
        if (job_id not in jobs):
            return None
        job = jobs[job_id]
        cherrypy.response.headers['Content-Type'] = 'text/csv'
        output_file = io.StringIO()

        if 'result' not in job:
            return None
        grid = job['result']
        column_names = [grid.sanitize_name(column.name) for column in grid.columns]
        writer = csv.DictWriter(output_file, fieldnames = ['Depth'] + column_names)

        writer.writeheader()

        def row_writer(node, _accumulator):
            row_dict = {'Depth': node.path_depth}
            row_dict.update(node.values._asdict())
            for key, value in row_dict.items():
                if isinstance(value, renderers.BaseAbsentValue):
                    row_dict[key] = "-"
            writer.writerow(row_dict)

        grid.visit(node = None, function = row_writer)

        return output_file.getvalue()
