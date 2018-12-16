import datetime
import json

import cherrypy

from volatility.framework import interfaces, renderers


class JSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, interfaces.renderers.BaseAbsentValue):
            if isinstance(obj, renderers.NotApplicableValue):
                return "N/A"
            else:
                return "-"
        return super().default(obj)


json_encoder = JSONEncoder()


def json_handler(*args, **kwargs):
    # Adapted from cherrypy/lib/jsontools.py
    value = cherrypy.serving.request._json_inner_handler(*args, **kwargs)
    for chunk in json_encoder.iterencode(value):
        yield chunk.encode('utf-8')
