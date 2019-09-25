# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
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
