import logging
import os
import cherrypy

from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
import controllers.module as module

logger = logging.getLogger('splunk')

class HealthCheck(module.ModuleMapper):

    @route('/:action=index')
    @expose_page(must_login=True, methods='GET')
    def index(self, **kwargs):
        return self.render_template(
            'splunk_health_check:/templates/health_check.html', {}
        )
