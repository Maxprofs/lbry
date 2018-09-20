import logging

from twisted.web import server, guard, resource
from twisted.cred import portal

from lbrynet import conf
from .auth import PasswordChecker, HttpPasswordRealm
from ..auth.keyring import Keyring

log = logging.getLogger(__name__)


class HTTPJSONRPCFactory(server.Site):
    def __init__(self, resource, requestFactory=None, *args, **kwargs):
        super().__init__(resource, requestFactory=requestFactory, *args, **kwargs)
        self.use_ssl = False


class HTTPSJSONRPCFactory(server.Site):
    def __init__(self, resource, requestFactory=None, *args, **kwargs):
        super().__init__(resource, requestFactory=requestFactory, *args, **kwargs)
        self.options = Keyring.get_private_x509().options()
        self.use_ssl = True


class AuthJSONRPCResource(resource.Resource):
    def __init__(self, protocol):
        resource.Resource.__init__(self)
        self.putChild(b"", protocol)
        self.putChild(conf.settings['API_ADDRESS'].encode(), protocol)

    def getChild(self, name, request):
        request.setHeader('cache-control', 'no-cache, no-store, must-revalidate')
        request.setHeader('expires', '0')
        return self if name == '' else resource.Resource.getChild(self, name, request)

    def getServerFactory(self) -> server.Site:
        factory = HTTPSJSONRPCFactory if conf.settings['use_https'] else HTTPJSONRPCFactory
        if conf.settings['use_auth_http']:
            log.info("Using authenticated API")
            Keyring.generate_api_key()
            checker = PasswordChecker(Keyring)
            realm = HttpPasswordRealm(self)
            portal_to_realm = portal.Portal(realm, [checker, ])
            root = guard.HTTPAuthSessionWrapper(
                portal_to_realm, [guard.BasicCredentialFactory('Login to lbrynet api'), ]
            )
        else:
            log.info("Using non-authenticated API")
            root = self
        return factory(root)
