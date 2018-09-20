import os
import datetime
import hmac
import hashlib
import base58
from OpenSSL.crypto import FILETYPE_PEM
from ssl import create_default_context, SSLContext
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.name import NameOID, NameAttribute
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from twisted.internet import ssl
import keyring as default_keyring
import logging
from lbrynet import conf

log = logging.getLogger(__name__)


def sha(x: bytes) -> str:
    h = hashlib.sha256(x).digest()
    return base58.b58encode(h).decode()


def generate_key(x: bytes = None) -> str:
    if not x:
        return sha(os.urandom(256))
    else:
        return sha(x)


def write_certificate_pem(certificate: bytes) -> None:
    with open(os.path.join(conf.settings['data_dir'], 'api_ssl_cert.pem'), 'wb') as f:
        f.write(certificate)


class APIKey:
    def __init__(self, secret: str, name: str):
        self.secret = secret
        self.name = name

    @classmethod
    def new(cls, seed=None, name=None):
        secret = generate_key(seed)
        return APIKey(secret, name)

    def _raw_key(self) -> str:
        return base58.b58decode(self.secret)

    def get_hmac(self, message) -> str:
        decoded_key = self._raw_key()
        signature = hmac.new(decoded_key, message.encode(), hashlib.sha256)
        return base58.b58encode(signature.digest())

    def compare_hmac(self, message, token) -> bool:
        decoded_token = base58.b58decode(token)
        target = base58.b58decode(self.get_hmac(message))

        try:
            if len(decoded_token) != len(target):
                return False
            return hmac.compare_digest(decoded_token, target)
        except:
            return False


class DefaultKeyring:
    name = "default"
    encoding = serialization.Encoding.PEM
    filetype = FILETYPE_PEM
    service_name = "lbrynet"
    x509_field = "public"
    private_field = "server"
    api_field = "api"

    def __init__(self, keyring) -> None:
        self.keyring = keyring

    @classmethod
    def get_keyring(cls, password: str = ""):
        try:
            return cls(default_keyring.get_keyring())
        except ImportError:
            return

    def save_public_x509(self, certificate: str) -> None:
        self.keyring.set_password(self.service_name, self.x509_field, certificate)
        write_certificate_pem(certificate.encode())

    def save_private_rsa(self, private_key: str) -> None:
        self.keyring.set_password(self.service_name, self.private_field, private_key)

    def get_public_x509(self) -> str:
        return self.keyring.get_password(self.service_name, self.x509_field)

    def get_private_rsa(self) -> str:
        return self.keyring.get_password(self.service_name, self.private_field)

    def save_api_key(self, api_key: str) -> None:
        self.keyring.set_password(self.service_name, self.api_field, api_key)

    def get_api_key(self) -> APIKey:
        return APIKey(self.keyring.get_password(self.service_name, self.api_field), self.api_field)

    def generate_api_key(self) -> APIKey:
        key = APIKey.new(seed=None, name=self.api_field)
        self.save_api_key(key.secret)
        return key

    def get_private_x509(self) -> ssl.PrivateCertificate:
        public = self.get_public_x509()
        private = self.get_private_rsa()
        if not public or not private:
            public = self.generate_certificate().public_bytes(self.encoding).decode()
            private = self.get_private_rsa()
        if public and private:
            return ssl.PrivateCertificate.load(
                public,
                ssl.KeyPair.load(private, self.filetype),
                self.filetype
            )

    def save_private_x509(self, private_key: rsa.RSAPrivateKey, certificate: ssl.PrivateCertificate) -> None:
        self.save_private_rsa(
            private_key.private_bytes(
                encoding=self.encoding,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        )
        self.save_public_x509(
            certificate.public_bytes(self.encoding).decode()
        )

    def get_ssl_context(self) -> SSLContext:
        public = self.get_public_x509()
        if public:
            return create_default_context(cadata=public)

    def generate_certificate(self, country: str = "US", organization: str = "LBRY",
                                     common_name: str = "LBRY API", expiration: int = 365) -> _Certificate:
        dns = conf.settings['api_host']
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        subject = issuer = x509.Name([
            NameAttribute(NameOID.COUNTRY_NAME, country),
            NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        alternative_name = x509.SubjectAlternativeName([x509.DNSName(dns)])
        certificate = x509.CertificateBuilder(
            subject_name=subject,
            issuer_name=issuer,
            public_key=private_key.public_key(),
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.datetime.utcnow(),
            not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=expiration),
            extensions=[x509.Extension(oid=alternative_name.oid, critical=False, value=alternative_name)]
        ).sign(private_key, hashes.SHA256(), default_backend())
        self.save_private_x509(
            private_key, certificate
        )
        return certificate


# class AndroidKeyring(DefaultKeyring):
#     encoding = serialization.Encoding.OpenSSH
#     filetype = FILETYPE_ASN1
#     name = "android"
#
#     def __init__(self, keyring, path, password):
#         super().__init__(keyring)
#         self.path = path
#         self.password = password
#
#     @classmethod
#     def get_keyring(cls, password: str = ""):
#         try:
#             from jks import KeyStore as android_keyring
#             path = "%s.jks" % cls.service_name
#             return cls(android_keyring.load(path, password), path, password)
#         except ImportError:
#             pass
#
#     def save_api_key(self, api_key: str) -> None:
#         raise NotImplementedError()
#
#     def get_api_key(self) -> APIKey:
#         raise NotImplementedError()
#
#     def save_public_x509(self, certificate: str) -> None:
#         from jks import TrustedCertEntry
#         new_entry = TrustedCertEntry.new(self.x509_field, certificate)
#         self.keyring.entries[self.x509_field] = new_entry
#         self.keyring.save(self.keyring, self.password)
#
#     def save_private_rsa(self, private_key: str) -> None:
#         from jks import PrivateKeyEntry
#         new_entry = PrivateKeyEntry.new(self.private_field, [], private_key)
#         self.keyring.entries[self.x509_field] = new_entry
#         self.keyring.save(self.keyring, self.password)
#
#     def get_public_x509(self) -> str:
#         from jks import TrustedCertEntry
#         if self.x509_field in self.keyring.certs:
#             cert: TrustedCertEntry = self.keyring.certs[self.x509_field]
#             return cert.cert.decode()
#
#     def get_private_rsa(self) -> str:
#         from jks import PrivateKeyEntry
#         if self.private_field in self.keyring.private_keys:
#             pk_entry: PrivateKeyEntry = self.keyring.private_keys[self.private_field]
#             return pk_entry.pkey.decode()
#
#     # def get_ssl_context(self) -> SSLContext:
#     #     from jks import PrivateKeyEntry
#     #     _ASN1 = ssl_crypto.FILETYPE_ASN1
#     #     pk_entry: PrivateKeyEntry = self.keyring.private_keys["public"]
#     #     pkey = self.get_private_certificate_from_keyring()
#     #     public_cert = ssl_crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
#     #     trusted_certs = [ssl_crypto.load_certificate(_ASN1, cert.cert) for alias, cert in self.keyring.certs]
#     #     ctx = SSL.Context(SSL.TLSv1_METHOD)
#     #     ctx.use_privatekey(pkey)
#     #     ctx.use_certificate(public_cert)
#     #     ctx.check_privatekey()
#     #     cert_store = ctx.get_cert_store()
#     #     for cert in trusted_certs:
#     #         cert_store.add_cert(cert)
#     #     # return create_default_context(cadata=cert_asn)
#     #     return ctx
#     #


Keyring = DefaultKeyring.get_keyring() #or AndroidKeyring.get_keyring()
assert Keyring is not None, "No keyring could be configured"
