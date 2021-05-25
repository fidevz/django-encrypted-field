# -*- coding: utf-8 -*-
from __future__ import unicode_literals


from django.core.exceptions import ImproperlyConfigured
from django.contrib.postgres.fields import JSONField
from django.utils.functional import cached_property
from django.db.models.fields import TextField
from django.conf import settings
from django.db import models

from Crypto.Cipher import AES


class EncryptedFieldMixin(models.Field):
    """
    A field that encrypts values with AES 256 symmetric encryption, using Pycryptodome.
    """

    def __init__(self, *args, **kwargs):
        if kwargs.get("primary_key"):
            raise ImproperlyConfigured(f"{self.__class__.__name__} does not support primary_key=True.")
        if kwargs.get("unique"):
            raise ImproperlyConfigured(f"{self.__class__.__name__} does not support unique=True.")
        if kwargs.get("db_index"):
            raise ImproperlyConfigured(f"{self.__class__.__name__} does not support db_index=True.")

        super().__init__(*args, **kwargs)

    @cached_property
    def keys(self):
        # should be a list or tuple of hex encoded 32byte keys
        key_list = settings.FIELD_ENCRYPTION_KEYS
        if not isinstance(key_list, (list, tuple)):
            raise ImproperlyConfigured("FIELD_ENCRYPTION_KEYS should be a list.")
        return key_list

    def encrypt(self, data_to_encrypt):
        if not isinstance(data_to_encrypt, str):
            data_to_encrypt = str(data_to_encrypt)
        cipher = AES.new(bytes.fromhex(self.keys[0]), AES.MODE_GCM)
        nonce = cipher.nonce
        cypher_text, tag = cipher.encrypt_and_digest(data_to_encrypt.encode())
        return nonce + tag + cypher_text

    def decrypt(self, value):
        nonce = value[:16]
        tag = value[16:32]
        cypher_text = value[32:]
        counter = 0
        num_keys = len(self.keys)
        while counter < num_keys:
            cipher = AES.new(bytes.fromhex(self.keys[counter]), AES.MODE_GCM, nonce=nonce)
            try:
                plaintext = cipher.decrypt_and_verify(cypher_text, tag)
            except ValueError:
                counter += 1
                continue
            return plaintext.decode()
        raise ValueError("AES Key incorrect or message corrupted")


class EncryptedJSONField(EncryptedFieldMixin, JSONField):

    def get_db_prep_save(self, value, connection):
        """Encrypt our JSON values before we save"""

        if value == "":
            return None

        if isinstance(value, dict):
            value = self.encrypt_dict(value)

        return super(JSONField, self).get_db_prep_save(value, connection)

    def from_db_value(self, value, expression, connection):
        if value is not None and isinstance(value, dict):
            value = self.decrypt_dict(value)
            return self.to_python(value)

    def decrypt_dict(self, value):
        for key, v in value.items():
            if isinstance(v, dict):
                value[key] = self.decrypt_dict(v)
            else:
                if isinstance(eval(value[key]), (bytearray, bytes)):
                    exec(f"value[key] = {value[key]}")
                    value[key] = self.decrypt(value[key])
                    if value[key].startswith('[') and value[key].endswith(']'):
                        exec(f"value[key] = {value[key]}")
                else:
                    value[key] = None
        return value

    def encrypt_dict(self, value):
        for key, v in value.items():
            if isinstance(v, dict):
                value[key] = self.encrypt_dict(v)
            else:
                value[key] = self.encrypt(v).__str__()
        return value


class EncryptedTextField(EncryptedFieldMixin, TextField):

    def get_db_prep_save(self, value, connection):
        if value == "" or value is None:
            return None

        value = self.encrypt(value).__str__()
        return super(EncryptedTextField, self).get_db_prep_save(value, connection)

    def from_db_value(self, value, expression, connection):
        if value is not None:
            value = self.decrypt_value(value)
            return self.to_python(value)
        return ''

    def decrypt_value(self, value):
        if isinstance(eval(value), (bytearray, bytes)):
            return self.decrypt(eval(value))
        return None
