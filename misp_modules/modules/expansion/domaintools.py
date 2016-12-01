import json
import logging
import sys

from domaintools import API


log = logging.getLogger('domaintools')
log.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

misperrors = {'error': 'Error'}
mispattributes = {
    'input': ['domain'],
    'output': ['whois-registrant-email', 'whois-registrant-phone', 'whois-registrant-name',
               'whois-registrar', 'whois-creation-date', 'freetext']
}

moduleinfo = {
    'version': '0.1',
    'author': 'Raphaël Vinot',
    'description': 'DomainTools MISP expansion module.',
    'module-type': ['expansion', 'hover']
}

moduleconfig = ['username', 'api_key']


class DomainTools(object):

    def __init__(self):
        self.reg_mail = {}
        self.reg_phone = {}
        self.reg_name = {}
        self.registrar = {}
        self.creation_date = {}
        self.freetext = ''

    def _add_value(self, value_type, value, comment):
        if value_type.get(value):
            if comment:
                value_type[value] += ' - {}'.format(comment)
        else:
            value_type[value] = comment or ''
        return value_type

    def add_mail(self, mail, comment=None):
        self.reg_mail = self._add_value(self.reg_mail, mail, comment)

    def add_phone(self, phone, comment=None):
        self.reg_phone = self._add_value(self.reg_phone, phone, comment)

    def add_name(self, name, comment=None):
        self.reg_name = self._add_value(self.reg_name, name, comment)

    def add_registrar(self, reg, comment=None):
        self.registrar = self._add_value(self.registrar, reg, comment)

    def add_creation_date(self, date, comment=None):
        self.creation_date = self._add_value(self.creation_date, date, comment)

    def dump(self):
        to_return = []
        if self.reg_mail:
            for mail, comment in self.reg_mail.items():
                to_return.append({'type': 'whois-registrant-email', 'values': [mail], 'comment': comment or ''})
        if self.reg_phone:
            for phone, comment in self.reg_phone.items():
                to_return.append({'type': 'whois-registrant-phone', 'values': [phone], 'comment': comment or ''})
        if self.reg_name:
            for name, comment in self.reg_name.items():
                to_return.append({'type': 'whois-registrant-name', 'values': [name], 'comment': comment or ''})
        if self.registrar:
            for reg, comment in self.registrar.items():
                to_return.append({'type': 'whois-registrar', 'values': [reg], 'comment': comment or ''})
        if self.creation_date:
            for date, comment in self.creation_date.items():
                to_return.append({'type': 'whois-creation-date', 'values': [date], 'comment': comment or ''})
        if self.freetext:
            to_return.append({'type': 'freetext', 'values': [self.freetext], 'comment': 'Freetext import'})
        return to_return


def handler(q=False):
    if not q:
        return q

    request = json.loads(q)
    to_query = None
    for t in mispattributes['input']:
        to_query = request.get(t)
        if to_query:
            break
    if not to_query:
        misperrors['error'] = "Unsupported attributes type"
        return misperrors

    if request.get('config'):
        if (request['config'].get('username') is None) or (request['config'].get('api_key') is None):
            misperrors['error'] = 'DomainTools authentication is incomplete'
            return misperrors
        else:
            domtools = API(request['config'].get('username'), request['config'].get('api_key'))
    else:
        misperrors['error'] = 'DomainTools authentication is missing'
        return misperrors

    whois_entry = domtools.parsed_whois(to_query)
    print(whois_entry)
    values = DomainTools()

    if whois_entry.get('error'):
        misperrors['error'] = whois_entry['error']['message']
        return misperrors

    if whois_entry.get('registrant'):
        values.add_name(whois_entry['registrant'], 'Parsed registrant')

    if whois_entry.get('registration'):
        values.add_creation_date(whois_entry['registration']['created'], 'timestamp')

    if whois_entry.get('whois'):
        values.freetext = whois_entry['whois']['record']
    if whois_entry.get('parsed_whois'):
        if whois_entry['parsed_whois']['created_date']:
            values.add_creation_date(whois_entry['parsed_whois']['created_date'])
        if whois_entry['parsed_whois']['registrar']['name']:
            values.add_registrar(whois_entry['parsed_whois']['registrar']['name'], 'name')
        if whois_entry['parsed_whois']['registrar']['url']:
            values.add_registrar(whois_entry['parsed_whois']['registrar']['url'], 'url')
        if whois_entry['parsed_whois']['registrar']['iana_id']:
            values.add_registrar(whois_entry['parsed_whois']['registrar']['iana_id'], 'iana_id')
        for key, entry in whois_entry['parsed_whois']['contacts'].items():
            if entry['email']:
                values.add_mail(entry['email'], key)
            if entry['phone']:
                values.add_phone(entry['phone'], key)
            if entry['name']:
                values.add_name(entry['name'], key)
    if whois_entry.emails():
        for mail in whois_entry.emails():
            if mail not in values.reg_mail.keys():
                values.add_mail(mail, 'Maybe registrar')
    return {'results': values.dump()}


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
