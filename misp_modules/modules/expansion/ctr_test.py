import json
import requests
from threatresponse import ThreatResponse

misperrors = {'error': 'Error'}
mispattributes = {'input': ['hostname', 'domain']}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Mykhailo Myskiv',
              'description': 'Request CTR',
              'module-type': ['hover']}

# config fields that your code expects from the site admin
moduleconfig = ["client_secret", "client_id"]


def handler(q=False):
    if q is False:
        return False
    request = {"module": "ctr_test", "persistent": 1, "config": {"client_secret": None, "client_id": None},
               "hostname": "24tv.ua"}
    request = json.loads(q)
    client_secret = request.get('config', {}).get('client_secret')
    client_id = request.get('config', {}).get('client_id')
    if not client_secret:
        return {'error': 'An client_secret for CTRIntegration is required.'}
    if not client_id:
        return {'error': 'An client_id for CTRIntegration is required.'}

    client = ThreatResponse(
        client_id=client_id,
        client_password=client_secret,
    )

    res = client.enrich.health()

    r = {'results':
        [
            {
                'types': ['text'],
                'values': [module["module"] for module in res["data"]]
            }
        ]
    }
    return r


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
