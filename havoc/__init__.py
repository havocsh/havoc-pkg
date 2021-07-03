# Copyright 2020 Havoc Inc. or its affiliates. All Rights Reserved.

# Licensed under the GNU General Public Licnese v3.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import os, re, json, datetime, hashlib, hmac, requests


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region, host):
    k_date = sign(('havoc' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_signing = sign(k_region, host)
    return k_signing


class Connect:

    def __init__(self, region, api_domain_name, api_key, secret):
        self.region = region
        self.api_domain_name = api_domain_name
        self.api_key = api_key
        self.secret = secret
        self.session = None

    def post(self, uri, payload):

        # Create sig_date for signature and date_stamp for signing key
        t = datetime.datetime.utcnow()
        sig_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        # Get signing_key
        signing_key = get_signature_key(self.secret, date_stamp, self.region, self.api_domain_name)

        # Setup string to sign
        algorithm = 'HMAC-SHA256'
        credential_scope = date_stamp + '/' + self.region + '/' + self.api_domain_name
        string_to_sign = algorithm + '\n' + sig_date + '\n' + credential_scope + hashlib.sha256(
            self.api_key.encode('utf-8')).hexdigest()

        # Generate signature
        signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # Create and issue post
        headers = {'x-api-key': self.api_key, 'x-sig-date': sig_date, 'x-signature': signature}
        try:
            r = requests.post(uri, json=payload, headers=headers)
            r.raise_for_status()
            return json.loads(r.text)
        except requests.exceptions.HTTPError as err:
            print(err.request.url)
            print(err)
            print(err.response.text)

    def get_commands(self, task_name):
        remote_api_endpoint = f'https://{self.api_domain_name}/remote-task'
        payload = {'command': 'get_commands', 'detail': {'task_name': task_name}}

        commands_response = self.post(remote_api_endpoint, payload)
        return commands_response

    def post_response(self, results):
        remote_api_endpoint = f'https://{self.api_domain_name}/remote-task'
        payload = {'command': 'post_results', 'results': results}

        post_response = self.post(remote_api_endpoint, payload)
        return post_response

    def sync_workspace(self, sync_direction, sync_path):
        manage_api_endpoint = f'https://{self.api_domain_name}/manage'
        file_list = []
        if sync_direction == 'sync_from_workspace':
            payload = {'resource': 'workspace', 'command': 'list'}
            list_response = self.post(manage_api_endpoint, payload)
            for file in list_response['files']:
                file_list.append(file)
                payload = {'resource': 'workspace', 'command': 'get', 'detail': {'filename': file}}
                get_file_response = self.post(manage_api_endpoint, payload)
                file_contents = get_file_response['file_contents']
                f = open(f'{sync_path}/{file}', 'wb')
                f.write(file_contents)
                f.close()
        if sync_direction == 'sync_to_workspace':
            for root, subdirs, files in os.walk(sync_path):
                for filename in files:
                    corrected_root = re.match(f'{sync_path}/(.*)', root).group(1)
                    relative_path = os.path.join(corrected_root, filename)
                    file_list.append(relative_path)
                    file_path = os.path.join(root, filename)
                    f = open(file_path, 'rb')
                    file_contents = f.read()
                    f.close()
                    payload = {
                        'resource': 'workspace', 'command': 'create', 'detail': {
                            'filename': relative_path, 'file_contents': file_contents
                        }
                    }
                    self.post(manage_api_endpoint, payload)
        return file_list
