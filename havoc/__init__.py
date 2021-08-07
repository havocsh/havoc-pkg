# Copyright 2020 Havoc Inc. or its affiliates. All Rights Reserved.

# Licensed under the GNU General Public Licnese v3.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import os, re, json, datetime, hashlib, hmac, requests, base64


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
        self.__remote_api_endpoint = None
        self.__manage_api_endpoint = None
        self.__task_control_api_endpoint = None

    @property
    def remote_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/remote-task'
        else:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/remote-task'
        return self.__remote_api_endpoint

    @property
    def manage_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/manage'
        else:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/manage'
        return self.__manage_api_endpoint

    @property
    def task_control_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name:
            self.__task_control_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/task-control'
        else:
            self.__task_control_api_endpoint = f'https://{self.api_domain_name}/task-control'
        return self.__task_control_api_endpoint

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

    def list_tasks(self):
        payload = {
            'resource': 'task',
            'command': 'list'
        }
        list_tasks_response = self.post(self.manage_api_endpoint, payload)
        return list_tasks_response

    def get_task(self, task_name):
        payload = {
            'resource': 'task',
            'command': 'get',
            'detail': {'task_name': task_name}
        }
        get_task_response = self.post(self.manage_api_endpoint, payload)
        return get_task_response

    def kill_task(self, task_name):
        payload = {
            'resource': 'task',
            'command': 'kill',
            'detail': {'task_name': task_name}
        }
        kill_task_response = self.post(self.manage_api_endpoint, payload)
        return kill_task_response

    def list_task_types(self):
        payload = {
            'resource': 'task_type',
            'command': 'list'
        }
        list_task_types_response = self.post(self.manage_api_endpoint, payload)
        return list_task_types_response

    def get_task_type(self, task_type):
        payload = {
            'resource': 'task_type',
            'command': 'get',
            'detail': {'task_type': task_type}
        }
        get_task_type_response = self.post(self.manage_api_endpoint, payload)
        return get_task_type_response

    def list_users(self):
        payload = {
            'resource': 'user',
            'command': 'list'
        }
        list_users_response = self.post(self.manage_api_endpoint, payload)
        return list_users_response

    def get_user(self, user_id):
        payload = {
            'resource': 'user',
            'command': 'get',
            'detail': {'user_id': user_id}
        }
        get_user_response = self.post(self.manage_api_endpoint, payload)
        return get_user_response

    def create_user(self, user_id, admin):
        payload = {
            'resource': 'user',
            'command': 'create',
            'detail': {'user_id': user_id, 'admin': admin}
        }
        create_user_response = self.post(self.manage_api_endpoint, payload)
        return create_user_response

    def update_user(self, user_id, admin=None, reset_keys=None):
        detail = {'user_id': user_id}
        if admin:
            detail['admin'] = admin
        if reset_keys:
            detail['reset_keys'] = reset_keys
        payload = {
            'resource': 'user',
            'command': 'update',
            'detail': detail
        }
        update_user_response = self.post(self.manage_api_endpoint, payload)
        return update_user_response

    def delete_user(self, user_id):
        payload = {
            'resource': 'user',
            'command': 'delete',
            'detail': {'user_id': user_id}
        }
        delete_user_response = self.post(self.manage_api_endpoint, payload)
        return delete_user_response

    def list_files(self):
        payload = {
            'resource': 'workspace',
            'command': 'list'
        }
        list_files_response = self.post(self.manage_api_endpoint, payload)
        return list_files_response

    def get_file(self, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'get',
            'detail': {'filename': file_name}
        }
        get_file_response = self.post(self.manage_api_endpoint, payload)
        return get_file_response

    def create_file(self, file_name, raw_file):
        encoded_file = base64.b64encode(raw_file).decode()
        payload = {
            'resource': 'workspace',
            'command': 'create',
            'detail': {'filename': file_name, 'file_contents': encoded_file}
        }
        create_file_response = self.post(self.manage_api_endpoint, payload)
        return create_file_response

    def delete_file(self, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'delete',
            'detail': {'filename': file_name}
        }
        delete_file_response = self.post(self.manage_api_endpoint, payload)
        return delete_file_response

    def list_portgroups(self):
        payload = {
            'resource': 'portgroup',
            'command': 'list'
        }
        list_portgroups_response = self.post(self.manage_api_endpoint, payload)
        return list_portgroups_response

    def get_portgroup(self, portgroup_name):
        payload = {
            'resource': 'portgroup',
            'command': 'get',
            'detail': {'portgroup_name': portgroup_name}
        }
        get_portgroup_response = self.post(self.manage_api_endpoint, payload)
        return get_portgroup_response

    def create_portgroup(self, portgroup_name, portgroup_description):
        payload = {
            'resource': 'portgroup',
            'command': 'create',
            'detail': {'portgroup_name': portgroup_name, 'portgroup_description': portgroup_description}
        }
        create_portgroup_response = self.post(self.manage_api_endpoint, payload)
        return create_portgroup_response

    def update_portgroup_rule(self, portgroup_name, portgroup_action, ip_ranges, port, ip_protocol):
        payload = {
            'resource': 'portgroup',
            'command': 'update',
            'detail': {
                'portgroup_name': portgroup_name,
                'portgroup_action': portgroup_action,
                'ip_ranges': ip_ranges,
                'port': port,
                'ip_protocol': ip_protocol
            }
        }
        update_portgroup_rule_response = self.post(self.manage_api_endpoint, payload)
        return update_portgroup_rule_response

    def delete_portgroup(self, portgroup_name):
        payload = {
            'resource': 'portgroup',
            'command': 'delete',
            'detail': {'portgroup_name': portgroup_name}
        }
        delete_portgroup_response = self.post(self.manage_api_endpoint, payload)
        return delete_portgroup_response

    def run_task(self, task_name, task_type, end_time='None'):
        payload = {
            'action': 'execute',
            'detail': {'task_name': task_name, 'task_type': task_type, 'end_time': end_time}
        }
        run_task_response = self.post(self.task_control_api_endpoint, payload)
        return run_task_response

    def instruct_task(self, task_name, instruct_instance, instruct_command, instruct_args=None):
        payload = {
            'action': 'interact',
            'detail': {
                'task_name': task_name,
                'instruct_instance': instruct_instance,
                'instruct_command': instruct_command
            }
        }
        if instruct_args:
            payload['detail']['instruct_args'] = instruct_args
        instruct_task_response = self.post(self.task_control_api_endpoint, payload)
        return instruct_task_response

    def get_task_results(self, task_name):
        payload = {
            'action': 'get_results',
            'detail': {'task_name': task_name}
        }
        get_task_results_response = self.post(self.task_control_api_endpoint, payload)
        return get_task_results_response

    def register_task(self, task_name, task_context, task_type, attack_ip, local_ip):
        payload = {
            'command': 'register_task',
            'detail': {
                'task_name': task_name,
                'task_context': task_context,
                'task_type': task_type,
                'attack_ip': attack_ip,
                'local_ip': local_ip
            }
        }

        register_task_response = self.post(self.remote_api_endpoint, payload)
        return register_task_response

    def get_commands(self, task_name):
        payload = {'command': 'get_commands', 'detail': {'task_name': task_name}}

        commands_response = self.post(self.remote_api_endpoint, payload)
        return commands_response

    def post_response(self, results):
        payload = {'command': 'post_results', 'results': results}

        post_response = self.post(self.remote_api_endpoint, payload)
        return post_response

    def sync_workspace(self, sync_direction, sync_path):
        file_list = []
        if sync_direction == 'sync_from_workspace':
            payload = {'resource': 'workspace', 'command': 'list'}
            list_response = self.post(self.manage_api_endpoint, payload)
            if 'files' in list_response:
                for f in list_response['files']:
                    file_list.append(f)
                    payload = {'resource': 'workspace', 'command': 'get', 'detail': {'filename': f}}
                    get_file_response = self.post(self.manage_api_endpoint, payload)
                    file_contents = get_file_response['file_contents']
                    f = open(f'{sync_path}/{file}', 'wb')
                    f.write(file_contents)
                    f.close()
        if sync_direction == 'sync_to_workspace':
            for root, subdirs, files in os.walk(sync_path):
                if files:
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
                        self.post(self.manage_api_endpoint, payload)
        return file_list
