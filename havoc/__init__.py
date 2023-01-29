# Copyright 2020 Havoc Inc. or its affiliates. All Rights Reserved.

# Licensed under the GNU General Public Licnese v3.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import os, zlib, random, string, json, datetime, hashlib, hmac, requests, base64
import time as t


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
        if 'amazonaws.com' in self.api_domain_name and os.path.exists('.havoc/havoc.cfg'):
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc/remote-task'
        elif 'amazonaws.com' in self.api_domain_name:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/remote-task'
        else:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/remote-task'
        return self.__remote_api_endpoint

    @property
    def manage_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and os.path.exists('.havoc/havoc.cfg'):
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc/manage'
        elif 'amazonaws.com' in self.api_domain_name:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/manage'
        else:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/manage'
        return self.__manage_api_endpoint

    @property
    def task_control_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and os.path.exists('.havoc/havoc.cfg'):
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc/task-control'
        elif 'amazonaws.com' in self.api_domain_name:
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
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

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

    def create_deployment(self, deployment_version, deployment_admin_email, results_queue_expiration, api_domain_name, api_region, 
                          tfstate_s3_bucket, tfstate_s3_key, tfstate_s3_region, tfstate_dynamodb_table):
        payload = {
            'resource': 'deployment',
            'command': 'create',
            'detail': {
                'deployment_version': deployment_version,
                'deployment_admin_email': deployment_admin_email,
                'results_queue_expiration': results_queue_expiration,
                'api_domain_name': api_domain_name,
                'api_region': api_region,
                'tfstate_s3_bucket': tfstate_s3_bucket,
                'tfstate_s3_key': tfstate_s3_key,
                'tfstate_s3_region': tfstate_s3_region,
                'tfstate_dynamodb_table': tfstate_dynamodb_table
            }
        }
        create_deployment_response = self.post(self.manage_api_endpoint, payload)
        return create_deployment_response
    
    def update_deployment(self, **kwargs):
        payload = {
            'resource': 'deployment',
            'command': 'update'
        }
        if kwargs:
            payload['detail'] = kwargs
        else:
            payload['detail'] = {}
        update_deployment_response = self.post(self.manage_api_endpoint, payload)
        return update_deployment_response
    
    def get_deployment(self):
        payload = {
            'resource': 'deployment',
            'command': 'get',
        }
        get_deployment_response = self.post(self.manage_api_endpoint, payload)
        return get_deployment_response

    def list_tasks(self, task_name_contains='', task_status='running'):
        payload = {
            'resource': 'task',
            'command': 'list',
            'detail': {'task_name_contains': task_name_contains, 'task_status': task_status}
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

    def create_task_type(self, task_type, task_version, source_image, capabilities, cpu, memory):
        payload = {
            'resource': 'task_type',
            'command': 'create',
            'detail': {
                'task_type': task_type,
                'task_version': task_version,
                'source_image': source_image,
                'capabilities': capabilities,
                'cpu': cpu,
                'memory': memory
            }
        }
        create_task_type_response = self.post(self.manage_api_endpoint, payload)
        return create_task_type_response

    def delete_task_type(self, task_type):
        payload = {
            'resource': 'task_type',
            'command': 'delete',
            'detail': {'task_type': task_type}
        }
        delete_task_type_response = self.post(self.manage_api_endpoint, payload)
        return delete_task_type_response

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

    def update_user(self, user_id, new_user_id=None, admin=None, reset_keys=None):
        detail = {'user_id': user_id}
        if admin:
            detail['admin'] = admin
        if reset_keys:
            detail['reset_keys'] = reset_keys
        if new_user_id:
            detail['new_user_id'] = new_user_id
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
        decoded_file = base64.b64decode(get_file_response['file_contents'])
        get_file_response['file_contents'] = decoded_file
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

    def list_domains(self):
        payload = {
            'resource': 'domain',
            'command': 'list'
        }
        list_domains_response = self.post(self.manage_api_endpoint, payload)
        return list_domains_response

    def get_domain(self, domain_name):
        payload = {
            'resource': 'domain',
            'command': 'get',
            'detail': {'domain_name': domain_name}
        }
        get_domain_response = self.post(self.manage_api_endpoint, payload)
        return get_domain_response

    def create_domain(self, domain_name, hosted_zone):
        payload = {
            'resource': 'domain',
            'command': 'create',
            'detail': {'domain_name': domain_name, 'hosted_zone': hosted_zone}
        }
        create_domain_response = self.post(self.manage_api_endpoint, payload)
        return create_domain_response

    def delete_domain(self, domain_name):
        payload = {
            'resource': 'domain',
            'command': 'delete',
            'detail': {'domain_name': domain_name}
        }
        delete_domain_response = self.post(self.manage_api_endpoint, payload)
        return delete_domain_response

    def run_task(self, task_name, task_type, task_host_name='None', task_domain_name='None', portgroups=['None'],
                 end_time='None'):
        payload = {
            'action': 'execute',
            'detail': {
                'task_name': task_name,
                'task_type': task_type,
                'task_host_name': task_host_name,
                'task_domain_name': task_domain_name,
                'portgroups': portgroups,
                'end_time': end_time
            }
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

    def get_task_results(self, task_name, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'task_name': task_name, 'start_time': start_time, 'end_time': end_time}
        }
        get_task_results_response = self.post(self.task_control_api_endpoint, payload)
        return get_task_results_response

    def get_filtered_task_results(self, task_name, instruct_command=None, instruct_instance=None, start_time=None, end_time=None):
        get_task_results_response = self.get_task_results(task_name, start_time, end_time)
        if 'queue' not in get_task_results_response:
            return get_task_results_response
        filtered_results = []
        if not instruct_command and not instruct_instance:
            for result in get_task_results_response['queue']:
                filtered_results.append(result)
        if instruct_command and not instruct_instance:
            for result in get_task_results_response['queue']:
                if result['instruct_command'] == instruct_command:
                    filtered_results.append(result)
        if instruct_instance and not instruct_command:
            for result in get_task_results_response['queue']:
                if result['instruct_instance'] == instruct_instance:
                    filtered_results.append(result)
        if instruct_command and instruct_instance:
            for result in get_task_results_response['queue']:
                if result['instruct_command'] == instruct_command and result['instruct_instance'] == instruct_instance:
                    filtered_results.append(result)
        del get_task_results_response['queue']
        get_task_results_response['queue'] = filtered_results
        return get_task_results_response

    def task_startup(self, task_name, task_type, task_host_name='None', task_domain_name='None', portgroups=['None'],
                 end_time='None'):
        self.run_task(task_name, task_type, task_host_name, task_domain_name, portgroups, end_time)
        task_status = None
        task_details = None
        while task_status != 'idle':
            t.sleep(5)
            task_details = self.get_task(task_name)
            task_status = task_details['task_status']
        return task_details

    def task_shutdown(self, task_name):
        command_finished = None
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_command = 'terminate'
        instruct_task_response = self.instruct_task(task_name, instruct_instance, instruct_command)
        if instruct_task_response['outcome'] != 'success':
            return instruct_task_response
        while not command_finished:
            instruct_results = self.get_task_results(task_name)
            for entry in instruct_results['queue']:
                if entry['instruct_command'] == instruct_command and entry['instruct_instance'] == instruct_instance:
                    command_finished = True
            if not command_finished:
                t.sleep(5)
        return 'task_shutdown completed.'

    def verify_task(self, task_name, task_type):
        task_list = self.list_tasks()
        for task in task_list['tasks']:
            if task_name == task['task_name']:
                task_details = self.get_task(task_name)
                if task_details['task_type'] == task_type and task_details['task_status'] != 'terminated':
                    return task
        else:
            return False

    def wait_for_idle_task(self, task_name):
        task_status = None
        task_details = None
        while task_status != 'idle':
            t.sleep(5)
            task_details = self.get_task(task_name)
            task_status = task_details['task_status']
        return task_details

    def interact_with_task(self, task_name, instruct_command, instruct_instance=None, instruct_args=None):
        results = None
        if not instruct_instance:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        interaction = self.instruct_task(task_name, instruct_instance, instruct_command, instruct_args)
        if interaction['outcome'] == 'success':
            while not results:
                command_results = self.get_task_results(task_name)
                if 'queue' in command_results:
                    for entry in command_results['queue']:
                        if entry['instruct_command'] == instruct_command and entry[
                            'instruct_instance'] == instruct_instance:
                            results = json.loads(entry['instruct_command_output'])
                if not results:
                    t.sleep(5)
        else:
            return interaction
        return results
    
    def verify_agent(self, task_name, agent_name):
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_command = 'get_agents'
        instruct_args = {'Name': agent_name}
        agents_list = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        for agent in agents_list['agents']:
            if agent_name == agent['name']:
                return agent
            else:
                return False

    def execute_agent_shell_command(self, task_name, agent_name, command, wait_for_results=True, completion_string=None):
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_args = {'Name': agent_name, 'command': command}
        command_response = self.interact_with_task(task_name, 'agent_shell_command', instruct_instance, instruct_args)
        if command_response['outcome'] == 'success':
            command_task_id = command_response['message']['taskID']
        else:
            return command_response
        if wait_for_results:
            try:
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    instruct_args = {'Name': agent_name, 'task_id': command_task_id}
                    command_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_instance, instruct_args)
                    if command_results['outcome'] == 'success' and command_results['results']:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(command_results['results'].encode())).decode())
                        if tmp_results['results'] is not None:
                            if completion_string is not None and completion_string in tmp_results['results']:
                                results = tmp_results['results']
                            if completion_string is None:
                                results = tmp_results['results']
                    else:
                        results = f'get_shell_command_results for execute_agent_shell_command failed.\nget_shell_command_results response: {command_results}'
                    if not results:
                        t.sleep(10)
                return results
            except Exception as e:
                return f'unable to retrieve results for agent task ID {command_task_id} with error: {e}'
        else:
            return command_response
    
    def execute_agent_module(self, task_name, agent_name, module, module_args, wait_for_results=True, completion_string=None):
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_args = {'Agent': agent_name, 'Name': module}
        for k, v in module_args.items():
            instruct_args[k] = v
        module_response = self.interact_with_task(task_name, 'execute_module', instruct_instance, instruct_args)
        if module_response['outcome'] == 'success':
            module_task_id = module_response['message']['taskID']
        else:
            return module_response
        if wait_for_results:
            try:
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    instruct_args = {'Name': agent_name, 'task_id': module_task_id}
                    module_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_instance, instruct_args)
                    if module_results['outcome'] == 'success' and module_results['results']:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(module_results['results'].encode())).decode())
                        if tmp_results['results'] is not None and 'Job started:' not in tmp_results['results']:
                            if completion_string is not None and completion_string in tmp_results['results']:
                                results = tmp_results['results']
                            if completion_string is None:
                                results = tmp_results['results']
                    else:
                        results = f'get_shell_command_results for execute_agent_module failed.\nget_shell_command_results response: {module_results}'
                    if not results:
                        t.sleep(10)
                return results
            except Exception as e:
                return f'unable to retrieve results for agent task ID {module_task_id} with error: {e}'
        else:
            return module_response
    
    def get_agent_results(self, task_name, agent_name, task_id):
        instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_args = {'Name': agent_name, 'task_id': task_id}
        agent_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_instance, instruct_args)
        if agent_results['results']:
            tmp_results = json.loads(zlib.decompress(base64.b64decode(agent_results['results'].encode())).decode())
            results = tmp_results['results']
        else:
            results = agent_results
        return results

    def wait_for_c2(self, task_name):
        results = None
        existing_agents = []
        get_existing_agents = self.get_task_results(task_name)
        if 'queue' in get_existing_agents:
            for get_existing_agent in get_existing_agents['queue']:
                instruct_command = get_existing_agent['instruct_command']
                if instruct_command == 'agent_status_monitor' or instruct_command == 'session_status_monitor':
                    instruct_command_output = json.loads(get_existing_agent['instruct_command_output'])
                    existing_agents.append(instruct_command_output['agent_info']['name'])
        while not results:
            command_results = self.get_task_results(task_name)
            if 'queue' in command_results:
                for command_result in command_results['queue']:
                    instruct_command = command_result['instruct_command']
                    if instruct_command == 'agent_status_monitor' or instruct_command == 'session_status_monitor':
                        instruct_command_output = json.loads(command_result['instruct_command_output'])
                        if instruct_command_output['agent_info']['name'] not in existing_agents:
                            results = instruct_command_output
            if not results:
                t.sleep(5)
        return results

    def register_task(self, task_name, task_context, task_type, task_version, attack_ip, local_ip):
        payload = {
            'command': 'register_task',
            'detail': {
                'task_name': task_name,
                'task_context': task_context,
                'task_type': task_type,
                'task_version': task_version,
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
                    decoded_file = base64.b64decode(get_file_response['file_contents'])
                    new_file = open(f'{sync_path}/{f}', 'wb')
                    new_file.write(decoded_file)
                    new_file.close()
        if sync_direction == 'sync_to_workspace':
            for root, subdirs, files in os.walk(sync_path):
                if files:
                    for file_name in files:
                        file_list.append(file_name)
                        file_path = os.path.join(root, file_name)
                        f = open(file_path, 'rb')
                        file_contents = f.read()
                        encoded_file = base64.b64encode(file_contents).decode()
                        f.close()
                        payload = {
                            'resource': 'workspace', 'command': 'create', 'detail': {
                                'filename': file_name, 'file_contents': encoded_file
                            }
                        }
                        self.post(self.manage_api_endpoint, payload)
        return file_list
