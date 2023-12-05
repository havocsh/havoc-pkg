# Copyright 2020 Havoc Inc. or its affiliates. All Rights Reserved.

# Licensed under the GNU General Public Licnese v3.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import os, re, zlib, random, string, json, datetime, hashlib, hmac, requests, base64
import time as t


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key(key, date_stamp, region, host):
    k_date = sign(('havoc' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_signing = sign(k_region, host)
    return k_signing


class Connect:

    def __init__(self, region, api_domain_name, api_key, secret, api_version=None):
        self.region = region
        self.api_domain_name = api_domain_name
        self.api_key = api_key
        self.secret = secret
        self.api_version = api_version
        self.__remote_api_endpoint = None
        self.__manage_api_endpoint = None
        self.__task_control_api_endpoint = None
        self.__playbook_operator_control_api_endpoint = None
        self.__trigger_executor_api_endpoint = None
        self.__workspace_access_get_api_endpoint = None
        self.__workspace_access_put_api_endpoint = None

    @property
    def remote_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc/remote-task'
        elif 'amazonaws.com' in self.api_domain_name:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/remote-task'
        else:
            self.__remote_api_endpoint = f'https://{self.api_domain_name}/remote-task'
        return self.__remote_api_endpoint

    @property
    def manage_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/havoc/manage'
        elif 'amazonaws.com' in self.api_domain_name:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/manage'
        else:
            self.__manage_api_endpoint = f'https://{self.api_domain_name}/manage'
        return self.__manage_api_endpoint

    @property
    def task_control_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__task_control_api_endpoint = f'https://{self.api_domain_name}/havoc/task-control'
        elif 'amazonaws.com' in self.api_domain_name:
            self.__task_control_api_endpoint = f'https://{self.api_domain_name}/havoc_sh/task-control'
        else:
            self.__task_control_api_endpoint = f'https://{self.api_domain_name}/task-control'
        return self.__task_control_api_endpoint
    
    @property
    def playbook_operator_control_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__playbook_operator_control_api_endpoint = f'https://{self.api_domain_name}/havoc/playbook-operator-control'
        else:
            self.__playbook_operator_control_api_endpoint = f'https://{self.api_domain_name}/playbook-operator-control'
        return self.__playbook_operator_control_api_endpoint
    
    @property
    def trigger_executor_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__trigger_executor_api_endpoint = f'https://{self.api_domain_name}/havoc/trigger-executor'
        else:
            self.__trigger_executor_api_endpoint = f'https://{self.api_domain_name}/trigger-executor'
        return self.__trigger_executor_api_endpoint

    @property
    def workspace_access_get_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__workspace_access_get_api_endpoint = f'https://{self.api_domain_name}/havoc/workspace-access-get'
        else:
            self.__workspace_access_get_api_endpoint = f'https://{self.api_domain_name}/workspace-access-get'
        return self.__workspace_access_get_api_endpoint
    
    @property
    def workspace_access_put_api_endpoint(self):
        if 'amazonaws.com' in self.api_domain_name and self.api_version:
            self.__workspace_access_put_api_endpoint = f'https://{self.api_domain_name}/havoc/workspace-access-put'
        else:
            self.__workspace_access_put_api_endpoint = f'https://{self.api_domain_name}/workspace-access-put'
        return self.__workspace_access_put_api_endpoint

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
            if r.text:
                return json.loads(r.text)
            return err.response.text

    def create_deployment(self, deployment_version, deployment_admin_email, results_queue_expiration, api_domain_name, api_region,
                          enable_task_results_logging, task_results_logging_cwlogs_group, enable_playbook_results_logging,
                          playbook_results_logging_cwlogs_group, tfstate_s3_bucket, tfstate_s3_key, tfstate_s3_region, tfstate_dynamodb_table):
        payload = {
            'resource': 'deployment',
            'command': 'create',
            'detail': {
                'deployment_version': deployment_version,
                'deployment_admin_email': deployment_admin_email,
                'results_queue_expiration': results_queue_expiration,
                'api_domain_name': api_domain_name,
                'api_region': api_region,
                'enable_task_results_logging': enable_task_results_logging,
                'task_results_logging_cwlogs_group': task_results_logging_cwlogs_group,
                'enable_playbook_results_logging': enable_playbook_results_logging,
                'playbook_results_logging_cwlogs_group': playbook_results_logging_cwlogs_group,
                'tfstate_s3_bucket': tfstate_s3_bucket,
                'tfstate_s3_key': tfstate_s3_key,
                'tfstate_s3_region': tfstate_s3_region,
                'tfstate_dynamodb_table': tfstate_dynamodb_table
            }
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def update_deployment(self, **kwargs):
        payload = {
            'resource': 'deployment',
            'command': 'update'
        }
        if kwargs:
            payload['detail'] = kwargs
        else:
            payload['detail'] = {}
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def get_deployment(self):
        payload = {
            'resource': 'deployment',
            'command': 'get',
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_tasks(self, task_name_contains='', task_status='running', task_type=None):
        payload = {
            'resource': 'task',
            'command': 'list',
            'detail': {'task_name_contains': task_name_contains, 'task_status': task_status}
        }
        if task_type:
            payload['detail']['task_type'] = task_type
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_task(self, task_name):
        payload = {
            'resource': 'task',
            'command': 'get',
            'detail': {'task_name': task_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def kill_task(self, task_name):
        payload = {
            'resource': 'task',
            'command': 'kill',
            'detail': {'task_name': task_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_task_types(self):
        payload = {
            'resource': 'task_type',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_task_type(self, task_type):
        payload = {
            'resource': 'task_type',
            'command': 'get',
            'detail': {'task_type': task_type}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

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
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_task_type(self, task_type):
        payload = {
            'resource': 'task_type',
            'command': 'delete',
            'detail': {'task_type': task_type}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_triggers(self):
        payload = {
            'resource': 'trigger',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_trigger(self, trigger_name):
        payload = {
            'resource': 'trigger',
            'command': 'get',
            'detail': {'trigger_name': trigger_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_trigger(self, trigger_name, schedule_expression, execute_command, execute_command_args=None, execute_command_timeout=None,
                       filter_command=None, filter_command_args=None, filter_command_timeout=None):
        payload = {
            'resource': 'trigger',
            'command': 'create',
            'detail': {
                'trigger_name': trigger_name, 
                'schedule_expression': schedule_expression,
                'execute_command': execute_command,
                'execute_command_args': execute_command_args,
                'execute_command_timeout': execute_command_timeout,
                'filter_command': filter_command,
                'filter_command_args': filter_command_args,
                'filter_command_timeout': filter_command_timeout
            }
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def delete_trigger(self, trigger_name):
        payload = {
            'resource': 'trigger',
            'command': 'delete',
            'detail': {'trigger_name': trigger_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def list_users(self):
        payload = {
            'resource': 'user',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_user(self, user_id):
        payload = {
            'resource': 'user',
            'command': 'get',
            'detail': {'user_id': user_id}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_user(self, user_id, admin=None, remote_task=None, task_name=None):
        payload = {
            'resource': 'user',
            'command': 'create',
            'detail': {'user_id': user_id, 'admin': admin, 'remote_task': remote_task, 'task_name': task_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def update_user(self, user_id, new_user_id=None, admin=None, remote_task=None, task_name=None, reset_keys=None):
        detail = {'user_id': user_id}
        if admin:
            detail['admin'] = admin
        if reset_keys:
            detail['reset_keys'] = reset_keys
        if new_user_id:
            detail['new_user_id'] = new_user_id
        if remote_task:
            detail['remote_task'] = remote_task
        if task_name:
            detail['task_name'] = task_name
        payload = {
            'resource': 'user',
            'command': 'update',
            'detail': detail
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_user(self, user_id):
        payload = {
            'resource': 'user',
            'command': 'delete',
            'detail': {'user_id': user_id}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_files(self, path=None):
        payload = {
            'resource': 'workspace',
            'command': 'list',
            'detail': {}
        }
        if path:
            payload['detail']['path'] = path
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_file(self, path, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'get',
            'detail': {'path': path, 'file_name': file_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        decoded_file = base64.b64decode(response['file_contents'])
        response['file_contents'] = decoded_file
        return response

    def create_file(self, path, file_name, raw_file):
        encoded_file = base64.b64encode(raw_file).decode()
        payload = {
            'resource': 'workspace',
            'command': 'create',
            'detail': {'path': path, 'file_name': file_name, 'file_contents': encoded_file}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_file(self, path, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'delete',
            'detail': {'path': path, 'file_name': file_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_playbooks(self, playbook_name_contains='', playbook_status='all'):
        payload = {
            'resource': 'playbook',
            'command': 'list',
            'detail': {'playbook_name_contains': playbook_name_contains, 'playbook_status': playbook_status}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def get_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'get',
            'detail': {'playbook_name': playbook_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def create_playbook(self, playbook_name, playbook_type, playbook_timeout, playbook_config):
        payload = {
            'resource': 'playbook',
            'command': 'create',
            'detail': {
                'playbook_name': playbook_name,
                'playbook_type': playbook_type,
                'playbook_timeout': playbook_timeout,
                'playbook_config': playbook_config
            }
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def delete_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'delete',
            'detail': {'playbook_name': playbook_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def kill_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'kill',
            'detail': {'playbook_name': playbook_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def run_playbook(self, playbook_name, playbook_type=None, playbook_config=None, playbook_timeout=None):
        payload = {
            'action': 'launch',
            'detail': {'playbook_name': playbook_name}
        }
        if playbook_type:
            payload['detail']['playbook_type'] = playbook_type
        if playbook_config:
            payload['detail']['playbook_config'] = playbook_config
        if playbook_timeout:
            payload['detail']['playbook_timeout'] = playbook_timeout
        response = self.post(self.playbook_operator_control_api_endpoint, payload)
        return response
    
    def get_playbook_results(self, playbook_name, operator_command=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'playbook_name': playbook_name, 'start_time': start_time, 'end_time': end_time}
        }
        response = self.post(self.playbook_operator_control_api_endpoint, payload)
        if 'queue' not in response:
            return response
        filtered_results = []
        if not operator_command:
            for result in response['queue']:
                filtered_results.append(result)
        if operator_command:
            for result in response['queue']:
                if result['operator_command'] == operator_command:
                    filtered_results.append(result)
        del response['queue']
        response['queue'] = filtered_results
        return response
    
    def list_playbook_types(self):
        payload = {
            'resource': 'playbook_type',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_playbook_type(self, playbook_type):
        payload = {
            'resource': 'playbook_type',
            'command': 'get',
            'detail': {'playbook_type': playbook_type}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_playbook_type(self, playbook_type, playbook_version, playbook_template):
        payload = {
            'resource': 'playbook_type',
            'command': 'create',
            'detail': {
                'playbook_type': playbook_type,
                'playbook_version': playbook_version,
                'playbook_template': playbook_template,
            }
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_playbook_type(self, playbook_type):
        payload = {
            'resource': 'playbook_type',
            'command': 'delete',
            'detail': {'playbook_type': playbook_type}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def list_portgroups(self):
        payload = {
            'resource': 'portgroup',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_portgroup(self, portgroup_name):
        payload = {
            'resource': 'portgroup',
            'command': 'get',
            'detail': {'portgroup_name': portgroup_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_portgroup(self, portgroup_name, portgroup_description):
        payload = {
            'resource': 'portgroup',
            'command': 'create',
            'detail': {'portgroup_name': portgroup_name, 'portgroup_description': portgroup_description}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

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
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_portgroup(self, portgroup_name):
        payload = {
            'resource': 'portgroup',
            'command': 'delete',
            'detail': {'portgroup_name': portgroup_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_domains(self):
        payload = {
            'resource': 'domain',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_domain(self, domain_name):
        payload = {
            'resource': 'domain',
            'command': 'get',
            'detail': {'domain_name': domain_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_domain(self, domain_name, hosted_zone):
        payload = {
            'resource': 'domain',
            'command': 'create',
            'detail': {'domain_name': domain_name, 'hosted_zone': hosted_zone}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_domain(self, domain_name):
        payload = {
            'resource': 'domain',
            'command': 'delete',
            'detail': {'domain_name': domain_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response
    
    def list_listeners(self):
        payload = {
            'resource': 'listener',
            'command': 'list'
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def get_listener(self, listener_name):
        payload = {
            'resource': 'listener',
            'command': 'get',
            'detail': {'listener_name': listener_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def create_listener(self, listener_name, listener_config, task_name, portgroups, host_name=None, domain_name=None):
        payload = {
            'resource': 'listener',
            'command': 'create',
            'detail': {
                'listener_name': listener_name,
                'listener_config': listener_config,
                'task_name': task_name,
                'portgroups': portgroups,
                'host_name': host_name,
                'domain_name': domain_name
            }
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def delete_listener(self, listener_name):
        payload = {
            'resource': 'listener',
            'command': 'delete',
            'detail': {'listener_name': listener_name}
        }
        response = self.post(self.manage_api_endpoint, payload)
        return response

    def list_workspace_get_urls(self, path=None, file_name=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'list',
            'detail': {}
        }
        if path:
            payload['detail']['path'] = path
        if file_name:
            payload['detail']['file_name'] = file_name
        response = self.post(self.workspace_access_get_api_endpoint, payload)
        return response

    def get_workspace_get_url(self, path, file_name):
        payload = {
            'resource': 'workspace_access',
            'command': 'get',
            'detail': {'path': path, 'file_name': file_name}
        }
        response = self.post(self.workspace_access_get_api_endpoint, payload)
        return response

    def create_workspace_get_url(self, path, file_name, expiration=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'create',
            'detail': {'path': path, 'file_name': file_name}
        }
        if expiration:
            payload['detail']['expiration'] = expiration
        response = self.post(self.workspace_access_get_api_endpoint, payload)
        return response

    def list_workspace_put_urls(self, path=None, file_name=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'list',
            'detail': {}
        }
        if path:
            payload['detail']['path'] = path
        if file_name:
            payload['detail']['file_name'] = file_name
        response = self.post(self.workspace_access_put_api_endpoint, payload)
        return response

    def get_workspace_put_url(self, path, file_name):
        payload = {
            'resource': 'workspace_access',
            'command': 'get',
            'detail': {'path': path, 'file_name': file_name}
        }
        response = self.post(self.workspace_access_put_api_endpoint, payload)
        return response

    def create_workspace_put_url(self, path, file_name, expiration=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'create',
            'detail': {'path': path, 'file_name': file_name}
        }
        if expiration:
            payload['detail']['expiration'] = expiration
        response = self.post(self.workspace_access_put_api_endpoint, payload)
        return response
    
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
        response = self.post(self.task_control_api_endpoint, payload)
        return response

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
        response = self.post(self.task_control_api_endpoint, payload)
        return response

    def get_task_results(self, task_name, instruct_command=None, instruct_instance=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'task_name': task_name, 'start_time': start_time, 'end_time': end_time}
        }
        response = self.post(self.task_control_api_endpoint, payload)
        if 'queue' not in response:
            return response
        filtered_results = []
        if not instruct_command and not instruct_instance:
            for result in response['queue']:
                filtered_results.append(result)
        if instruct_command and not instruct_instance:
            for result in response['queue']:
                if result['instruct_command'] == instruct_command:
                    filtered_results.append(result)
        if instruct_instance and not instruct_command:
            for result in response['queue']:
                if result['instruct_instance'] == instruct_instance:
                    filtered_results.append(result)
        if instruct_command and instruct_instance:
            for result in response['queue']:
                if result['instruct_command'] == instruct_command and result['instruct_instance'] == instruct_instance:
                    filtered_results.append(result)
        del response['queue']
        response['queue'] = filtered_results
        return response

    def task_startup(self, task_name, task_type, task_host_name='None', task_domain_name='None', portgroups=['None'],
                 end_time='None'):
        response = self.run_task(task_name, task_type, task_host_name, task_domain_name, portgroups, end_time)
        if response['outcome'] != 'success':
            return response
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
        response = self.instruct_task(task_name, instruct_instance, instruct_command)
        if response['outcome'] != 'success':
            return response
        instruct_id = response['instruct_id']
        while not command_finished:
            instruct_results = self.get_task_results(task_name)
            if 'queue' in instruct_results:
                for entry in instruct_results['queue']:
                    if entry['instruct_id'] == instruct_id and \
                    entry['instruct_command'] == instruct_command and \
                    entry['instruct_instance'] == instruct_instance:
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
            instruct_id = interaction['instruct_id']
            while not results:
                command_results = self.get_task_results(task_name)
                if 'queue' in command_results:
                    for entry in command_results['queue']:
                        if entry['instruct_id'] == instruct_id and \
                           entry['instruct_command'] == instruct_command and \
                           entry['instruct_instance'] == instruct_instance:
                            results = json.loads(entry['instruct_command_output'])
                if not results:
                    t.sleep(5)
        else:
            return interaction
        return results
    
    def run_metasploit_session_command(self, task_name, session_id, session_command, wait_time=None, instruct_instance=None):
        instruct_command = 'run_metasploit_session_command'
        instruct_args = {'session_id': session_id, 'metasploit_session_command': session_command, 'wait_time': wait_time}
        response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return response
    
    def run_metasploit_session_shell_command(self, task_name, session_id, session_shell_command, wait_time=None, instruct_instance=None):
        instruct_command = 'run_metasploit_session_shell_command'
        instruct_args = {'session_id': session_id, 'metasploit_session_shell_command': session_shell_command, 'wait_time': wait_time}
        response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return response
    
    def list_metasploit_sessions(self, task_name=None):
        sessions_list = []
        list_tasks_response = self.list_tasks(task_name_contains=task_name, task_type='metasploit')
        if len(list_tasks_response['tasks']) != 0:
            for task in list_tasks_response['tasks']:
                task_name=task['task_name']
                instruct_command = 'list_metasploit_sessions'
                list_sessions_response = self.interact_with_task(task_name, instruct_command)
                sessions_list.append({'task_name': task_name, instruct_command: list_sessions_response[instruct_command]})
        return sessions_list
    
    def kill_metasploit_session(self, task_name, session_id, instruct_instance=None):
        instruct_command = 'kill_metasploit_session'
        instruct_args = {'session_id': session_id}
        response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return response
    
    def verify_metasploit_session(self, task_name, session_id, instruct_instance=None):
        instruct_command = 'list_metasploit_sessions'
        response = self.interact_with_task(task_name, instruct_command, instruct_instance)
        for session in response[instruct_command]:
            if session_id == session['session_id']:
                return session
            else:
                return False

    def list_empire_agents(self, task_name=None):
        agents_list = []
        if task_name is None:
            list_tasks_response = self.list_tasks(task_name_contains=task_name, task_type='powershell_empire')
            if len(list_tasks_response['tasks']) != 0:
                for task in list_tasks_response['tasks']:
                    task_name=task['task_name']
                    instruct_command = 'list_empire_agents'
                    list_agents_response = self.interact_with_task(task_name, instruct_command)
                    agents_list.append({'task_name': task_name, instruct_command: list_agents_response[instruct_command]})
        else:
            list_agents_response = self.interact_with_task(task_name, instruct_command)
            agents_list.append({'task_name': task_name, instruct_command: list_agents_response[instruct_command]})
        return agents_list
    
    def kill_empire_agent(self, task_name, agent_name, instruct_instance=None):
        if instruct_instance is None:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_command = 'kill_empire_agent'
        instruct_args = {'Name': agent_name}
        response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return response

    def verify_empire_agent(self, task_name, agent_name, instruct_instance=None):
        instruct_command = 'list_empire_agents'
        instruct_args = {'Name': agent_name}
        response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        for agent in response[instruct_command]:
            if agent_name == agent['name']:
                return agent
            else:
                return False

    def list_empire_agent_task_ids(self, task_name, agent_name):
        instruct_args = {'Name': agent_name}
        agent_task_ids = self.interact_with_task(task_name, 'list_empire_agent_task_ids', instruct_args=instruct_args)
        if 'task_id_list' in agent_task_ids:
            return agent_task_ids['task_id_list']
        else:
            return agent_task_ids

    def get_empire_agent_results(self, task_name, agent_name, task_id):
        instruct_args = {'Name': agent_name, 'task_id': task_id}
        agent_results = self.interact_with_task(task_name, 'get_empire_agent_results', instruct_args=instruct_args)
        if 'results' in agent_results and agent_results['results']:
            tmp_results = json.loads(zlib.decompress(base64.b64decode(agent_results['results'].encode())).decode())
            results = tmp_results['results']
        else:
            results = []
        return results
    
    def execute_empire_agent_shell_command(self, task_name, agent_name, command, wait_for_results=None, beginning_string=None, completion_string=None, instruct_instance=None):
        if instruct_instance is None:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        orig_instruct_command = 'execute_empire_agent_shell_command'
        orig_instruct_args = {'Name': agent_name, 'command': command}
        response = self.interact_with_task(task_name, orig_instruct_command, instruct_instance, orig_instruct_args)
        if response['outcome'] == 'success':
            command_task_id = response[orig_instruct_command]['taskID']
        else:
            return response
        if wait_for_results and wait_for_results.lower() != 'false':
            try:
                outcome = None
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    res_instruct_command = 'get_empire_agent_results'
                    res_instruct_args = {'Name': agent_name, 'task_id': command_task_id}
                    command_results = self.interact_with_task(task_name, res_instruct_command, instruct_instance, res_instruct_args)
                    if command_results['outcome'] == 'success' and command_results[res_instruct_command]:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(command_results[res_instruct_command].encode())).decode())
                        if tmp_results['results'] is not None:
                            if beginning_string is not None and completion_string is not None:
                                re_string = re.compile('(' + beginning_string + '.*' + completion_string + ')')
                                re_results = re.search(re_string, tmp_results['results'])
                                if re_results:
                                    outcome = 'success'
                                    results = re_results.group(1)
                            elif completion_string is not None and completion_string in tmp_results['results']:
                                outcome = 'success'
                                results = tmp_results['results']
                            else:
                                outcome = 'success'
                                results = tmp_results['results']
                    else:
                        outcome = 'failed'
                        results = f'{res_instruct_command} for {orig_instruct_command} failed with error: {command_results}'
                    if not results:
                        t.sleep(10)
                output = {'outcome': outcome, orig_instruct_command: results}
                return output
            except Exception as e:
                outcome = 'failed'
                results = f'unable to retrieve results for agent task ID {command_task_id} with error: {e}'
                output = {'outcome': outcome, orig_instruct_command: results}
                return output
        else:
            return response

    def execute_empire_agent_module(self, task_name, agent_name, module, module_args=None, wait_for_results=None, beginning_string=None, completion_string=None, instruct_instance=None):
        if instruct_instance is None:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        orig_instruct_command = 'execute_empire_agent_module'
        orig_instruct_args = {'Agent': agent_name, 'Name': module}
        if module_args:
            for k, v in module_args.items():
                orig_instruct_args[k] = v
        response = self.interact_with_task(task_name, orig_instruct_command, instruct_instance, orig_instruct_args)
        if response['outcome'] == 'success':
            module_task_id = response[orig_instruct_command]['taskID']
        else:
            return response
        if wait_for_results and wait_for_results.lower() != 'false':
            try:
                outcome = None
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    res_instruct_command = 'get_empire_agent_results'
                    res_instruct_args = {'Name': agent_name, 'task_id': module_task_id}
                    module_results = self.interact_with_task(task_name, res_instruct_command, instruct_instance, res_instruct_args)
                    if module_results['outcome'] == 'success' and module_results[res_instruct_command]:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(module_results[res_instruct_command].encode())).decode())
                        if tmp_results['results'] is not None and 'Job started:' not in tmp_results['results']:
                            if beginning_string is not None and completion_string is not None:
                                re_string = re.compile('(' + beginning_string + '.*' + completion_string + ')')
                                re_results = re.search(re_string, tmp_results['results'])
                                if re_results:
                                    outcome = 'success'
                                    results = re_results.group(1)
                            elif completion_string is not None and completion_string in tmp_results['results']:
                                outcome = 'success'
                                results = tmp_results['results']
                            else:
                                outcome = 'success'
                                results = tmp_results['results']
                    else:
                        outcome = 'failed'
                        results = f'{res_instruct_command} for {orig_instruct_command} failed with error: {module_results}'
                    if not results:
                        t.sleep(10)
                output = {'outcome': outcome, orig_instruct_command: results}
                return output
            except Exception as e:
                outcome = 'failed'
                results = f'unable to retrieve results for agent task ID {module_task_id} with error: {e}'
                output = {'outcome': outcome, orig_instruct_command: results}
                return output
        else:
            return response
    
    def execute_trigger(self, trigger_name, execute_command, execute_command_args=None, execute_command_timeout=None, filter_command=None,
                        filter_command_args=None, filter_command_timeout=None):
        payload = {
            'action': 'execute_trigger',
            'detail': {
                'trigger_name': trigger_name,
                'execute_command': execute_command
            }
        }
        if execute_command_args:
            payload['detail']['execute_command_args'] = execute_command_args
        if execute_command_timeout:
            payload['detail']['execute_command_timeout'] = execute_command_timeout
        if filter_command:
            payload['detail']['filter_command'] = filter_command
        if filter_command_args:
            payload['detail']['filter_command_args'] = filter_command_args
        if filter_command_timeout:
            payload['detail']['filter_command_timeout'] = filter_command_timeout
        response = self.post(self.trigger_executor_api_endpoint, payload)
        return response
    
    def get_trigger_results(self, trigger_name, filter_command=None, execute_command=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'trigger_name': trigger_name, 'start_time': start_time, 'end_time': end_time}
        }
        response = self.post(self.trigger_executor_api_endpoint, payload)
        if 'queue' not in response:
            return response
        filtered_results = []
        if not execute_command and not filter_command:
            for result in response['queue']:
                filtered_results.append(result)
        if filter_command and not execute_command:
            for result in response['queue']:
                if result['filter_command'] == filter_command:
                    filtered_results.append(result)
        if execute_command and not filter_command:
            for result in response['queue']:
                if result['execute_command'] == execute_command:
                    filtered_results.append(result)
        if filter_command and execute_command:
            for result in response['queue']:
                if result['filter_command'] == filter_command and result['execute_command'] == execute_command:
                    filtered_results.append(result)
        del response['queue']
        response['queue'] = filtered_results
        return response

    def wait_for_c2(self, task_name, time_skew=0):
        results = None
        existing_c2 = []
        time_skew_datetime = datetime.datetime.utcnow() - datetime.timedelta(minutes=int(time_skew))
        time_skew_string = time_skew_datetime.strftime('%m/%d/%Y %H:%M:%S')
        response = self.get_task_results(task_name, end_time=time_skew_string)
        if 'queue' in response:
            for task_result in response['queue']:
                instruct_command = task_result['instruct_command']
                if instruct_command == 'agent_status_monitor' or instruct_command == 'session_status_monitor':
                    instruct_command_output = json.loads(task_result['instruct_command_output'])
                    if 'agent_info' in instruct_command_output:
                        existing_c2.append(instruct_command_output['agent_info']['name'])
                    if 'session_connected' in instruct_command_output:
                        existing_c2.append(instruct_command_output['session_id'])
        while not results:
            command_results = self.get_task_results(task_name, start_time=time_skew_string)
            if 'queue' in command_results:
                for command_result in command_results['queue']:
                    instruct_command = command_result['instruct_command']
                    if instruct_command == 'agent_status_monitor' or instruct_command == 'session_status_monitor':
                        instruct_command_output = json.loads(command_result['instruct_command_output'])
                        if 'agent_info' in instruct_command_output:
                            if instruct_command_output['agent_info']['name'] not in existing_c2:
                                results = instruct_command_output
                        if 'session_connected' in instruct_command_output:
                            if instruct_command_output['session_id'] not in existing_c2:
                                results = instruct_command_output
            if not results:
                t.sleep(5)
        return results

    def register_task(self, task_name, task_context, task_type, task_version, public_ip, local_ip):
        payload = {
            'command': 'register_task',
            'detail': {
                'task_name': task_name,
                'task_context': task_context,
                'task_type': task_type,
                'task_version': task_version,
                'public_ip': public_ip,
                'local_ip': local_ip
            }
        }

        response = self.post(self.remote_api_endpoint, payload)
        return response

    def get_commands(self, task_name):
        payload = {'command': 'get_commands', 'detail': {'task_name': task_name}}

        response = self.post(self.remote_api_endpoint, payload)
        return response

    def post_response(self, results):
        payload = {'command': 'post_results', 'results': results}

        response = self.post(self.remote_api_endpoint, payload)
        return response

    def sync_workspace(self, sync_direction, sync_path):
        file_list = []
        if sync_direction == 'sync_from_workspace':
            payload = {'resource': 'workspace', 'command': 'list'}
            list_response = self.post(self.manage_api_endpoint, payload)
            if 'files' in list_response:
                for f in list_response['files']:
                    file_list.append(f)
                    payload = {'resource': 'workspace', 'command': 'get', 'detail': {'file_name': f}}
                    get_file_response = self.post(self.manage_api_endpoint, payload)
                    decoded_file = base64.b64decode(get_file_response['file_contents'])
                    new_file = None
                    if os.name() == 'nt':
                        new_file = open(f'{sync_path}\\{f}', 'wb+')
                    else:
                        new_file = open(f'{sync_path}/{f}', 'wb+')
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
                                'file_name': file_name, 'file_contents': encoded_file
                            }
                        }
                        self.post(self.manage_api_endpoint, payload)
        return file_list
