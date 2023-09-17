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

    def list_triggers(self):
        payload = {
            'resource': 'trigger',
            'command': 'list'
        }
        list_triggers_response = self.post(self.manage_api_endpoint, payload)
        return list_triggers_response

    def get_trigger(self, trigger_name):
        payload = {
            'resource': 'trigger',
            'command': 'get',
            'detail': {'trigger_name': trigger_name}
        }
        get_trigger_response = self.post(self.manage_api_endpoint, payload)
        return get_trigger_response

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
        create_trigger_response = self.post(self.manage_api_endpoint, payload)
        return create_trigger_response
    
    def delete_trigger(self, trigger_name):
        payload = {
            'resource': 'trigger',
            'command': 'delete',
            'detail': {'trigger_name': trigger_name}
        }
        delete_trigger_response = self.post(self.manage_api_endpoint, payload)
        return delete_trigger_response
    
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

    def create_user(self, user_id, admin=None, remote_task=None, task_name=None):
        payload = {
            'resource': 'user',
            'command': 'create',
            'detail': {'user_id': user_id, 'admin': admin, 'remote_task': remote_task, 'task_name': task_name}
        }
        create_user_response = self.post(self.manage_api_endpoint, payload)
        return create_user_response

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

    def list_files(self, path=None):
        payload = {
            'resource': 'workspace',
            'command': 'list',
            'detail': {}
        }
        if path:
            payload['detail']['path'] = path
        list_files_response = self.post(self.manage_api_endpoint, payload)
        return list_files_response

    def get_file(self, path, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'get',
            'detail': {'path': path, 'filename': file_name}
        }
        get_file_response = self.post(self.manage_api_endpoint, payload)
        decoded_file = base64.b64decode(get_file_response['file_contents'])
        get_file_response['file_contents'] = decoded_file
        return get_file_response

    def create_file(self, path, file_name, raw_file):
        encoded_file = base64.b64encode(raw_file).decode()
        payload = {
            'resource': 'workspace',
            'command': 'create',
            'detail': {'path': path, 'filename': file_name, 'file_contents': encoded_file}
        }
        create_file_response = self.post(self.manage_api_endpoint, payload)
        return create_file_response

    def delete_file(self, path, file_name):
        payload = {
            'resource': 'workspace',
            'command': 'delete',
            'detail': {'path': path, 'filename': file_name}
        }
        delete_file_response = self.post(self.manage_api_endpoint, payload)
        return delete_file_response

    def list_playbooks(self, playbook_name_contains='', playbook_status='all'):
        payload = {
            'resource': 'playbook',
            'command': 'list',
            'detail': {'playbook_name_contains': playbook_name_contains, 'playbook_status': playbook_status}
        }
        list_playbooks_response = self.post(self.manage_api_endpoint, payload)
        return list_playbooks_response
    
    def get_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'get',
            'detail': {'playbook_name': playbook_name}
        }
        get_playbook_response = self.post(self.manage_api_endpoint, payload)
        return get_playbook_response
    
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
        create_playbook_response = self.post(self.manage_api_endpoint, payload)
        return create_playbook_response
    
    def delete_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'delete',
            'detail': {'playbook_name': playbook_name}
        }
        delete_playbook_response = self.post(self.manage_api_endpoint, payload)
        return delete_playbook_response
    
    def kill_playbook(self, playbook_name):
        payload = {
            'resource': 'playbook',
            'command': 'kill',
            'detail': {'playbook_name': playbook_name}
        }
        kill_playbook_response = self.post(self.manage_api_endpoint, payload)
        return kill_playbook_response
    
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
        run_playbook_response = self.post(self.playbook_operator_control_api_endpoint, payload)
        return run_playbook_response
    
    def get_playbook_results(self, playbook_name, operator_command=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'playbook_name': playbook_name, 'start_time': start_time, 'end_time': end_time}
        }
        get_playbook_results_response = self.post(self.playbook_operator_control_api_endpoint, payload)
        if 'queue' not in get_playbook_results_response:
            return get_playbook_results_response
        filtered_results = []
        if not operator_command:
            for result in get_playbook_results_response['queue']:
                filtered_results.append(result)
        if operator_command:
            for result in get_playbook_results_response['queue']:
                if result['operator_command'] == operator_command:
                    filtered_results.append(result)
        del get_playbook_results_response['queue']
        get_playbook_results_response['queue'] = filtered_results
        return get_playbook_results_response
    
    def list_playbook_types(self):
        payload = {
            'resource': 'playbook_type',
            'command': 'list'
        }
        list_playbook_types_response = self.post(self.manage_api_endpoint, payload)
        return list_playbook_types_response

    def get_playbook_type(self, playbook_type):
        payload = {
            'resource': 'playbook_type',
            'command': 'get',
            'detail': {'playbook_type': playbook_type}
        }
        get_playbook_type_response = self.post(self.manage_api_endpoint, payload)
        return get_playbook_type_response

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
        create_playbook_type_response = self.post(self.manage_api_endpoint, payload)
        return create_playbook_type_response

    def delete_playbook_type(self, playbook_type):
        payload = {
            'resource': 'playbook_type',
            'command': 'delete',
            'detail': {'playbook_type': playbook_type}
        }
        delete_playbook_type_response = self.post(self.manage_api_endpoint, payload)
        return delete_playbook_type_response
    
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
    
    def list_listeners(self):
        payload = {
            'resource': 'listener',
            'command': 'list'
        }
        list_listeners_response = self.post(self.manage_api_endpoint, payload)
        return list_listeners_response

    def get_listener(self, listener_name):
        payload = {
            'resource': 'listener',
            'command': 'get',
            'detail': {'listener_name': listener_name}
        }
        get_listener_response = self.post(self.manage_api_endpoint, payload)
        return get_listener_response

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
        create_listener_response = self.post(self.manage_api_endpoint, payload)
        return create_listener_response

    def delete_listener(self, listener_name):
        payload = {
            'resource': 'listener',
            'command': 'delete',
            'detail': {'listener_name': listener_name}
        }
        delete_listener_response = self.post(self.manage_api_endpoint, payload)
        return delete_listener_response

    def list_workspace_get_urls(self, filename=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'list',
            'detail': {}
        }
        if filename:
            payload['detail']['filename'] = filename
        list_workspace_get_urls_response = self.post(self.workspace_access_get_api_endpoint, payload)
        return list_workspace_get_urls_response

    def get_workspace_get_url(self, filename):
        payload = {
            'resource': 'workspace_access',
            'command': 'get',
            'detail': {'filename': filename}
        }
        get_workspace_get_url_response = self.post(self.workspace_access_get_api_endpoint, payload)
        return get_workspace_get_url_response

    def create_workspace_get_url(self, filename, expiration=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'create',
            'detail': {
                'filename': filename
            }
        }
        if expiration:
            payload['detail']['expiration'] = expiration
        create_workspace_get_url_response = self.post(self.workspace_access_get_api_endpoint, payload)
        return create_workspace_get_url_response

    def list_workspace_put_urls(self, path=None, filename=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'list',
            'detail': {}
        }
        if path:
            payload['detail']['path'] = path
        if filename:
            payload['detail']['filename'] = filename
        list_workspace_put_urls_response = self.post(self.workspace_access_put_api_endpoint, payload)
        return list_workspace_put_urls_response

    def get_workspace_put_url(self, path, filename):
        payload = {
            'resource': 'workspace_access',
            'command': 'get',
            'detail': {'path': path, 'filename': filename}
        }
        get_workspace_put_url_response = self.post(self.workspace_access_put_api_endpoint, payload)
        return get_workspace_put_url_response

    def create_workspace_put_url(self, path, filename, expiration=None):
        payload = {
            'resource': 'workspace_access',
            'command': 'create',
            'detail': {
                'path': path,
                'filename': filename
            }
        }
        if expiration:
            payload['detail']['expiration'] = expiration
        create_workspace_put_url_response = self.post(self.workspace_access_put_api_endpoint, payload)
        return create_workspace_put_url_response
    
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

    def get_task_results(self, task_name, instruct_command=None, instruct_instance=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'task_name': task_name, 'start_time': start_time, 'end_time': end_time}
        }
        get_task_results_response = self.post(self.task_control_api_endpoint, payload)
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
        run_task_response = self.run_task(task_name, task_type, task_host_name, task_domain_name, portgroups, end_time)
        if run_task_response['outcome'] != 'success':
            return run_task_response
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
        instruct_id = instruct_task_response['instruct_id']
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
    
    def run_session_command(self, task_name, session_id, session_command, end_strings=None, timeout=None, timeout_exception=None, instruct_instance=None):
        instruct_command = 'run_session_command'
        instruct_args = {'session_id': session_id, 'session_command': session_command, 'end_strings': end_strings, 'timeout': timeout, 'timeout_exception': timeout_exception}
        run_session_command_response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return run_session_command_response
    
    def run_session_shell_command(self, task_name, session_id, session_shell_command, wait_time=None, instruct_instance=None):
        instruct_command = 'run_session_shell_command'
        instruct_args = {'session_id': session_id, 'session_shell_command': session_shell_command, 'wait_time': wait_time}
        run_session_command_response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return run_session_command_response
    
    def kill_session(self, task_name, session_id, instruct_instance=None):
        instruct_command = 'kill_session'
        instruct_args = {'session_id': session_id}
        run_session_command_response = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        return run_session_command_response

    def get_agents(self, task_name):
        instruct_command = 'get_agents'
        agents_list = self.interact_with_task(task_name, instruct_command)
        return agents_list

    def verify_agent(self, task_name, agent_name, instruct_instance=None):
        instruct_command = 'get_agents'
        instruct_args = {'Name': agent_name}
        agents_list = self.interact_with_task(task_name, instruct_command, instruct_instance, instruct_args)
        for agent in agents_list['agents']:
            if agent_name == agent['name']:
                return agent
            else:
                return False

    def execute_agent_shell_command(self, task_name, agent_name, command, wait_for_results=None, beginning_string=None, completion_string=None, instruct_instance=None):
        if instruct_instance is None:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_args = {'Name': agent_name, 'command': command}
        command_response = self.interact_with_task(task_name, 'execute_agent_shell_command', instruct_instance, instruct_args)
        if command_response['outcome'] == 'success':
            command_task_id = command_response['execute_agent_shell_command']['taskID']
        else:
            return command_response
        if wait_for_results and wait_for_results.lower() != 'false':
            try:
                outcome = None
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    instruct_args = {'Name': agent_name, 'task_id': command_task_id}
                    command_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_instance, instruct_args)
                    if command_results['outcome'] == 'success' and command_results['get_shell_command_results']:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(command_results['get_shell_command_results'].encode())).decode())
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
                        results = f'get_shell_command_results for execute_agent_shell_command failed with error: {command_results}'
                    if not results:
                        t.sleep(10)
                output = {'outcome': outcome, 'execute_agent_shell_command': results}
                return output
            except Exception as e:
                outcome = 'failed'
                results = f'unable to retrieve results for agent task ID {command_task_id} with error: {e}'
                output = {'outcome': outcome, 'execute_agent_shell_command': results}
                return output
        else:
            return command_response
    
    def execute_agent_module(self, task_name, agent_name, module, module_args=None, wait_for_results=None, beginning_string=None, completion_string=None, instruct_instance=None):
        if instruct_instance is None:
            instruct_instance = ''.join(random.choice(string.ascii_letters) for i in range(6))
        instruct_args = {'Agent': agent_name, 'Name': module}
        if module_args:
            for k, v in module_args.items():
                instruct_args[k] = v
        module_response = self.interact_with_task(task_name, 'execute_agent_module', instruct_instance, instruct_args)
        if module_response['outcome'] == 'success':
            module_task_id = module_response['execute_agent_module']['taskID']
        else:
            return module_response
        if wait_for_results and wait_for_results.lower() != 'false':
            try:
                outcome = None
                results = None
                while not results:
                    self.wait_for_idle_task(task_name)
                    instruct_args = {'Name': agent_name, 'task_id': module_task_id}
                    module_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_instance, instruct_args)
                    if module_results['outcome'] == 'success' and module_results['get_shell_command_results']:
                        tmp_results = json.loads(zlib.decompress(base64.b64decode(module_results['get_shell_command_results'].encode())).decode())
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
                        results = f'get_shell_command_results for execute_agent_module failed with error: {module_results}'
                    if not results:
                        t.sleep(10)
                output = {'outcome': outcome, 'execute_agent_module': results}
                return output
            except Exception as e:
                outcome = 'failed'
                results = f'unable to retrieve results for agent task ID {module_task_id} with error: {e}'
                output = {'outcome': outcome, 'execute_agent_module': results}
                return output
        else:
            return module_response
    
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
        execute_trigger_response = self.post(self.trigger_executor_api_endpoint, payload)
        return execute_trigger_response
    
    def get_trigger_results(self, trigger_name, filter_command=None, execute_command=None, start_time=None, end_time=None):
        payload = {
            'action': 'get_results',
            'detail': {'trigger_name': trigger_name, 'start_time': start_time, 'end_time': end_time}
        }
        get_trigger_results_response = self.post(self.trigger_executor_api_endpoint, payload)
        if 'queue' not in get_trigger_results_response:
            return get_trigger_results_response
        filtered_results = []
        if not execute_command and not filter_command:
            for result in get_trigger_results_response['queue']:
                filtered_results.append(result)
        if filter_command and not execute_command:
            for result in get_trigger_results_response['queue']:
                if result['filter_command'] == filter_command:
                    filtered_results.append(result)
        if execute_command and not filter_command:
            for result in get_trigger_results_response['queue']:
                if result['execute_command'] == execute_command:
                    filtered_results.append(result)
        if filter_command and execute_command:
            for result in get_trigger_results_response['queue']:
                if result['filter_command'] == filter_command and result['execute_command'] == execute_command:
                    filtered_results.append(result)
        del get_trigger_results_response['queue']
        get_trigger_results_response['queue'] = filtered_results
        return get_trigger_results_response
    
    def get_agent_task_ids(self, task_name, agent_name):
        instruct_args = {'Name': agent_name}
        agent_task_ids = self.interact_with_task(task_name, 'get_task_id_list', instruct_args=instruct_args)
        if 'task_id_list' in agent_task_ids:
            return agent_task_ids['task_id_list']
        else:
            return agent_task_ids

    def get_agent_results(self, task_name, agent_name, task_id):
        instruct_args = {'Name': agent_name, 'task_id': task_id}
        agent_results = self.interact_with_task(task_name, 'get_shell_command_results', instruct_args=instruct_args)
        if 'results' in agent_results and agent_results['results']:
            tmp_results = json.loads(zlib.decompress(base64.b64decode(agent_results['results'].encode())).decode())
            results = tmp_results['results']
        else:
            results = []
        return results

    def wait_for_c2(self, task_name, time_skew=0):
        results = None
        existing_c2 = []
        time_skew_datetime = datetime.datetime.utcnow() - datetime.timedelta(minutes=int(time_skew))
        time_skew_string = time_skew_datetime.strftime('%m/%d/%Y %H:%M:%S')
        get_task_results_response = self.get_task_results(task_name, end_time=time_skew_string)
        if 'queue' in get_task_results_response:
            for task_result in get_task_results_response['queue']:
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
                                'filename': file_name, 'file_contents': encoded_file
                            }
                        }
                        self.post(self.manage_api_endpoint, payload)
        return file_list
