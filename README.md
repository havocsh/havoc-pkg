Havoc.sh provides on-demand, cloud hosted attack infrastructure that is API based, automation friendly, massively scalable, collaborative and reportable. This Python3 library provides the base functionality for interacting with the havoc.sh REST API.

### The basics

To install the havoc library:

```
pip install havoc
```

To use the havoc library:
 
```
import havoc

api_region='<aws-region>' # The AWS region for your havoc.sh deployment
api_domain_name='<domain-name>' # The domain name for your havoc.sh REST API
api_key='<api-key>' # The API key for your havoc.sh user
secret='<secret>' # The secret that accompanies your API key
```

Setup the connection:

```
h = havoc.Connect(api_region, api_domain_name, api_key, secret)
```

Post a request to the REST API:
```
uri='<uri>' # The full URI including domain-name and api-endpoint for the REST API call you want to make
payload='<payload>' # The python dictionary containing the instructions for the REST API call you want to make
h.post(uri, payload)
```

### Examples

#### Managing task types
List task types:
```
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'task_type',
    'command': 'list'
}
h.post(uri, payload)
```

#### Manage portgroups
List portgroups:
```
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'list'
}
h.post(uri, payload)
```

Get portgroup details:
```
portgroup_name = 'web'
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'get',
    'detail': {
        'portgroup_name': portgroup_name
    }
}
h.post(uri, payload)
```

Create a portgroup:
```
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'create',
    'detail': {
        'portgroup_name': 'web',
        'portgroup_description': 'standard web ports'
    }
}
h.post(uri, payload)
```

Add a rule to a portgroup:
```
portgroup_name = 'web'
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'update',
    'detail': {
        'portgroup_name': portgroup_name,
        'portgroup_action': 'add',
        'ip_ranges': [
            {
                'CidrIp': '1.2.3.4/32'
            }
        ],
        'port': 80,
        'ip_protocol': 'tcp'
    }
}
h.post(uri, payload)
```

Remove a rule from a portgroup:
```
portgroup_name = 'web'
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'update',
    'detail': {
        'portgroup_name': portgroup_name,
        'portgroup_action': 'remove',
        'ip_ranges': [
            {
                'CidrIp': '1.2.3.4/32'
            }
        ],
        'port': 80,
        'ip_protocol': 'tcp'
    }
}
h.post(uri, payload)
```

Delete a portgroup:
```
portgroup_name = 'web'
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'portgroup',
    'command': 'delete',
    'detail': {
        'portgroup_name': portgroup_name
    }
}
h.post(uri, payload)
```

#### Manage tasks
List tasks:
```
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'task',
    'command': 'list'
}
h.post(uri, payload)
```

Force kill a task:
```
task_name = 'nmap-test'
uri='https://havoc-my-campaign-api.example.com/manage'
payload = {
    'resource': 'task',
    'command': 'kill',
    'detail': {
        'task_name': task_name
    }
}
h.post(uri, payload)
```

#### Run and interact with tasks
Execute an NMAP task:
```
uri='https://havoc-my-campaign-api.example.com/task_control'
payload = {
    'action': 'execute',
    'detail': {
        'task_type': 'nmap',
        'task_name': 'nmap-test',
        'end_time': 'None'
    }
}
h.post(uri, payload)
```

Run a basic NMAP Port Scan for port 80:
```
task_name = 'nmap-test'
target = '<IP address to scan>'
uri='https://havoc-my-campaign-api.example.com/task_control'
payload={
    'action': 'interact',
    'detail': {
        'task_name': task_name,
        'instruct_instance': 'nmap1',
        'instruct_command': 'run_scan',
        'instruct_args': {
            'options': '-A -T4 -Pn -p 80',
            'target': target
        }
    }
}
h.post(uri, payload)
```

Kill an NMAP task:
```
task_name = 'nmap-test'
uri='https://havoc-my-campaign-api.example.com/task_control'
payload = {
    'action': 'interact',
    'detail': {
        'task_name': task_name,
        'instruct_command': 'terminate'
    }
}
h.post(uri, payload)
```
