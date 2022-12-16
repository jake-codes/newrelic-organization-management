import formatting
import graphql_queries

import csv
import glob
import json
import pdb
import requests
import yaml

from _shared.io_file import write_csv_file

def load_keys_file():
  with open('config.yml', 'r') as file:
    keys = yaml.safe_load(file)
    if not keys['NEW_RELIC_USER_API_KEY']:
        formatting.print_error('You must add a user api key to the config.yml')
    return keys

def _execute_graphql(graphql_string, key):
  # Graphql calls it 'cursor' instead of page
  try:
    # pdb.set_trace()
    headers = {'X-Api-Key': key, 'Content-Type': 'application/json'}
    data = {"query": graphql_string }
    data_json = json.dumps(data)
    response  = requests.post('https://api.newrelic.com/graphql', headers=headers, data=data_json)
    r_json = response.json()
    return r_json

  except Exception as e:
    formatting.print_error('Error executing graphql query for key: {}\nquery: {}'.format(key, query))
    pdb.set_trace()
    return None

def _get_cursored_query(query, cursor=None):
    cursor_txt = '' if not cursor else '(cursor: "{}")'.format(cursor)
    return query.replace('||CURSOR||', cursor_txt.format(cursor_txt))

def _query_until_cursor_empty(graphql_query, key, parse_results, parse_cursor):
    results = []
    next_cursor = None
    first_run = True
    while next_cursor or first_run:
        first_run = False
        query = _get_cursored_query(graphql_query, cursor=next_cursor)
        r_json = _execute_graphql(query, key)
        curr_results = parse_results(r_json)
        results = results + curr_results
        next_cursor = parse_cursor(r_json) if len(results) else None
    return results

def list_accounts(key):
    get_results = lambda r: r['data']['actor']['organization']['accountManagement']['managedAccounts']
    get_cursor = lambda r: None
    accounts = _query_until_cursor_empty(graphql_queries.LIST_ACCOUNTS_FOR_ORG, key, get_results, get_cursor)
    formatting.print_json(accounts, prefix='Accounts: ')
    return accounts

def list_groups(key, auth_id):
    auth_format = '(id: "{}")'.format(auth_id)
    query = graphql_queries.LIST_GROUPS_PER_AUTH_DOMAIN.replace('||AUTH_ID||', auth_format)
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains'][0]['groups']['groups']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains'][0]['groups']['nextCursor']
    groups = _query_until_cursor_empty(query, key, get_results, get_cursor)
    # if auth_id_optional:
    #     auth_domains = [x for x in auth_domains if x['id'] == auth_id_optional]
    # groups = [x['groups']['groups'] for x in auth_domains]
    formatting.print_json(groups, prefix='Groups: ')
    return groups

def delete_group(key, group_id):
    mutation = graphql_queries.DELETE_GROUP.replace('||GROUP_ID||', group_id)
    handled_exceptions = 'Group hsdsfsdfa'
    error_message = 'Could not delete group: {} .. key: {}'.format(str(group_id), key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message, handled_exceptions)
    return results

def list_roles(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['roles']['roles']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['roles']['nextCursor']
    roles = _query_until_cursor_empty(graphql_queries.LIST_AUTH_ROLES_QUERY, key, get_results, get_cursor)
    formatting.print_json(roles, prefix='Roles: ')
    return roles

def list_auth_domains(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['nextCursor']
    auth_domains = _query_until_cursor_empty(graphql_queries.LIST_AUTH_DOMAINS_QUERY, key, get_results, get_cursor)
    formatting.print_json(auth_domains, prefix='Auth Domains: ')
    return auth_domains

def list_users_for_auth_domains(key, auth_id):
    if not auth_id:
        formatting.print_error('Must include auth domain id to list users.')
    get_results = lambda r: r['data']['actor']['organization']['userManagement']['authenticationDomains']['authenticationDomains'][0]['users']['users']
    get_cursor = lambda r: r['data']['actor']['organization']['userManagement']['authenticationDomains']['authenticationDomains'][0]['users']['nextCursor']
    query = graphql_queries.LIST_USERS_FOR_AUTH_DOMAINS.replace('||AUTH_ID||', auth_id)
    users = _query_until_cursor_empty(query, key, get_results, get_cursor)
    formatting.print_json(users, prefix='Users: ')
    return users

def _execute_mutation_or_raise_error(mutation, key, error_message, handled_exceptions=''):
    r_json = _execute_graphql(mutation, key)
    if 'errors' in r_json:
        errors = ''
        try:
            errors = '{}\n{}'.format(error_message, r_json['errors'])
        except:
            pass
        if handled_exceptions and handled_exceptions in errors:
            formatting.print_warning('Handled exception: {}'.format(errors))
        else:
            formatting.print_error(errors)
            raise Exception(errors)
    return r_json

def create_group(key, name, auth_id):
    if not auth_id:
        formatting.print_error('Must include auth domain id to create group.')
    mutation = graphql_queries.CREATE_GROUP.replace('||AUTH_ID||', auth_id).replace('||GROUP_NAME||', name)
    error_message = 'Could not create group with name: {}, auth id: {}, key: {}'.format(name, auth_id, key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message)
    # pdb.set_trace()
    formatting.print_('Group created: {}.'.format(name))
    return results

def create_user(key, name, email, auth_id):
    if not auth_id or not name or not email:
        formatting.print_error('Must include name, email and auth id to create user ({},{},{}).'.format(name, email, auth_id))
    mutation = graphql_queries.CREATE_USER.replace('||AUTH_ID||', auth_id).replace('||NAME||', name).replace('||EMAIL||', email)
    error_message = 'Could not create user with name: {}, auth id: {}, email: {}, key: {}'.format(name, auth_id, email, key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message)
    formatting.print_('User created: {}.'.format(email))
    return results

def grant_group_access_to_role_for_account(key, group_id, account_id, role_id):
    if not group_id or not account_id or not role_id:
        formatting.print_error('Must include parameters to grant group access.')

    mutation = graphql_queries.GRANT_GROUP_ACCESS_TO_ACCOUNT_AND_ROLE.replace('||GROUP_ID||', group_id).replace('||ACCOUNT_ID||', str(account_id)).replace('||ROLE_ID||', role_id)
    print('\n{}\n'.format(mutation))
    error_message = 'Could not grant group access with group id: {}, account id: {}, role id: {}, key: {}'.format(group_id, account_id, role_id, key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message)
    formatting.print_('Access grant created for group.')
    return results

def get_roles_for_group(key, group_id):
    if not key or not group_id:
        formatting.print_error('Must include parameters to get roles for group.')

    def get_results(r):
        for d in r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains']:
            if len(d['groups']['groups']) and d['groups']['groups'][0]['id'] == group_id:
                return d['groups']['groups'][0]['roles']['roles']
    get_cursor = lambda r: None
    query = graphql_queries.LIST_ROLES_FOR_GROUP.replace('||GROUP_ID||', group_id)
    roles = _query_until_cursor_empty(query, key, get_results, get_cursor)
    formatting.print_json(roles, prefix='Roles: ')
    return roles

def copy_group_roles_to_new_account(key, group_to_copy_from_id, group_to_copy_to_id, account_id):
    if not group_to_copy_from_id or not account_id or not group_to_copy_to_id:
        formatting.print_error('Must include parameters to copy group rules.')
    role_ids = list(set([r['roleId'] for r in get_roles_for_group(key, group_to_copy_from_id)]))
    for role_id in role_ids:
        grant_group_access_to_role_for_account(key, group_to_copy_to_id, account_id, '{}'.format(role_id))

def add_users_to_groups(key, group_ids, user_ids):
    if not group_ids or not len(group_ids) or not user_ids or not len(user_ids) or not key:
        formatting.print_error('Must include parameters to add users to groups.')

    mutation = graphql_queries.ADD_USERS_TO_GROUPS.replace('||GROUP_IDS||', json.dumps(group_ids)).replace('||USER_IDS||', json.dumps(user_ids))
    handled_exceptions = 'Group has already been taken'
    error_message = 'Could not add users to groups: {} .. users:{} .. key: {}'.format(str(group_ids), str(user_ids), key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message, handled_exceptions)
    formatting.print_('User ({}) added to group ({}).'.format(group_ids, user_ids))
    return results

def _execute_scimapi(data, url_suffix, token, method='post'):
  # Graphql calls it 'cursor' instead of page
  try:
    # pdb.set_trace()
    headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
    data_json = json.dumps(data)
    url = 'https://scim-provisioning.service.newrelic.com/scim/v2/{}'.format(url_suffix)
    response = None
    if method == 'post':
        response  = requests.post(url, headers=headers, data=data_json)
    elif method == 'patch': 
        response  = requests.patch(url, headers=headers, data=data_json)
    elif method == 'put': 
        response  = requests.put(url, headers=headers, data=data_json)
    elif method == 'get':
        response  = requests.get(url, headers=headers)
    r_json = response.json()
    return r_json

  except Exception as e:
    formatting.print_error('Error executing scim query for key: {}url suffix: {}\nData: {}'.format(token, url_suffix, data))
    pdb.set_trace()
    raise

def load_csv(filename='user_upload.csv'):
    users = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            _row = dict(row)
            users.append(_row)
        return users

def _load_and_validate_users_from_csv(filename='user_upload.csv'):
    users = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            _row = dict(row)
            if 'Email' in _row and 'Name' in _row and 'User type' in _row:
                users.append(_row)
            else:
                error_message = '{} does not have the expected format for SCIM API: {}'.format(filename, row)
                formatting.print_error(error_message)
                raise Exception(error_message)
        return users

def create_v2_users_from_csv_scim(token):
    # NOTE:
    # 1) It assumes the CSV file was generated from within the V1 management URL (https://account.newrelic.com/accounts/<<RPM>>/users)
    # 2) It has the following fieldnames: 'Email', 'Name', 'User type'
    # 3) It does NOT automatically assign groups from this CSV

    users = _load_and_validate_users_from_csv()

    for user in users:
        email = user['Email']
        name_split = user['Name'].split(' ')
        first_name = name_split[0]
        last_name = name_split[len(name_split)-1]
        user_type = 'Basic User' if user['User type'] == 'basic' else 'Full User'
        response = create_user_via_scim(token, email, first_name, last_name, user_type)
        formatting.print_success('User added: {}'.format(email))

def create_user_via_scim(token, email, first_name, last_name, user_type):
    if user_type != 'Basic User' and user_type != 'Full User':
        raise Exception('Unrecognized User Type: {}'.format(user_type))

    payload = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:newrelic:2.0:User"
        ],
        "userName": email,
        "name": {
        "familyName": last_name,
        "givenName": first_name
        },
        "emails": [{
          "primary": True,
          "value": email
        }],
        "active": True,
        "timezone": "America/Los_Angeles",
        "urn:ietf:params:scim:schemas:extension:newrelic:2.0:User": {
          "nrUserType": user_type
        }
    }
    url_suffix = 'Users'
    return _execute_scimapi(payload, url_suffix, token)

def create_group_via_scim(token, group_name):
    payload = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": group_name
    }
    url_suffix = 'Groups'
    return _execute_scimapi(payload, url_suffix, token)

def get_users_via_scim(token):
    payload = None
    url_suffix = 'Users'
    return _execute_scimapi(payload, url_suffix, token, 'get')

def get_user_details_via_scim(token, user_id):
    payload = None
    url_suffix = 'Users/{}'.format(user_id)
    return _execute_scimapi(payload, url_suffix, token, 'get')

def add_user_to_group_scim(token, user_id, group_id):
    payload = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        "Operations": [{
            "op": "Add",
            "path": "members",
            "value": [{
                "value": user_id
            }]
        }]
    }
    url_suffix = 'Groups/{}'.format(group_id)
    return _execute_scimapi(payload, url_suffix, token, 'patch')

def remove_user_from_group_scim(token, user_id, group_id):
    payload = {
        "schemas": [
            "urn:ietf:params:scim:api:messages:2.0:PatchOp"
        ],
        "Operations": [{
            "op": "Remove",
            "path": "members",
            "value": [{
                "value": user_id
            }]
        }]
    }
    url_suffix = 'Groups/{}'.format(group_id)
    return _execute_scimapi(payload, url_suffix, token, 'patch')

def change_user_type_scim(token, user_id, user_type):
    if user_type != 'Basic User' and user_type != 'Full User':
        raise Exception('Unrecognized User Type: {}'.format(user_type))
    payload = {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:newrelic:2.0:User"
        ],
            "urn:ietf:params:scim:schemas:extension:newrelic:2.0:User": {
            "nrUserType": user_type
        }
    }
    url_suffix = 'Users/{}'.format(user_id)
    return _execute_scimapi(payload, url_suffix, token, 'put')

def get_account_id_from_group_name(group_name, accounts):
    snippet = ''
    try:
        snippet = group_name.split('.')[1]
    except Exception as error:
        pdb.set_trace()
        return None
    for account in accounts:
        if snippet in account['name']:
            return account['id']


def main():
    formatting.print_('Hello.')

    key = load_keys_file()['NEW_RELIC_USER_API_KEY']

    # list_accounts(key)
    # list_groups(key)
    # list_roles(key)
    # list_auth_domains(key)
    # list_users_for_auth_domains(key, '<AUTH_ID>')
    # create_group(key, '<GROUP_NAME>', '<AUTH_ID>')
    # get_roles_for_group(key, '<GROUP_ID>')
    # grant_group_access_to_role_for_account(key, '<GROUP_ID>', '<ACCOUNT_ID>', '<ROLE_ID>')
    # copy_group_roles_to_new_account(key, '<GROUP_ID>', '<GROUP_ID_2>', '<ACCOUNT_ID>')
    # create_user(key, '<NAME>', '<GROUP_ID>', '<AUTH_ID>')
    

    formatting.print_('Goodbye.\n')

if __name__ == "__main__":
    main()