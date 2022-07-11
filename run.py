import formatting
import graphql_queries

import csv
import json
import pdb
import requests
import yaml

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
        next_cursor = parse_cursor(r_json)
    return results

def list_accounts(key):
    get_results = lambda r: r['data']['actor']['organization']['accountManagement']['managedAccounts']
    get_cursor = lambda r: None
    accounts = _query_until_cursor_empty(graphql_queries.LIST_ACCOUNTS_FOR_ORG, key, get_results, get_cursor)
    formatting.print_json(accounts, prefix='Accounts: ')
    return accounts

def list_groups(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['nextCursor']
    groups = _query_until_cursor_empty(graphql_queries.LIST_GROUPS_PER_AUTH_DOMAIN, key, get_results, get_cursor)
    formatting.print_json(groups, prefix='Groups: ')
    return groups

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

def _execute_mutation_or_raise_error(mutation, key, error_message):
    r_json = _execute_graphql(mutation, key)
    if 'errors' in r_json:
        formatting.print_error(error_message)
        try:
            formatting.print_json(r_json['errors'], 'Errors: ')
        except:
            pass
        raise Exception(error_message)

def create_group(key, name, auth_id):
    if not auth_id:
        formatting.print_error('Must include auth domain id to create group.')
    mutation = graphql_queries.CREATE_GROUP.replace('||AUTH_ID||', auth_id).replace('||GROUP_NAME||', name)
    error_message = 'Could not create group with name: {}, auth id: {}, key: {}'.format(name, auth_id, key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message)
    formatting.print_('Group created.')
    return results

def grant_group_access_to_role_for_account(key, group_id, account_id, role_id):
    if not group_id or not account_id or not role_id:
        formatting.print_error('Must include parameters to grant group access.')

    mutation = graphql_queries.GRANT_GROUP_ACCESS_TO_ACCOUNT_AND_ROLE.replace('||GROUP_ID||', group_id).replace('||ACCOUNT_ID||', account_id).replace('||ROLE_ID||', role_id)
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
    
    group_ids_str = ','.join(group_ids)
    user_ids_str = ','.join(user_ids)

    mutation = graphql_queries.ADD_USERS_TO_GROUPS.replace('||GROUP_IDS||', group_ids_str).replace('||USER_IDS||', user_ids_str)
    error_message = 'Could not add users to groups: {}\nusers:{}\nkey: {}'.format(group_ids_str, user_ids_str, key)
    results = _execute_mutation_or_raise_error(mutation, key, error_message)
    formatting.print_('Users added to groups.')
    return results

def _execute_scimapi(data, url_suffix, token):
  # Graphql calls it 'cursor' instead of page
  try:
    # pdb.set_trace()
    headers = {'Authorization': 'Bearer {}'.format(token), 'Content-Type': 'application/json'}
    data_json = json.dumps(data)
    response  = requests.post('https://scim-provisioning.service.newrelic.com/scim/v2/{}'.format(url_suffix), headers=headers, data=data_json)
    r_json = response.json()
    return r_json

  except Exception as e:
    formatting.print_error('Error executing scim query for key: {}url suffix: {}\nData: {}'.format(token, url_suffix, data))
    pdb.set_trace()
    raise

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
        _execute_scimapi(payload, 'Users', token)
        formatting.print_success('User added: {}'.format(email))

def main():
    formatting.print_('Hello.')

    key = load_keys_file()['NEW_RELIC_USER_API_KEY']

    # Note: Remember that tokens are associated with authentication domains
    #       so if you need to add V2 users to multiple auth domains via SCIM
    #       you will need to switch the BEARER token file
    token = load_keys_file()['NEW_RELIC_SCIM_BEARER_TOKEN']
    
    # list_accounts(key)
    # list_groups(key)
    # list_roles(key)
    # list_auth_domains(key)
    # list_users_for_auth_domains(key, '877e9403-1d1b-43b1-b0b2-d53d24950eea')
    # create_group(key, 'TestingScriptGroupCreate3', '877e9403-1d1b-43b1-b0b2-d53d24950eea')
    # get_roles_for_group(key, 'b16f57e5-be28-49e2-ae7c-9526bfb1f499')
    # grant_group_access_to_role_for_account(key, '2bf285da-08d0-445b-9665-061e2ec5e6ec', '1822040', '5198')
    # copy_group_roles_to_new_account(key, 'b16f57e5-be28-49e2-ae7c-9526bfb1f499', 'b16f57e5-be28-49e2-ae7c-9526bfb1f499', '1822040')
    # add_users_to_groups(key,['b16f57e5-be28-49e2-ae7c-9526bfb1f499'],[])
    # create_v2_users_from_csv_scim(token)
    # create_v2_users_from_csv_scim(token)

    formatting.print_('Goodbye.\n')

if __name__ == "__main__":
    main()