import formatting
import graphql_queries

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

def execute_graphql(graphql_string, key):
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

def get_cursored_query(query, cursor=None):
    cursor_txt = '' if not cursor else '(cursor: "{}")'.format(cursor)
    return query.replace('||CURSOR||', cursor_txt.format(cursor_txt))

def query_until_cursor_empty(graphql_query, key, parse_results, parse_cursor):
    results = []
    next_cursor = None
    first_run = True
    while next_cursor or first_run:
        first_run = False
        query = get_cursored_query(graphql_query, cursor=None)
        r_json = execute_graphql(query, key)
        curr_results = parse_results(r_json)
        results = results + curr_results
        next_cursor = parse_cursor(r_json)
    return results

def list_accounts(key):
    get_results = lambda r: r['data']['actor']['organization']['accountManagement']['managedAccounts']
    get_cursor = lambda r: None
    accounts = query_until_cursor_empty(graphql_queries.LIST_ACCOUNTS_FOR_ORG, key, get_results, get_cursor)
    formatting.print_json(accounts, prefix='Accounts: ')
    return accounts

def list_groups(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['nextCursor']
    groups = query_until_cursor_empty(graphql_queries.LIST_GROUPS_PER_AUTH_DOMAIN, key, get_results, get_cursor)
    formatting.print_json(groups, prefix='Groups: ')
    return groups

def list_roles(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['roles']['roles']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['roles']['nextCursor']
    roles = query_until_cursor_empty(graphql_queries.LIST_AUTH_ROLES_QUERY, key, get_results, get_cursor)
    formatting.print_json(roles, prefix='Roles: ')
    return roles

def list_auth_domains(key):
    get_results = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['authenticationDomains']
    get_cursor = lambda r: r['data']['actor']['organization']['authorizationManagement']['authenticationDomains']['nextCursor']
    auth_domains = query_until_cursor_empty(graphql_queries.LIST_AUTH_DOMAINS_QUERY, key, get_results, get_cursor)
    formatting.print_json(auth_domains, prefix='Auth Domains: ')
    return auth_domains

def list_users_for_auth_domains(key, auth_id):
    if not auth_id:
        formatting.print_error('Must include auth domain id to list users.')
    get_results = lambda r: r['data']['actor']['organization']['userManagement']['authenticationDomains']['authenticationDomains'][0]['users']['users']
    get_cursor = lambda r: r['data']['actor']['organization']['userManagement']['authenticationDomains']['authenticationDomains'][0]['users']['nextCursor']
    query = graphql_queries.LIST_USERS_FOR_AUTH_DOMAINS.replace('||AUTH_ID||', auth_id)
    users = query_until_cursor_empty(query, key, get_results, get_cursor)
    formatting.print_json(users, prefix='Users: ')
    return users

def execute_mutation_or_raise_error(mutation, key, error_message):
    r_json = execute_graphql(mutation, key)
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
    results = execute_mutation_or_raise_error(mutation, key, error_message)
    formatting.print_('Group created.')
    return results

def grant_group_access_to_role_for_account(key, group_id, account_id, role_id):
    if not group_id or not account_id or not role_id:
        formatting.print_error('Must include parameters to grant group access.')

    mutation = graphql_queries.GRANT_GROUP_ACCESS_TO_ACCOUNT_AND_ROLE.replace('||GROUP_ID||', group_id).replace('||ACCOUNT_ID||', account_id).replace('||ROLE_ID||', role_id)
    error_message = 'Could not grant group access with group id: {}, account id: {}, role id: {}, key: {}'.format(group_id, account_id, role_id, key)
    results = execute_mutation_or_raise_error(mutation, key, error_message)
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
    roles = query_until_cursor_empty(query, key, get_results, get_cursor)
    formatting.print_json(roles, prefix='Roles: ')
    return roles

def copy_group_roles_to_new_account(key, group_to_copy_from_id, group_to_copy_to_id, account_id):
    if not group_to_copy_from_id or not account_id or not group_to_copy_to_id:
        formatting.print_error('Must include parameters to copy group rules.')
    role_ids = list(set([r['roleId'] for r in get_roles_for_group(key, group_to_copy_from_id)]))
    print('role ids: {}'.format(role_ids))
    for role_id in role_ids:
        grant_group_access_to_role_for_account(key, group_to_copy_to_id, account_id, '{}'.format(role_id))

def main():
    formatting.print_('Hello.')

    key = load_keys_file()['NEW_RELIC_USER_API_KEY']
    
    # list_accounts(key)
    # list_groups(key)
    # list_roles(key)
    # list_auth_domains(key)
    # list_users_for_auth_domains(key, '<AUTH_ID>')
    # create_group(key, 'TestingScriptGroupCreate3', '<AUTH_ID>')
    # get_roles_for_group(key, '<GROUP_ID>')
    # grant_group_access_to_role_for_account(key, '<GROUP_ID>', '<ACCOUNT_ID>', '<ROLE_ID>')
    # copy_group_roles_to_new_account(key, '<GROUP_ID>', '<GROUP_ID_2>', '<ACCOUNT_ID>')

    formatting.print_('Goodbye.\n')

if __name__ == "__main__":
    main()