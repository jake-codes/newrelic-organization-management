# New Relic Organization Helper

Creates a few convenience methods for scripting organization updates/migrations:

- `list_accounts(key)`
- `list_groups(key)`
- `list_roles(key)`
- `list_auth_domains(key)`
- `list_users_for_auth_domains(key, '<AUTH_ID>')`
- `create_group(key, '<GROUP_NAME>', '<AUTH_ID>')`
- `get_roles_for_group(key, '<GROUP_ID>')`
- `grant_group_access_to_role_for_account(key, '<GROUP_ID>', '<ACCOUNT_ID>', '<ROLE_ID>')`
- `copy_group_roles_to_new_account(key, '<GROUP_ID>', '<GROUP_ID_2>', '<ACCOUNT_ID>')`
- `create_v2_users(key, '<NAME>', '<EMAIL>', '<AUTH_ID>')`