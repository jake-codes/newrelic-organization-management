LIST_ACCOUNTS_FOR_ORG = '''{
  actor {
    organization {
      accountManagement {
        managedAccounts {
          id
          name
        }
      }
    }
  }
}
'''

LIST_AUTH_DOMAINS_QUERY = '''{
  actor {
    organization {
      authorizationManagement {
        authenticationDomains||CURSOR|| {
          authenticationDomains {
            id
            name
          }
          nextCursor
        }
      }
    }
  }
}
''' 

LIST_AUTH_ROLES_QUERY = '''{
  actor {
    organization {
      authorizationManagement {
        roles||CURSOR|| {
          roles {
            displayName
            id
            name
            scope
            type
          }
          nextCursor
        }
      }
    }
  }
}
'''

LIST_GROUPS_PER_AUTH_DOMAIN = '''{
  actor {
    organization {
      authorizationManagement {
        authenticationDomains {
          authenticationDomains {
            groups {
              groups {
                id
                displayName
              }
            }
            id
            name
          }
          nextCursor
        }
      }
    }
  }
}
'''

LIST_USERS_FOR_AUTH_DOMAINS = '''{
  actor {
    organization {
      userManagement {
        authenticationDomains(id: "||AUTH_ID||") {
          authenticationDomains {
            users||CURSOR|| {
              users {
                groups {
                  groups {
                    id
                    displayName
                  }
                }
                id
                name
                email
              }
              nextCursor
            }
            id
            name
          }
        }
      }
    }
  }
}
'''

LIST_ROLES_FOR_GROUP = '''{
  actor {
    organization {
      authorizationManagement {
        authenticationDomains {
          authenticationDomains {
            groups(id: "||GROUP_ID||") {
              groups {
                roles {
                  roles {
                    id
                    displayName
                    name
                    roleId
                    organizationId
                    type
                    accountId
                  }
                }
                id
                displayName
              }
            }
          }
        }
      }
    }
  }
}
'''

CREATE_GROUP = '''mutation {
  userManagementCreateGroup(createGroupOptions: {authenticationDomainId: "||AUTH_ID||", displayName: "||GROUP_NAME||"}) {
    group {
      displayName
      id
    }
  }
}
'''

GRANT_GROUP_ACCESS_TO_ACCOUNT_AND_ROLE = '''mutation {
  authorizationManagementGrantAccess(grantAccessOptions: {groupId: "||GROUP_ID||", accountAccessGrants: {accountId: ||ACCOUNT_ID||, roleId: "||ROLE_ID||"}}) {
    roles {
      displayName
      accountId
    }
  }
}
'''

ADD_USERS_TO_GROUPS = '''mutation {
  userManagementAddUsersToGroups(addUsersToGroupsOptions: {groupIds: [||GROUP_IDS||], userIds: [||USER_IDS||]}) {
    groups {
      displayName
      id
    }
  }
}
'''