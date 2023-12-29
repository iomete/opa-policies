package iomete

# logic that implements RBAC.
allow[name] {
    # load data_plane data
    data_plane := data.data_plane

    # iterate over user's roles
    user_role := data_plane.users[input.user.id].roles[_]

    # get role's permissions
    permissions := data_plane.role_permissions[user_role]

    # iterate over role's permissions
    p := permissions[_]

    # check if the input service matches the permission's service
    p.service == input.service

    # if service match, iterate over the actions
    action := p.actions[_]

    action.action == input.action

    # iterate over input resource names
    input_resource := input.resources[_]

    # iterate over the permission's resources
    action_resource_glob := action.resources[_]

    glob.match(action_resource_glob, [], input_resource.name)

    name := input_resource.name
}

user_permissions = [service |
    data_plane := data.data_plane
    user_role := data_plane.users[input.user.id].roles[_]

    # get role's permissions
    permissions := data_plane.role_permissions[user_role]

    # iterate over role's permissions
    p := permissions[_]

    # if service match, get the action name
    service := {
        "service": p.service,
        "actions": [action | action := p.actions[_].action]
    }
]
