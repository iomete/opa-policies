package iomete

# logic that implements root user
allow[name] {
    data_plane := data.data_plane

    data_plane.users[input.user.id].root_user == true

    # iterate over input resource names
    input_resource := input.resources[_]

    name := input_resource.name
}

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

# root user implementation
module_permissions[result] {
    data_plane := data.data_plane
    data_plane.users[input.user.id].root_user == true

    result := {
        "create": { "all_roles": ["*"] },
        "manage": { "all_roles": ["*"] }
    }
}

# non-root user implementation
module_permissions[result] {
    data_plane := data.data_plane
    not data_plane.users[input.user.id].root_user == true
    result := {
        "create": matching_rules("create"),
        "manage": matching_rules("manage")
    }
}

matching_rules(test_action) = result {
    result := { user_role: resources |
        data_plane := data.data_plane

        user_role := data_plane.users[input.user.id].roles[i]

        # get role's permissions
        permissions := data_plane.role_permissions[user_role]

        # iterate over role's permissions
        p := permissions[_]

        # check if the input service mathces the permission's service
        p.service == input.service

        # if service match, iterate over the actions
        action := p.actions[_]

        action.action == test_action

        resources := [name |
            some i
            name := action.resources[i]
        ]
    }
}
