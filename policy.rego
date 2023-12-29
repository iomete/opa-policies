package iomete

# logic that implements root user
allow[name] {
    data_plane := data.data_plane

    data_plane.users[input.user.id].root_user == true

    # iterate over input resource names
    input_resource := input.resources[_]

    not is_system_role_create_or_manage(input.service, input.action, input_resource.name)

    name := input_resource.name
}

# logic that implements RBAC (for empty resource name).
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

    not is_system_role_create_or_manage(input.service, input.action, input_resource.name)

    # Allow empty resource name for specific actions like List and Create
    is_empty_resource_name_allowed(action.action, input_resource.name)

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

    not is_system_role_create_or_manage(input.service, input.action, input_resource.name)

    # Allow empty resource name for specific actions like List and Create
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
            not is_system_role_create_or_manage(input.service, test_action, action.resources[i])
            name := action.resources[i]
        ]
    }
}

# This function prevents editing system roles (or creating with prefix system)
is_system_role_create_or_manage(service, action, resource_name) {
    service == "iam_role"
    action == ["create", "manage"][_]
    glob.match("system:*", [], resource_name)
}

# Helper function to determine if empty resource names are allowed for specific actions
is_empty_resource_name_allowed(action, resource_name) {
    resource_name == ""
    allowed_empty_resource_actions := {"list", "create"}
    action in allowed_empty_resource_actions
}