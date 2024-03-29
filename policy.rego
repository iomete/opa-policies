package iomete

# Resource IDs

# lakehouse: name
# spark-job: name

# storage-integration: name
# ssh-tunnel: name

# iam-user: name
# iam-group: path?
# iam-role: name

# data-acl: none
# billing: none

action_hierarchy := {
    "lakehouse": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
		"owner": ["view", "manage"],
    },
    "spark-job": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
		"owner": ["view", "manage"],
	},
	"storage-integration": {
		"create": ["create"],
		"manage": ["manage"],
		"view": ["view", "manage"],
		"owner": ["view", "manage"],
	},
	"ssh-tunnel": {
		"create": ["create"],
		"manage": ["manage"],
		"view": ["view", "manage"],
		"owner": ["view", "manage"],
	},
    "data-acl": {
		"create": ["create"],
		"manage": ["manage"],
		"view": ["view", "manage"],
		"owner": ["view", "manage"],
    },
    "iam-user": {
        "create": ["create"],
        "manage": ["manage"],
        "attach": ["attach", "manage"],
        "view": ["view", "attach", "manage"],
        "owner": ["view", "attach", "manage"]
    },
    "iam-group": {
        "create": ["create"],
        "manage": ["manage"],
        "attach": ["attach", "manage"],
        "view": ["view", "attach", "manage"],
        "owner": ["view", "attach", "manage"]
    },
    "iam-role": {
        "create": ["create"],
        "manage": ["manage"],
        "attach": ["attach", "manage"],
        "view": ["view", "attach", "manage"],
        "owner": ["view", "attach", "manage"]
    },
    "billing": {
        "manage": ["manage"],
		"monitor": ["monitor", "manage"],
	},
}

# logic that implements root user
allow[name] {
    workspace := data.workspaces[input.user.workspaceId]

    workspace.users[input.user.id].root_user == true

    # iterate over input resource names
    input_resource := input.resources[_]

    not is_system_role_create_or_manage(input.service, input.action, input_resource.name)

    name := input_resource.name
}

 # logic that implements RBAC.
allow[name] {
    # load workspace data
    workspace := data.workspaces[input.user.workspaceId]

    # iterate over user's roles
    user_role := workspace.users[input.user.id].roles[_]

    # get role's permissions
    permissions := workspace.role_permissions[user_role]

    # iterate over role's permissions
    p := permissions[_]

    # check if the input service mathces the permission's service
    p.service == input.service

    # if service mathc, iterate over the actions
    action := p.actions[_]

    # check if the action mathc the input action
    # here we can get input.action = "view",
    # in that case we need to check if permission has "view" or "manage" based on action hierarchy
    actions_cover_input_action := action_hierarchy[input.service][input.action]

    action.action == actions_cover_input_action[_]

    # iterate over input resource names
    input_resource := input.resources[_]

    # iterate over the permission's resources
    action_resource_glob := action.resources[_]

    not is_system_role_create_or_manage(input.service, input.action, input_resource.name)

    # check if the input resource mathc the action resource glob
    glob.match(action_resource_glob, [], input_resource.name)

    name := input_resource.name
}

# logic that implements ABAC (OWNERSHIP rule).
allow[name] {
    # iterate over input resource names
    input_resource := input.resources[_]
    # check if there is ownership relationship between the input resource owner and the user
    input_resource.owner == input.user.id

    # if the user is the owner of the given resource, then can check if the requested action is allowed for the ownership relationship

    # let's get the acttions that cover owner action. e.g. "connect" or "manage"
    actions_cover_owner_action := action_hierarchy[input.service]["owner"]

    # check if the requested action match the owner covered actions (e.g. "connect" or "manage")
    input.action == actions_cover_owner_action[_]

    name := input_resource.name
}

# root user implementation
module_permissions[result] {
    workspace := data.workspaces[input.user.workspaceId]
    workspace.users[input.user.id].root_user == true

    result := {
        "create": { "all_roles": ["*"] },
        "manage": { "all_roles": ["*"] }
    }
}

# non-root user implementation
module_permissions[result] {
    workspace := data.workspaces[input.user.workspaceId]
    not workspace.users[input.user.id].root_user == true
    result := {
        "create": matching_rules("create"),
        "manage": matching_rules("manage")
    }
}

matching_rules(test_action) = result {
    result := { user_role: resources |
        workspace := data.workspaces[input.user.workspaceId]

        user_role := workspace.users[input.user.id].roles[i]

        # get role's permissions
        permissions := workspace.role_permissions[user_role]

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

is_system_role_create_or_manage(service, action, resource_name) {
    service == "iam-role"
    action == ["create", "manage"][_]
    glob.match("system:*", [], resource_name)
}
