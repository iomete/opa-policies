package iomete

action_hierarchy := {
    "lakehouse": {
        "create": ["create"],
        "manage": ["manage"],
        "connect": ["connect", "manage"],
        "owner": ["connect", "manage"]
    },
    "spark-job": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
        "owner": ["view", "manage"]
    },
    "iam-user": {
        "manage": ["manage"]
    },
    "iam-group": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
        "owner": ["view", "manage"]
    },
    "storage-integration": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
        "owner": ["view", "manage"]
    },
    "ssh-tunnel": {
        "create": ["create"],
        "manage": ["manage"],
        "view": ["view", "manage"],
        "owner": ["view", "manage"]
    },
    "app-bi": {
        "use": ["use"]
    },
    "billing": {
        "manage": ["manage"],
        "monitor": ["monitor", "manage"]
    }
}

 # logic that implements RBAC.
allow[name] {
    # load account data
    account := data.accounts[input.user.account]

    # iterate over user's roles
    user_role := input.user.roles[_]

    # get role's permissions
    permissions := account.role_permissions[user_role]

    # iterate over role's permissions
    p := permissions[_]

    # check if the input service mathces the permission's service
    p.service == input.service

    # if service mathc, iterate over the actions
    action := p.actions[_]

    # check if the action mathc the input action
    # here we can get input.action = "connect",
    # in that case we need to check if permission has "connect" or "manage" based on action hierarchy
    actions_cover_input_action := action_hierarchy[input.service][input.action]

    action.action == actions_cover_input_action[_]

    # iterate over input resource names
    input_resource := input.resources[_]

    # iterate over the permission's resources
    action_resource_glob := action.resources[_]

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