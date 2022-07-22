package iomete

# -------------- ALLOWED -----------------

test_integration_allowed_when_lakehouse_create {
	allow == {"resource1"} with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "create",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_allowed_when_lakehouse_manage {
	allow == {"reporting2"} with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "manage",
		"resources": [{"name": "reporting2", "owner": "abc"}]
	}
}

test_integration_allowed_when_lakehouse_connect {
	allow == {"analytics2"} with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "connect",
		"resources": [{"name": "analytics2", "owner": "abc"}]
	}

	# vusal has connect access to reporting1 because he has manage permission over that resource
	allow == {"reporting1"} with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "connect",
		"resources": [{"name": "reporting1", "owner": "abc"}]
	}
}

test_integration_returns_multiple_resources {
	allow == {"reporting1", "analytics2"} with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "connect",
		"resources": [
		    {"name": "analytics2", "owner": "abc"},
		    {"name": "reporting1", "owner": "abc"}
		]
	}
}

test_integration_allowed_when_user_is_owner {
    # connect is allowed
	allow == {"abc"} with input as {
		"account": "000000000000",
		"user": "any_user",
		"service": "lakehouse",
		"action": "connect",
		"resources": [{"name": "abc", "owner": "any_user"}]
	}

    # manage is allowed
	allow == {"abc"} with input as {
		"account": "000000000000",
		"user": "any_user",
		"service": "lakehouse",
		"action": "connect",
		"resources": [{"name": "abc", "owner": "any_user"}]
	}

	# returns multiple allowed resource names
    allow == {"abc", "xyz"} with input as {
        "account": "000000000000",
        "user": "any_user",
        "service": "lakehouse",
        "action": "connect",
        "resources": [
            {"name": "abc", "owner": "any_user"},
            {"name": "xyz", "owner": "any_user"}
        ]
    }
}

# -------------- NOT ALLOWED -----------------

test_integration_not_allowed_when_account_doesnt_exist {
	allow == set() with input as {
		"account": "000000000001",
		"user": "vusal",
		"service": "lakehouse",
		"action": "create",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_not_allowed_when_user_doesnt_exist {
	allow == set() with input as {
		"account": "000000000000",
		"user": "vusal2",
		"service": "lakehouse",
		"action": "create",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_not_allowed_when_service_doesnt_exist {
	allow == set() with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse2",
		"action": "create",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_not_allowed_when_action_is_not_match {
	allow == set() with input as {
		"account": "000000000000",
		"user": "vusal",
		"service": "lakehouse",
		"action": "create2",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_not_allowed_when_user_is_not_match {
	allow == set() with input as {
		"account": "000000000000",
		"user": "vusal2",
		"service": "lakehouse",
		"action": "create",
		"resources": [{"name": "resource1", "owner": "abc"}]
	}
}

test_integration_not_allowed_when_user_is_owner_but_action_is_not_compatible_with_owner_action {
	allow == set() with input as {
		"account": "000000000000",
		"user": "any_user",
		"service": "lakehouse",
		"action": "create",
		"resources": [{"name": "abc", "owner": "any_user"}]
	}
}