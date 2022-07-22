package iomete

unit_input := {
	"account": "000000000000",
	"user": "unit_test_user",
	"service": "service1",
	"action": "action1",
    "resources": [{"name": "resource1", "owner": "abc"}]
}

unit_action_hierarchy := {
    "service1": {
        "action1": ["action1"],
        "action2": ["action1", "action2"]
    }
}

# -------------- ALLOWED -----------------

test_rbac_allowed_when_matching_resource {
	allow == {"resource1"} with input as unit_input
	with action_hierarchy as unit_action_hierarchy
    with data.accounts["000000000000"].role_permissions.test_role as [{
        "service": "service1",
        "actions": [{
            "action": "action1",
            "resources": ["resource1"],
        }],
    }]
}

test_rbac_allowed_when_star_match {
	allow == {"resource1"} with input as unit_input
    with action_hierarchy as unit_action_hierarchy
    with data.accounts["000000000000"].role_permissions.test_role as [{
        "service": "service1",
        "actions": [{
            "action": "action1",
            "resources": ["*"],
        }],
    }]
}

test_rbac_allowed_when_wildcard_match {
	allow == {"resource1"} with input as unit_input
    with action_hierarchy as unit_action_hierarchy
    with data.accounts["000000000000"].role_permissions.test_role as [{
        "service": "service1",
        "actions": [{
            "action": "action1",
            "resources": ["reso*", "*sour*1"],
        }],
    }]
}

test_rbac_allowed_when_requested_action_belongs_to_permitted_action_hierarchy {
	allow == {"resource1"} with input as  {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "action2",
      "resources": [{"name": "resource1", "owner": "abc"}]
    }
    with action_hierarchy as unit_action_hierarchy
    with data.accounts["000000000000"].role_permissions.test_role as [{
        "service": "service1",
        "actions": [{
            "action": "action1",
            "resources": ["*"],
        }],
    }]
}

test_rbac_allowed_returns_multiple_allowed_resources {
	allow == {"resource1", "resource2"} with input as {
        "account": "000000000000",
        "user": "unit_test_user",
        "service": "service1",
        "action": "action1",
        "resources": [
            {"name": "resource1", "owner": "abc"},
            {"name": "resource2", "owner": "abc"},
        ]
    }
    with action_hierarchy as unit_action_hierarchy
    with data.accounts["000000000000"].role_permissions.test_role as [{
        "service": "service1",
        "actions": [{
            "action": "action1",
            "resources": ["reso*", "*sour*1"],
        }],
    }]
}

# -------------- NOT ALLOWED -----------------

test_rbac_not_allowed_when_empty_permission {
	allow == set() with input as unit_input
		with data.accounts["000000000000"].role_permissions.test_role as [{}]
}

test_rbac_not_allowed_when_empty_actions {
	allow == set() with input as unit_input
		with data.accounts["000000000000"].role_permissions.test_role as [{
			"service": "service1",
			"actions": [],
		}]
}

test_rbac_not_allowed_when_no_matching_actions {
	allow == set() with input as unit_input
		with data.accounts["000000000000"].role_permissions.test_role as [{
			"service": "service1",
			"actions": [{"action": "abc"}],
		}]
}

test_rbac_not_allowed_when_no_matching_resource {
	allow == set() with input as unit_input
		with data.accounts["000000000000"].role_permissions.test_role as [{
			"service": "service1",
			"actions": [{
				"action": "action1",
				"resources": ["resource2"],
			}],
		}]
}

test_rbac_not_allowed_when_no_matching_wildcard_resource {
	allow == set() with input as unit_input
		with data.accounts["000000000000"].role_permissions.test_role as [{
			"service": "service1",
			"actions": [{
				"action": "action1",
				"resources": ["resour*2"],
			}],
		}]
}