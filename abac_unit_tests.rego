package iomete

abac_action_hierarchy := {
    "service1": {
        "owner": ["connect", "manage"]
    }
}

# ---------- ALLOWED ----------

test_abac_allow_when_resource_owner_with_compatible_input_action {
    # connect is allowed
	allow == {"abc"} with input as {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "connect",
      "resources": [
        {"name": "abc", "owner": "unit_test_user"}
      ]
    }
    with action_hierarchy as abac_action_hierarchy

    # manage is allowed
    allow == {"abc"} with input as {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "manage",
      "resources": [
        {"name": "abc", "owner": "unit_test_user"}
      ]
    }
    with action_hierarchy as abac_action_hierarchy
}

test_abac_allowed_returns_multiple_allowed_resources {
	allow == {"abc", "xyz"} with input as {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "connect",
      "resources": [
        {"name": "abc", "owner": "unit_test_user"},
        {"name": "xyz", "owner": "unit_test_user"}
      ]
    }
    with action_hierarchy as abac_action_hierarchy
}

# ---------- NOT ALLOWED ----------
test_abac_not_allow_when_resource_owner_is_requesting_non_compatible_action {
	allow == set() with input as {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "create",
      "resources": [
        {"name": "abc", "owner": "unit_test_user"}
      ]
    }
    with action_hierarchy as abac_action_hierarchy
}

test_abac_not_allow_when_user_is_not_resource_owner {
	allow == set() with input as {
      "account": "000000000000",
      "user": "unit_test_user",
      "service": "service1",
      "action": "create",
      "resources": [
        {"name": "abc", "owner": "some_other_user"}
      ]
    }
    with action_hierarchy as abac_action_hierarchy
}