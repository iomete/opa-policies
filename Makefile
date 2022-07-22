

#https://www.openpolicyagent.org/docs/latest/policy-testing/
tests:
	opa test . -v


# run only test cases matching the regular expression
test:
	opa test . -v --run test_abac_.*