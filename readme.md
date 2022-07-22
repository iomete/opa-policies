
# OPA

https://hub.docker.com/r/openpolicyagent/opa/

## OPA CLI

```shell
brew install opa
```

## Tests

To run tests:
```shell
opa test . -v
```

To run individual test:
```shell
opa test . -v --run data.iomete.test_empty_permission_not_allowed
```

## Docker

```shell
docker run -it --rm -p 8181:8181 openpolicyagent/opa run --server --addr :8181
```



# OPAL

https://www.opal.ac/

```shell
docker-compose -f opal-docker-compose-example.yml up -d
```