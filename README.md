# psql-proxy

A simple PSQL wire protocol proxy allowing users to inspect the PostgreSQL wire protocol packages being send between the client and server. This CLI mainly exists to validate and debug PostgreSQL protocol implementations.

```bash
$ psql-proxy -d 127.0.0.1:5432 -l :2345
```