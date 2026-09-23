# CFMS Maintain CLI

Register the server directories managed by this CLI. Each directory must exist
and contain a `config.toml` file when it is added.

```console
cfms-maintain-cli instance add production /srv/cfms/production
cfms-maintain-cli instance add staging /srv/cfms/staging --set-default
cfms-maintain-cli instance list
cfms-maintain-cli instance show production
cfms-maintain-cli instance set-default production
cfms-maintain-cli instance remove staging
```

`instance delete NAME` is an alias for `instance remove NAME`. The first added
instance becomes the default. Removing the default leaves it unset until you
run `instance set-default NAME`. Commands that need an instance can use the
registry's `resolve(name)` method; omitting `name` selects the default.

The registry is stored in `instances.toml` under the user's platform-specific
configuration directory for `cfms-maintain-cli`. Writes replace the complete
file atomically. The registry retains comments and unrelated TOML fields when
instance commands update it.
