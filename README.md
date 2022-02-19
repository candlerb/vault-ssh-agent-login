vault-ssh-agent-login
=====================

This utility generates an SSH key pair, submits it for signing to a
[Hashicorp Vault Certificate Authority](https://brian-candler.medium.com/using-hashicorp-vault-as-an-ssh-certificate-authority-14d713673c9a),
and then inserts the key+cert into your local ssh-agent.

This means there is no writing to the filesystem.  In fact, you need no
private key on disk at all!  It works with all ssh utilities including
scp/sftp.

I hope that one day something like this will be integrated into Vault, e.g. as

```
vault ssh -mode=ca -use-ssh-agent ...
```

Build
-----
```
go build .
```

Usage
-----
Only the `-role` option is mandatory, although typically you'd also need to
request one or more principals because of
[this issue](https://github.com/hashicorp/vault/issues/10946).

For ease of use it's a good idea to create a wrapper script, e.g.
called `vssh`:

```
#!/bin/sh
export VAULT_ADDR="https://vault.example.net:8200"

vault-ssh-agent-login -role=my-role -valid-principals="brian,root" "$@"
```

If you pass any extra arguments, then ssh is invoked with these arguments.
If not, then just the key/certificate is generated if necessary.

If there is already a key in your ssh-agent with the expected key comment,
then no key/certificate generation is done unless you supply the `-force`
flag.  In that case, any existing key(s) with that comment are also deleted
from your agent.

Unless specified otherwise, the key comment is automatically generated as:

```
vault-XXXXXXXX-<rolename>
```

where `XXXXXXXX` is a CRC-32 of your `VAULT_ADDR`.

Authentication
--------------
`vault-ssh-agent-login` needs a token to authenticate to Vault.

If you have previously logged in using `vault login` then this token will be
picked up from `~/.vault-token`.  You can also the the `VAULT_TOKEN`
environment variable to override this.

If your Vault server has an upstream OIDC auth method, then you can enable
the built-in OIDC support in `vault-ssh-agent-login` with flag
`-auth-method=oidc`.  This is currently the only built-in authentication
method.

In this mode, `vault-ssh-agent-login` will perform an OIDC login in a
similar way to `vault login -method=oidc`, and use the fetched token for
signing the certificate.  The token is discarded after use.


Environment Settings
--------------------
The `VAULT_*` environment variables control communication with the Vault
server.  If you have `VAULT_TOKEN` in your environment then this is used,
otherwise the token file at `~/.vault-token` is read in.

Location of the ssh-agent is done via the `SSH_AUTH_SOCK` environment
variable, which is normally already set in your shell enviornment.

Command line options
--------------------

| Flag                 | Default          | Meaning
|----------------------|------------------|---------
| `-force`             | false            | Force generation of new key/cert, even if agent already has one with expected name. Delete any existing key/cert entries with that name.
| `-key-comment=`      | (auto-generated) | Override the key comment which is normally automatically chosen
| `-key-confirm-before-use` | false       | Tell ssh-agent to request confirmation before every use of this key
| `-ttl=`              | (role default)   | Choose TTL for the certificate. You can include units e.g. "5m" or "12h"
| `-mount-point=`      | `ssh`            | Mount point for the Vault secrets engine acting as SSH CA
| `-role=`             | REQUIRED         | Name of the SSH signing role to use
| `-valid-principals=` | (role default)   | Comma-separated list of principals to request
| `-extensions=`       | (role default)   | Comma-separated list of extensions to request
| `-write-pubkey=`     | (unset)          | If set, public key will also be written to this file. Useful with IdentifyFile/IdentitiesOnly
| `-write-cert=`       | (unset)          | If set, certificate will also be written to this file
| `-token-file=`       | `~/.vault-token` | Location of existing token file to use
| `-auth-method=`      | (unset)          | If set, perform a Vault login instead of looking for existing token
| `-auth-path=`        | (auth-method)    | For use with `-auth-method`, selects the auth mount path
| `-auth-role=`        | (role default)   | For use with `-auth-method`, selects the auth role
| `-ssh-executable=`   | `ssh`            | Name of ssh command to invoke if extra arguments are provided

Notes
-----
If your agent has many identities, and/or you have many other private keys
in `~/.ssh/`, then you may exceed the maximum number of authentication
attempts when talking to a remote host.  If that's a problem, you can write
the public key to a file and use `-o IdentityFile=<filename>` and `-o IdentitiesOnly`

Limitations
-----------
There is no support for retrieving the token from an external token helper.

Licence
-------
Licence is the same as Vault itself (MPL)
