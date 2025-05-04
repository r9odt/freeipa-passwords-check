# FreeIPA Passwords checker

Checking user passwords for presence in the specified dictionary.

## Configuration

Configuration via environment variables.

- LDAP_URL: (e.g. <ldap://ipa.example.com>)
- LDAP_BIND_DN: Bind DN for LDAP.
- LDAP_PASSWORD: LDAP password.
- LDAP_USERS_BASE_DN: Base DN for users. (e.g. cn=users,cn=accounts,dc=ipa,dc=example,dc=com)
- LDAP_FILTER: Ldapsearch filter. Please note, it is used in complex filter like `(&({self.ldap_filter})(!(nsaccountlock=TRUE)))`
- LDAP_PASSWORDS_FILE: Password dictionary. Default value - `wordlist`
