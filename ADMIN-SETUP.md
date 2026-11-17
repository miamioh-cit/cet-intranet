# Staff sign-in

Seven student tools remain on the public homepage. Staff resources and administration tools live at
`/admin/`. Signed-out visitors are redirected to the branded `/login/` page.
The design includes username/password fields and a password visibility toggle.
Staff can change their own password while signed in and sign out using the
buttons at the bottom of the admin page. Theme remains at the right of the header. Student links, branding, themes, and
favorites remain unchanged; admin favorites are displayed only on the admin page.

## Accounts in Rancher

Create a Secret named `intranet-admin-auth` in each deployment's namespace.
It needs a key named `htpasswd` containing separate bcrypt password hashes for
approved staff. The usernames in this file are the permitted accounts; there is
no public registration. Never commit this file or passwords to GitHub.

Using Apache htpasswd, create the first account with:

```
htpasswd -cB -C 12 htpasswd STAFF_USERNAME
```

Enter the password at the prompt. To add more accounts, omit `-c` so the existing
accounts are preserved:

```
htpasswd -B -C 12 htpasswd ANOTHER_USERNAME
```

The supported format is bcrypt (`$2a$`, `$2b$`, or `$2y$`) with cost 8–14.
Usernames can contain letters, numbers, underscores, dots, @, and hyphens, up to
64 characters. Passwords must fit bcrypt's 72-byte input limit.

Create or update the Secret in Rancher with the file contents as the `htpasswd`
key. Do not use the file as a ConfigMap. The deployed authentication service reads
the Secret through the Kubernetes API. It is also mounted read-only outside the
web folder for compatibility. If absent or invalid, the student homepage stays up and sign-in displays
a configuration error; protected tools remain inaccessible.

## Change password while signed in

The Change password button at the bottom of the page opens a dialog asking for the current
password, new password, and confirmation. New passwords must have at least 12
characters and fit the 72-byte bcrypt limit. Successful changes sign out all of
that account's existing sessions, and the user signs in with the new password.
Staff cannot choose a different username in this operation. Forgotten passwords
still require an authorized administrator to replace that account's hash in the
Secret; this release does not implement email recovery.

The deployment manifests create one dedicated ServiceAccount, Role, and
RoleBinding per environment. They grant only get and patch access to the named
intranet-admin-auth Secret in that namespace. The API token is projected only
into the staff-auth container, not Nginx. Changes check the current hash and
the Secret's resourceVersion before replacing htpasswd, so simultaneous edits
cannot silently overwrite another user's changes. The API connection verifies
the Kubernetes CA certificate. Jenkins needs permission to apply these
namespace-scoped RBAC resources before this release is deployed.

Account entries are created in Rancher, not in source code. To add staff, generate
a separate bcrypt entry for each username and include all entries, one per line,
in the same htpasswd value. Replacing one account must preserve the other lines.

## Temporary HTTP access

At the owner's request, the Dev and Prod manifests currently set
`AUTH_ALLOW_HTTP: "true"` on the `staff-auth` container so login works while the
HTTPS certificate request is pending. HTTP does not encrypt passwords or session
cookies. Use temporary passwords that are not reused for university accounts or
other systems. Campus/VPN network restrictions must remain in place.

When the certificate is installed:

1. Configure HTTPS for the existing hostname at the actual ingress/proxy and
   redirect HTTP traffic to HTTPS.
2. Confirm the proxy supplies `X-Forwarded-Proto: https` to Nginx.
3. Change `AUTH_ALLOW_HTTP` to `"false"` in both repository deployment manifests
   and deploy that change. Otherwise a subsequent deployment would re-enable it.
4. Replace temporary passwords in the Secret. Active sessions using changed
   password hashes are revoked after the Secret update reaches the pod.

HTTPS sessions use Secure, HttpOnly, SameSite=Strict cookies with a __Host prefix.
Temporary HTTP sessions use a separate HttpOnly, SameSite=Strict cookie.
Sessions expire after 30 minutes idle or eight hours total. Restarting the auth
container signs everyone out; it does not remove accounts. Cookies are random
session identifiers, never plaintext passwords. Passwords are not saved in browser
storage. Failed attempts are rate-limited; cross-site login/logout requests fail.

## Deployment

The same Docker image contains Nginx and the staff authentication code. The
existing deployment gains a small `staff-auth` container inside the same pod,
using that same image tag; no separate Rancher application is needed. It listens
only on the pod's loopback interface. The existing Jenkinsfile tags both container
images through its existing substitution and deploys Dev and Prod automatically.
The Jenkinsfile has not been changed. The new Docker build installs the pinned
`bcryptjs` dependency using npm ci and runs the authentication tests first.

Dev and Prod Services additionally select their own intranet-environment pod
label. This prevents either Service from selecting the other environment's pod
when both are in the same namespace. Existing immutable Deployment selectors
are unchanged. Each environment still uses a single replica, because sessions
are held in memory rather than a shared session database.

Deploy and verify Dev before production where your deployment process allows it.
Check public student links, the logo, themes, and favorites; signed-out access to
`/admin/` and `/admin/index.html` must redirect to login. Check correct/incorrect
passwords and Sign out. No staff account data or live Rancher configuration is
created by committing these files. Credentials must be configured separately.

This intranet has no project database. The change does not alter Backstage,
existing VMs, or project data. Jenkins, Rancher, Proxmox, vCenter, and Trello still
need their own access controls. The student Rancher link retains its existing
destination, which is shared with the staff Rancher card.
