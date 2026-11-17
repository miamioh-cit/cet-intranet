# Staff tools

The public homepage keeps all seven student resources. Five administration links
now live at `/admin/`, with a small Staff login link in the homepage footer.
The existing theme and favorites work on both pages; admin favorites appear only
on the admin page. The browser supplies the username/password prompt.

## Before deploying

1. Confirm the intranet uses HTTPS and still requires campus or VPN access.
   The manifests in this repository do not configure TLS or the VPN restriction;
   verify those at the actual network entry point before entering staff passwords.
2. Create an htpasswd file with a separate account for each approved staff member.
   Use an interactive password prompt, not a password in a shell command. For
   example, Apache `htpasswd -cB htpasswd STAFF_USERNAME` creates the first account;
   omit `-c` when adding accounts so existing users are preserved.
3. In Rancher, create a Secret named `intranet-admin-auth` in each deployment's
   namespace, with a key named `htpasswd` containing the file's contents.
   Keep the file and its hashes outside GitHub and outside the container image.
4. Deploy and verify Dev before approving production. The existing Jenkinsfile
   deploys to both environments automatically; it has not been changed here.

The Secret mounts read-only outside the website folder. It is optional so a
missing Secret does not take the student homepage down. Nginx still denies admin
access: missing credentials get 401; supplied credentials with no password file
are denied access. Set up the Secret before offering staff login.

Check `/admin`, `/admin/`, and `/admin/index.html`: anonymous visitors must never
receive admin content, wrong passwords must fail, and approved accounts must work.
Check the student homepage, advising page, themes, favorites, and the logo too.

Remove an account from the Secret's htpasswd contents to revoke it. Directory
Secret mounts allow updates without baking passwords into a new image; allow for
Kubernetes propagation. Browser Basic Auth has no reliable site logout button.

This protects the admin directory only. Jenkins, Rancher, Proxmox, vCenter, and
Trello still require their own access controls. Existing student links are retained,
including the Rancher link that shares its destination with the admin Rancher card.

No changes are required to Backstage, its data, or its deployment pipeline.
