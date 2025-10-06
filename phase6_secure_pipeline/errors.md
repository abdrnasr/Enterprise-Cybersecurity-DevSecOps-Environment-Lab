# Problems You May Run Into
## Connectivity Certificate Problem

```bash
Oct 02 03:22:58 app systemd[1]: chatapp@test.service: Consumed 2.529s CPU time, 141.7M memory peak, 0B memory swap peak.
Oct 02 03:22:58 app systemd[1]: Starting chatapp@test.service - Chatapp (test)...
Oct 02 03:22:58 app systemd[1]: Started chatapp@test.service - Chatapp (test).
Oct 02 03:22:59 app node[25568]:    ▲ Next.js 15.4.6
Oct 02 03:22:59 app node[25568]:    - Local:        http://localhost:3005
Oct 02 03:22:59 app node[25568]:    - Network:      http://192.168.20.2:3005
Oct 02 03:22:59 app node[25568]:  ✓ Starting...
Oct 02 03:22:59 app node[25568]:  ✓ Ready in 1077ms
Oct 02 03:23:14 app node[25568]: (node:25568) Warning: Setting the NODE_TLS_REJECT_UNAUTHORIZED environment variable to '0' makes TLS connections and HTTPS requests insecure by disabling certificate verificatio>
Oct 02 03:23:14 app node[25568]: (Use `node --trace-warnings ...` to show where the warning was created)
Oct 02 03:23:14 app node[25568]: [auth][error] TypeError: fetch failed
Oct 02 03:23:14 app node[25568]:     at node:internal/deps/undici/undici:13510:13
Oct 02 03:23:14 app node[25568]:     at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
Oct 02 03:23:14 app node[25568]:     at async aC (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:44559)
Oct 02 03:23:14 app node[25568]:     at async aO (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:47587)
Oct 02 03:23:14 app node[25568]:     at async aj (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:50257)
Oct 02 03:23:14 app node[25568]:     at async aD (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:54418)
Oct 02 03:23:14 app node[25568]:     at async rb.do (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:21059)
Oct 02 03:23:14 app node[25568]:     at async rb.handle (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:25902)
Oct 02 03:23:14 app node[25568]:     at async u (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:408:4128)
Oct 02 03:23:14 app node[25568]:     at async rb.handleResponse (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:1:104409)
```

The above logs show an error in the code that are not really helpful for debugging. However, if you ran into this problem, here are things to check:
- Is your `Keycloak` client configured correctly?
- Can you `reach` the `Keycloak` service with the URLs that you have provided?
    - Specifically can you reach it from your browser AND from the `APP VM`?
- Is DNS resolution functioning correctly?
    - You may need to add the mapping from `local.keycloak.com` to `192.168.20.2` in the `/etc/hosts` file.

    ```ini
    192.168.10.2 local.keycloak.com
    ```

- Was the TLS certificate added to node as a trusted certificate?
    - The certificate path can be added using the environment variable `NODE_EXTRA_CA_CERTS`
- Does the TLS certificate match the URL Keycloak is claiming?
    - This can happen if you use the wrong certificate.
- Are you using the correct certificate?
    - We have two certificates, and you should use the latest one.

If you have a similar setup to mine, those environment variables values should hopefully help you:

```ini
# /etc/chatapp/.env
AUTH_SECRET="UseYourOwnSecretHere"

## This configuration is the default configuration and will be used for publicly serving the app ##

# The public IP may not work from internal access
KEYCLOAK_ISSUER=https://192.168.33.6/sec/realms/master
KEYCLOAK_CLIENT_ID=chat-app
KEYCLOAK_CLIENT_SECRET="SecretGeneratedByKeycloak"
NEXTAUTH_URL=https://192.168.33.6/
DATABASE_NAME=IAM_CHAT_APP
DATABASE_URL="mysql://chat_app_user:YourDBPassword@localhost:3306/IAM_CHAT_APP"
###################################################################################################

SEEDING_SECRET="UseYourOwnSecretHere"

# The NEWEST certificate
NODE_EXTRA_CA_CERTS=/etc/chatapp/cert.pem
```

```ini
# /etc/chatapp/test.env

# NOTICE HOW THE IP CHANGED FROM 192.168.33.6 to local.keycloak.com
# THE IP WILL NOT WORK INTERNALLY AS WE COVERED BEFORE
KEYCLOAK_ISSUER=https://local.keycloak.com/sec/realms/master
KEYCLOAK_CLIENT_ID=chat-app-test
KEYCLOAK_CLIENT_SECRET="DifferentClientDifferentSecretGenerated"

NEXTAUTH_URL=http://192.168.20.2:3005/

# Here, we have a different database/user
DATABASE_NAME=IAM_CHAT_APP_TEST
DATABASE_URL="mysql://iam_test_user:YourPassword@localhost:3306/IAM_CHAT_APP_TEST"

PORT=3005

# You may uncomment this if you run into problems. However, this should not be used in production.
#NODE_TLS_REJECT_UNAUTHORIZED=0
```

```bash
# /etc/chatapp/blue.env
PORT=3001
```

```bash
# /etc/chatapp/green.env
PORT=3002
```

## Database Error 

```bash
Oct 02 03:37:43 app node[25605]: [auth][error] CallbackRouteError: Read more at https://errors.authjs.dev#callbackrouteerror
Oct 02 03:37:43 app node[25605]: [auth][cause]: Error: Login refused: user record error.
Oct 02 03:37:43 app node[25605]:     at Object.jwt (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:408:1287)
Oct 02 03:37:43 app node[25605]:     at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
Oct 02 03:37:43 app node[25605]:     at async aR (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:38392)
Oct 02 03:37:43 app node[25605]:     at async aj (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:49719)
Oct 02 03:37:43 app node[25605]:     at async aD (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:404:54418)
Oct 02 03:37:43 app node[25605]:     at async rb.do (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:21059)
Oct 02 03:37:43 app node[25605]:     at async rb.handle (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:25902)
Oct 02 03:37:43 app node[25605]:     at async u (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:408:4128)
Oct 02 03:37:43 app node[25605]:     at async rb.handleResponse (/srv/chatapp/release/2025-10-01T14-50-28/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:1:104409)
Oct 02 03:37:43 app node[25605]:     at async a (/srv/chatapp/release/2025-10-01T14-50-28/.next/server/chunks/node_modules_next_0561b23a._.js:408:5161)
Oct 02 03:37:43 app node[25605]: [auth][details]: {
Oct 02 03:37:43 app node[25605]:   "provider": "keycloak"
Oct 02 03:37:43 app node[25605]: }
```

This error indicates that the database might not have been seeded yet. So, you should seed it with the seeding endpoint.

## Keycloak Not Running

```bash
Oct 03 05:20:58 app node[10552]:  ✓ Ready in 1941ms
Oct 03 05:21:28 app node[10552]: [auth][error] nL: "response" is not a conform Authorization Server Metadata response (unexpected HTTP status code)
Oct 03 05:21:28 app node[10552]:     at nM (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:5182)
Oct 03 05:21:28 app node[10552]:     at nY (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:7271)
Oct 03 05:21:28 app node[10552]:     at aC (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:44600)
Oct 03 05:21:28 app node[10552]:     at process.processTicksAndRejections (node:internal/process/task_queues:105:5)
Oct 03 05:21:28 app node[10552]:     at async aO (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:47587)
Oct 03 05:21:28 app node[10552]:     at async aj (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:50257)
Oct 03 05:21:28 app node[10552]:     at async aD (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:404:54418)
Oct 03 05:21:28 app node[10552]:     at async rb.do (/srv/chatapp/release/2025-10-03T02-53-08/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:21059)
Oct 03 05:21:28 app node[10552]:     at async rb.handle (/srv/chatapp/release/2025-10-03T02-53-08/node_modules/next/dist/compiled/next-server/app-route-turbo.runtime.prod.js:5:25902)
Oct 03 05:21:28 app node[10552]:     at async u (/srv/chatapp/release/2025-10-03T02-53-08/.next/server/chunks/node_modules_next_0561b23a._.js:408:4128)
```

This error might occur if `Keycloak` is not running.