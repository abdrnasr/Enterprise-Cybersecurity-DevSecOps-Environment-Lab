# VMs Download and Setup
## Downloading
Here again, we can utilize the same ISO image we downloaded to initialize two more VMs, namely an IAM VM and an Application server VM.
## Setup 
The setup for these two new virtual machines is similar. However, this time, instead of connecting them to the **DMZ host-only network**, we will connect them to the internal network. This ensures both networks remain separate.

 **Note: [Keycloak](https://www.keycloak.org/high-availability/concepts-memory-and-cpu-sizing) requires a base of 1250 MB of memory, so ensure to provide sufficient memory for that VM.**
## Firewall Setup

Since we have not added any rules to route traffic from the internal network to outside, we need to add that to the router to be able to access the internet.

```bash
sudo iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -o enp0s3 -j MASQUERADE
```

This rule will allow the firewall to route external traffic back to the internal servers, so that the IAM and APP servers can get internet access. 

## Network Configuration Setup
We also need to configure the network interfaces on both new VMs. As an example, the following can be used to configure the `IAM VM`:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.20.3/24]
      routes:
        - to: 0.0.0.0/0
          via: 192.168.20.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

## Testing

We do not need any additional setup for now, because now the communication between the internal and DMZ server's is open (i.e, the firewall can route between the internal network and the DMZ without problems). We can prove this by attempting to `ping`/`curl` the reverse proxy.

### IAM to DMZ Curl
<p align="center">
  <img src="images/IAM_Curl.png">
</p>

### DMZ to IAM Ping
<p align="center">
  <img src="images/DMZ_Ping_IAM.png">
</p>

---
# IAM Installation
Here, I will be using `Keycloak` as an IAM solution for this environment. The steps for download and installation are described [here](https://www.keycloak.org/getting-started/getting-started-zip). 

## Keycloak
`Keycloak` is a powerful open-source Identity and Access Management (IAM) solution that centralizes authentication and authorization across an enterprise network, providing a single source of truth for user roles and permissions. By consolidating access control, organizations can easily make changes to roles and permissions that propagate across all integrated applications, ensuring consistent security policies while reducing administrative overhead. It offers robust security features such as Single Sign-On (SSO), Multi-Factor Authentication (MFA), and centralized session management, while supporting industry-standard protocols like OpenID Connect, OAuth 2.0, and SAML 2.0 for seamless interoperability. Keycloak integrates smoothly with enterprise systems, including LDAP, Active Directory, and third-party identity providers, and its extensibility allows for custom authentication flows and identity brokering. 

For our project's use, we will define users and roles, and these roles will be used in our app. Instead of managing users directly in our app (e.g., create a table for users), all credentials and roles are stored and dealt with in the IAM. In our app, we only communicate with the IAM to verify the user and their allowed actions.

## Downloading and Running Keycloak

We first need to download `OpenJDK21` as it is required to run the IAM.
```bash
sudo apt install openjdk-21-jdk
```

Then, we download and unzip the latest version of `Keycloak`.
```bash
sudo wget https://github.com/keycloak/keycloak/releases/download/26.3.2/keycloak-26.3.2.zip
```
 **Note: This URL uses the version 26.3.2; the most recent version as of the making of this lab.**

I chose to download the IAM at `/opt/keycloak`, as this is what is recommended.
```bash
unzip keycloak-26.3.2.zip
```
After unzipping, navigate inside the unzipped folder, and setup your temp admin account:

```bash
bin/kc.sh bootstrap-admin user --username admin
```

You will be asked to create a password for the admin account. Then you can run `Keycloak`.

```bash
sudo bin/kc.sh start-dev
```

 **Note, this command runs the app in dev mode, which is not recommended for production systems.**

## Accessing the IAM web app
As a part of the setup procedure, you will need to visit the web app for keycloak, which will be hosted on the `IAM VM` at `http://localhost:8080`. However,  we cannot access that VM directly, and there are multiple ways to deal with this problem. 

### 1. Temporary Firewall Routing
In this method, we add a mapping to the firewall to allow us to access the service externally. However, this method is not safe, since you will be exposing the entire IAM web app for external attackers (in product setting). This is because the firewall we are using is minimal, and cannot provide fine-grained access to the IAM endpoints.

### 2. SSH Proxy
Since we have access to the `DMZ VM`, we can relay our traffic using an SSH Proxy. This will work because the `DMZ VM` can reach the internal network currently. This method is the most secure method now, as it will guarantee that only those who have access to the `DMZ VM` can reach the internal IAM service. However, we will not be able to provide IAM access to external services, because only those connected to the proxy can access the IAM.

We can run a proxy through the SSH server in the DMZ using the following command, as an example:

```
ssh -D 9050 -q -C -N dmz@192.168.33.6
```

### 3. Nginx Reverse Proxy (Selected Method)
We can also configure the reverse proxy to forward external web traffic to an endpoint like `/sec`. This method is the best to use for this case because we can configure the reverse proxy to only expose the endpoints that are needed for external authentication (in production setting).

## Accessing Keycloak with Nginx
First we need to configure `Nginx` to forward any web traffic to `/sec/` to be forwarded to `Keycloak`. For my case, the config file was at `/etc/nginx/sites-available/default`.

```nginx
server {
    listen 80;
    #Note this IP may be different for you. Use your firewall's external IP 
    server_name 192.168.33.6;

    # Everything under /sec -> Keycloak
    location /sec/ {
        proxy_http_version 1.1;

        # Forward client info
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Keep /sec in the URI when passing to backend
        proxy_pass http://192.168.20.3:8080;

        # Don’t rewrite redirect headers automatically
        proxy_redirect off;
    }
}
```
We also need to rerun Keycloak to let it know that it is setting behind a proxy. An example command looks like this:

```bash
sudo bin/kc.sh start-dev --hostname 192.168.33.6 --http-relative-path /sec --proxy-headers xforwarded
```

 **Note: In the last two code snippets, the hostname 192.168.33.6 used is the firewall's address. In other words, we can consider it to be the external address of our environment.**

If everything went well, you should be able to access and login with the admin credentials that you have chosen. For me, I can now access the IAM through `http://192.168.33.6/sec`.

<p align="center">
  <img src="images/IAM_LoginPage.png">
</p>

 **Note: With this setup, the admin pages are exposed to external access, and should be closed. We could do that later, after we complete the setup process. Also, all traffic is not encrypted and credentials (and tokens issued by Keycloak) may be exposed with this setup.**

---
# Nginx TLS Encryption
To protect the traffic between any external user and the internal services, we must use TLS. We will use a self-signed certificate for now.

To generate a TLS certificate, you can use `openssl`. Ensure, you include the external IP address of your firewall in the certificate. For this project's case, the IP of the firewall `192.168.33.6`.

After generating a TLS certificate, we must make some changes to the `Nginx` config file. For example, this is how my config looks like:

```nginx
server {
    listen 80;
    # Again note the IP address
    server_name 192.168.33.6;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name 192.168.33.6;

    # TLS files
    ssl_certificate     /etc/nginx/tls/nginx.crt;
    ssl_certificate_key /etc/nginx/tls/nginx.key;

    # Sensible TLS defaults
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Optional but recommended once everything works (pins HTTPS usage)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Everything under /sec -> Keycloak
    location /sec/ {
        proxy_http_version 1.1;

        # Forward client info (so Keycloak knows real host/proto/IP)
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;

        # Preserve /sec in upstream request (note: NO trailing slash)
        proxy_pass http://192.168.20.3:8080;

        # Don’t auto-rewrite Location headers
        proxy_redirect off;
    }
}
```

If this works, you should be able to use HTTPs with the IAM. This also ensures that all http traffic is redirected to TLS, enforcing encryption on all communications with `Nginx`. 

<p align="center">
  <img src="images/DMZ_TLS.png">
</p>

There is red warning signifies that the certificate was not manually added as a trusted TLS certificate to the browser. You can add it manually in your browser's settings. However, in production environment, you either need to sign by a well-known certificate authority or by a local PKI in the company. For this lab's purpose, this will work fine.

---
<a id="keycloak-config"></a>

# Keycloak Configuration
For our app to work with Keycloak, we must first create a Keycloak client, visit keycloak at `https://192.168.33.6/sec` and create a client. A client is essentially a configuration that will allow our app to interact with `Keycloak` and exchange tokens.

- After login, you will see a client's tab to the left; click on it. 
- Then click on "Create Client"
<p align="center">
  <img src="images/Keycloak_Home.png">
</p>

- Choose a Client-ID and note it down, as it will be used in the APPs **.env file**.

<p align="center">
  <img src="images/Keycloak_Create_Client.png">
</p>

- Then ensure to choose Standard Flow, enable authorization and use S256 for PKCE.
<p align="center">
  <img src="images/Keycloak_Client_Step2.png">
</p>

- Finally, ensure you assign the correct IP address of your external interface for the firewall. For my case, the firewall sets on 1`92.168.33.6`.
<p align="center">
  <img src="images/Keycloak_Step_3.png">
</p>

 **Note, the IP address to use here should be your firewall external IP address, since we will be accessing this app externally.**

- After completing these steps, you can acquire the client secret (which is hidden on my screen):
<p align="center">
  <img src="images/Keycloak_Secret.png">
</p>

- We have not created any new realms for `Keycloak`, as we will be using the default realm **master**. 

---
# APP VM Setup
Next, we will prepare the `APP VM` to use an application that needs authentication and authorization based on `Keycloak`. For the purpose of this project, I have created a simple chatting app, which can be found [here](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM).

## Dependencies Installation
We require `node.js` and `MySQL` in addition to the `keycloak`.

### MySQL Setup
On the `App VM`, use the following sequence of commands to install `MySQL`.
```bash
sudo apt update
# Install MySQL server
sudo apt install mysql-server -y
# Start the service
sudo systemctl start mysql
# Enable MySQL to start on boot
sudo systemctl enable mysql
# Run the security script (recommended)
sudo mysql_secure_installation
```

Now we can configure and create the database that we need for the app. On the CLI, you can use **sudo** to access the `MySQL` server with full rights:

```bash
mysql -u username -p
```

Next, we will create the database that the app needs to store its content.
```bash
CREATE DATABASE IAM_CHAT_APP;
```
After this, we create a user the app can use to access the database. It must have the same read/write access levels required by the app (creating tables, selecting, updating). To do this the following command can be used:

```bash
CREATE USER 'chat_app_user'@'localhost' IDENTIFIED BY 'YourPassword';
```

This will create a user with username **"chat_app_user"** and that can only be accessed from **localhost**. Since we will run both the app server and the database on the same machine, this is applicable.

Next, we grant the user access to the database. It should have almost all access rights on the database, since it will be creating tables, adding & updating records, and querying  data.
```bash
GRANT ALL PRIVILEGES ON IAM_CHAT_APP.* TO 'chat_app_user'@'localhost';
```
You could be even more restrictive with access to this user. For example, the following will allow the the user to only select, insert, update, and create.

```bash
GRANT SELECT, INSERT, UPDATE, CREATE ON IAM_CHAT_APP.* TO 'chat_app_user'@'localhost';
```

This allows us to ensure that even if something went wrong with this account, it should only have as much rights as it needs and no more (Principle of least privilege).

Finally you apply the changes using:
```bash
FLUSH PRIVILEGES;
```

Now you should be able to login **without sudo** to the account.
```bash
mysql -u chat_app_user -p
```

## Node Installation

To install `node.js`, you should follow the guide that works for your environment[here](https://nodejs.org/en/download/).

After installation, you should be able to verify the installation by checking the version of the installed node packages. Example:

```bash
app@app:~$ nvm current
v22.18.0
app@app:~$ npm -v
10.9.3
app@app:~$ node -v
v22.18.0
```
Now we can clone the project inside the home folder of your account **~** folder (e.g, **/home/app**).

```bash
sudo git clone https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM.git
```
Now you can go into the folder and install the dependencies:

```bash
cd ~/Chat-App-with-Keycloak-IAM/ && npm install
```
Finally, we need to configure the environment variables as explained in [here](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM?tab=readme-ov-file#variable-explanation).

```ini
### Example Setup:
# You generate this
AUTH_SECRET="A_SECRET_AUTH"

# Note the IP address. This will cause us an issue when trying to reach keycloak server from the node app.
# The address to the master realm, as we have used the default master realm
KEYCLOAK_ISSUER=https://192.168.33.6/sec/realms/master
# The client ID you chose
KEYCLOAK_CLIENT_ID=chat-app
# Client Secret that keycloak generated
KEYCLOAK_CLIENT_SECRET="GENERATED_BY_KEYCLOAK"

# The public IP address of the app
NEXTAUTH_URL=https://192.168.33.6/

## Use the credentials that you have already setup in MySQL
DATABASE_NAME=IAM_CHAT_APP
DATABASE_URL="mysql://chat_app_user:your_db_pass@localhost:3306/IAM_CHAT_APP"
## You generate this too.
SEEDING_SECRET="A_SEEDING_SECRET"
```

### Keycloak Certificate
To be able to interact with Keycloak using HTTPs (and encrypt traffic), you need a TLS certificate. For the purpose of development, you can issue your own certificate and self sign it. However, next-auth may fail, because it requires a properly signed certificate. You can disable this check in multiple ways. For example, you could either disable certificate validation, or you could pass the path to the certificate in the following environment variable:

```ini
NODE_EXTRA_CA_CERTS=/path/to/pem/cert 
```
For example, before running node, this command can be run:
```bash
export NODE_EXTRA_CA_CERTS=/home/app/Chat-App-with-Keycloak-IAM/192.168.33.6.pem
```
 **Note, this is the same certificate we created for Nginx. We add it here manually to tell node to trust this certificate.**
## App VM to DMZ Connection Problem Discussion

Since we will be using the endpoint https://192.168.33.6/sec to access `keycloak` from the browser AND the APP server, a problem can arise. The reason for the problem is caused by how OPEN ID connect works, our network setup, and NAT.

### Browser To Keycloak
As the first step in an `OpenID connect` authentication sequence, the APP server will redirect the user to `keycloak` for login. The browser will then access keycloak at https://192.168.33.6/sec/realms/master without issues. As an external computer of the network, we have already configured the firewall and Nginx to do this.
<p align="center">
  <img src="images/ADMIN_Keycloak_Access.png">
</p>

### Browser To App
Next after providing the credentials, the user will be redirected to the node app on behalf of `keycloak`, which we will configure later in Nginx https://192.168.33.6/.

### App Server to Nginx
However, a problem occurs when the App server tries to connect to `Nginx`  through the **EXTERNAL IP ADDRESS** of the firewall. This problem is caused by our choice for the environment variable:
```ini
KEYCLOAK_ISSUER=https://192.168.33.6/sec/realms/master
```
This value will not only be used by the browser, but also the app server will use it as the last step to acquire the ID/Access token from `keycloak`.

### Nat Hairpinning
- When a device inside your LAN tries to access your own public IP address (instead of the private one), the request goes out to the router/firewall, then back inside to the server.
- Many NAT devices don’t handle this well by default.
- The packet leaves with a private source address, hits the NAT, and then the router doesn’t know how to **reflect** it back inside.
- Result: You can reach your server from the **outside world** using the public IP, but not from inside your **own network**.

So, accessing `keycloak` from the app server using https://192.168.33.6/sec/realms/master is not possible, and you can prove this by attempting to curl from the app server:

<p align="center">
  <img src="images/APP_Curl_No_Rule.png">
</p>

This is problematic, because the APP server must be able to connect to `keycloak` through this IP.

## A Solution To The Problem

A simple and straight forward solution is to configure the firewall inside the `APP VM` with the following command:

```bash
iptables -t nat -A OUTPUT -d 192.168.33.6 -p tcp --dport 443 -j DNAT --to-destination 192.168.10.2:443
```
 **Note: Please note this is added to `IPTables` of the `APP VM`, NOT the `firewall VM`. You can definitely add a similar rule to the firewall, but this one will only work if used in the `APP VM` firewall.** 

Essentially, this command states that, whenever a packet is generated by the APP server that has a destination of **192.168.33.6:443**, it must be replaced with the destination **192.168.10.2:443**. This simple but effective rule resolves the NAT hairpinning issue. The important thing here is that the node app will connect to https://192.168.10.2/sec instead of https://192.168.33.6/sec unknowingly, which avoids the NAT problem. 

With this rule added, we can access the `Nginx server` from `APP VM` using the **EXTERNAL IP ADDRESS**:

<p align="center">
  <img src="images/APP_DMZ_EXTERNAL.png">
</p>

This means that now, the APP server can exchange tokens with `Keycloak` through `Nginx`.

## New Nginx Config
The following `Nginx` config file:
- Adds the APP server as a destination when the root address **/** is requested
- Takes into account that we may get direct traffic from the APP server which will have a destination of `192.168.10.2`

```nginx
server {
    listen 443 ssl http2;
    # Note the external IP will depend on your network
    server_name 192.168.33.6 192.168.10.2 mymachine;

    # TLS
    ssl_certificate     /etc/nginx/tls/nginx.crt;
    ssl_certificate_key /etc/nginx/tls/nginx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Base path "/" -> Next.js at 192.168.10.2:3000
    location / {
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket/HMR (safe to keep even in prod)
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_pass http://192.168.20.2:3000;
    }

    # Keycloak under "/sec" -> 192.168.20.3:8080
    # Keep the /sec prefix; do NOT rewrite/strip it.
    location /sec/ {
        proxy_http_version 1.1;

        proxy_set_header Host               $host;
        proxy_set_header X-Real-IP          $remote_addr;
        proxy_set_header X-Forwarded-For    $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  $scheme;
        proxy_set_header X-Forwarded-Host   $host;

        proxy_pass http://192.168.20.3:8080;  # no trailing slash
        proxy_redirect off;
    }

    client_max_body_size 20m;
}

server {
    listen 80;
    # Be careful, this IP is the external IP of MY firewall VM, you must use urs
    server_name 192.168.33.6;
    return 301 https://$host$request_uri;
}
```
Now, reload `Nginx` to reflect the new changes.

## ChatApp on Startup
Now that we have fully configured the chat-app, you may want register it to run on startup. You could do this with the help of `systemd`. This will ensure that you do not have to run the app manually after any system reboot.

---
# Extra Keycloak Configs

An advantage for using an IAM such as `Keycloak` is that we can delegate the entirety of authentication and authorization to the IAM. Our chat app will ONLY check the validity of the issued tokens, check the user info, and permissions. In our app, we will not be registering any users or granting permissions, as this is entirely done by the IAM.

In the IAM itself, you can create new users, grant different permissions and roles, and deal with identity and access control issues. Our app trusts the IAM and grants the user access based on their IAM records.

However, this means that you should need some control over the IAM you are using. For example, in `Keycloak` you can add roles to each user, while a public IAM does not provide that level of access to you.

## The Chat App Sign In Mechanism
For users to be able to use this app, you have to create accounts for them in the IAM itself. Once that is done, you can visit the website.

### User Creation
To create a user that can use the app, simply navigate to the Users tab to the left, and create user.

<p align="center">
  <img src="images/Keycloak_ViewerUser.png">
</p>

You can create as many users as you like and use any authentication method you want directly through the IAM.

## The Chat App Access Control

The app uses the JWT token issued by `keycloak` to determine the level of right's to grant a user. This token contains not only the user info, but the roles assigned to the user. The JWT token is validated for each request and access is granted to the user depending on the roles assigned to the user.

```typescript
// Each role has a list of allowed permissions
const ROLE_PERMISSIONS: Record<string, readonly string[]> = {
  'chat-admin': ["post.create", "post.edit", "post.delete", "post.view"],
  'chat-editor': ["post.create", "post.edit", "post.view"],
  'chat-user': ["post.view", "post.create"],
};

// Check if a user has a ROLE with the specific permission
export function hasPermission(roles: string[], permission: string): boolean {
  return roles.some(role => ROLE_PERMISSIONS[role]?.includes(permission));
}
```
As the above code shows, the hasPermission function is passed an array of roles for the user and it sees if this user has access rights based on the ROLE_PERMISSION matrix.


```typescript
# Some Examples
const hasDeleteAccess = hasPermission(["chat-admin"],"post.delete")
# True
const hasEditAccess = hasPermission(["chat-user"],"post.delete")
# False
```

## Creating Roles
As you saw, the matrix has three roles which we can create in `Keycloak` and assign to users. These roles are important to assign in `Keycloak` since we will be relying on it to allow/disallow certain actions executed by the user.

### Keycloak Roles
By default, the JWT token will contain the roles that are assigned to the users. However, they must be explicitly defined and assigned. To create roles, you can either create realm-wide or client-only roles (the client is the chat-app configuration that we created). For my case, I created three roles under the client:

<p align="center">
  <img src="images/Keycloak_User_Roles.png">
</p>

### Roles Assignment
After that, you can assign roles to the users. For example, this user will only be granted the role of chat-user, which only allows the user to view and create posts (messages). 

<p align="center">
  <img src="images/Keycloak_ViewerPerms.png">
</p>

## Keycloak on Startup
Now that we have fully configured `keycloak` for our use, you may want register it to run on startup. You could do this with the help of `systemd`. 

---
# Testing
## Trying The Chat App
To test the app, navigate to `APP VM` to the directory where the chat app is located, ensure all environment variables and other services are correctly configured, and run the app.
```bash
npm run build
npm run start
```
After running the app, ensure that you create the required database tables. This can be easily done with the provided [seeding function](https://github.com/abdrnasr/Chat-App-with-Keycloak-IAM?tab=readme-ov-file#database-seeding).

## Access Keycloak
`Keycloak` is now accessible externally and the admins can now configure `keycloak`. In addition to admins, users located outside the network who want to use the chat app can do so. Since interacting with `keycloak` is a key part of the authentication process, some endpoints of `Keycloak` must remain exposed.

<p align="center">
  <img src="images/Keycloak_Signin_page.png">
</p>

## Accessing The Chat App
After successfully signing in with `Keycloak`, you will get redirect to the home page of the app which shows you the chat messages.

<p align="center">
  <img src="images/Chat_App_Messages.png">
</p>

Now you can write, create, or edit messages depending on which role you were assigned.

---
# Considerations
## Accessing Keycloak Externally
Currently, an admin can remotely configure `keycloak` and work with it, all endpoints are exposed. However, this is a security risk especially if the admins do not use hard passwords or use 2FA with `keycloak`. For that, you can "unexposed" some of the admin dashboards and only allow access to them from the DMZ computer. `Keycloak` provides [guidance](https://www.keycloak.org/server/reverseproxy#_exposed_path_recommendations) on how to do this, but we will not do this here for this project.

## Chat App
The chat app is now publicly exposed to the internet and our users can login externally. However, if users are not using strong passwords or their passwords/sessions get stolen, then the app can be accessed by unauthorized entities.

## APP VM to DMZ Connectivity Further Discussion
The solution that I have proposed to the NAT problem does not scale well if we have more computers on in the network. This is because adding firewall rules to every internal computer is error prone.

Also, if there are internal computers trying to use the Chat APP, say `192.168.20.5`, then they cannot use the public IP address of the firewall, rather they must use the IP of the DMZ computer.

Thus, a broader solution maybe needed. This can include configuring the firewall to correctly route traffic to the DMZ. In addition, we can host and run an internal DNS server, and rather than using a direct IP, we could rely on the DNS to resolve the IP address for us.

For example, assume we choose and register the domain name **enterpriseXYZ.com**. The following table shows how DNS may work here.
| User IP | DNS Server | Resolved IP|
|---------|--------|-------------|
| 192.168.33.2 (External User) | Public DNS Server | 192.168.33.6|
| 192.168.20.2 (Internal User) | Internal DNS Server | 192.168.10.2|

So, depending on the location of the user and the DNS they use, they will get a different IP address to connect to. Now, instead of accessing the app through direct IP address access we can request https://enterpriseXYZ.com, which will work seamlessly any where.

This DNS solution works well for larger scale networks, since we will only need to configure the IP address on two DNS servers, and not on every computer.

# Technical Summary

In this stage of the lab, the environment is expanded by introducing two additional virtual machines: one dedicated to `Identity and Access Management (IAM) with Keycloak` and another for `hosting the application`. Both are connected to the internal host-only network, which keeps them logically separated from the DMZ segment. This design ensures that external access is only possible through controlled paths while still allowing the internal servers to communicate with each other and reach the internet through the firewall.

The `IAM VM` is provisioned with sufficient resources to run Keycloak, which requires more memory than the earlier servers. Network configuration assigns static addressing and ensures that traffic from the internal network can be routed outward through the firewall. Connectivity tests confirm that the internal machines can reach the DMZ services and vice versa, establishing a functional baseline for later integration.

`Keycloak` is then deployed on the `IAM VM` to serve as the centralized identity and access management platform. It provides single sign-on, multi-factor authentication, session management, and integration with protocols such as `OpenID Connect and OAuth 2.0`. By consolidating user accounts, credentials, and roles within `Keycloak`, the lab eliminates the need for the application to manage its own user data. Instead, the application will delegate authentication and authorization checks to the `IAM`, simplifying administration and enforcing consistent policies across the environment.

Because the `IAM` service resides on the internal network, special considerations are required to make it accessible for external use cases. Several methods are evaluated, including direct exposure through the firewall, tunneling traffic through the DMZ via SSH, and relaying requests with the existing `Nginx reverse proxy`. The reverse proxy approach is selected, as it provides the balance of accessibility and control needed for the project. `Nginx` is configured to only expose the required endpoints externally, enabling secure interaction between outside clients and the IAM service.

To further improve security, **TLS encryption** is added using a **self-signed certificate**, ensuring that communications with `Keycloak` are encrypted even if the certificate is not trusted by default in a browser. With these measures in place, the IAM is accessible at a controlled external address through the proxy while continuing to protect the internal network from direct exposure.

Once `Keycloak` is operational, it is configured with clients, roles, and users. Clients define how external applications interact with the IAM, while roles are used to represent different levels of permissions. Users are then created and assigned appropriate roles, allowing the lab’s sample application to authenticate against `Keycloak` and receive authorization tokens that govern access rights.

On the `application VM`, a `simple chat application` is deployed as a proof of concept. This app uses a database backend for storing data and integrates directly with the IAM service for authentication. The environment variables and configuration files of the app reference `Keycloak` as the identity provider. When users access the application, they are redirected to `Keycloak` for login, and their tokens determine which actions are permitted based on their assigned roles. **Role-based access control** is enforced directly by validating the tokens for each request.

During testing, challenges are encountered with how the application server communicates with the IAM due to `NAT hairpinning`. This occurs when internal machines attempt to reach a service through its external address, which can cause failures in environments without proper **NAT reflection**. The lab discusses this limitation and demonstrates that while simple fixes exist for the single app server, larger environments would benefit from solutions like `DNS split-horizon`, where internal and external users resolve the same service to different addresses.

By the end of this stage, the lab environment successfully demonstrates a secure architecture where authentication and authorization are centralized through `Keycloak`, external access is mediated by a reverse proxy with TLS encryption, and an application integrates seamlessly with the IAM for identity verification and **role-based control**. This setup closely mirrors real enterprise environments where separation of duties, secure access, and centralized management are essential.
