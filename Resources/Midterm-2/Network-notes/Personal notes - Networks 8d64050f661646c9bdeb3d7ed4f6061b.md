# Personal notes - Networks

# ➡️ 1. Firewalls

When configuring firewalls in our exercises we used `iptables` which only support IPv4, so it is important to **disable IPv6** in each machine when it is turned on. This is done by editing the `/etc/sysctl.conf` file with the following code snippet and applying those changes with `sudo sysctl -p`.

```bash
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Also make sure to install all the packages/software on the main/root machine from which you make copies from.

For configuring firewalls use the script template available at:

`git clone [https://github.com/lem-course/isp-iptables.git](https://github.com/lem-course/isp-iptables.git)`

Then just use `sudo ./iptables1.sh reset` when making changes and testing.

## 1.1. Protocols and their ports

| Protocol | Port | Transport protocol |
| --- | --- | --- |
| SSH | 22 | TCP |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| ICMP | / | ICMP |
| DNS | 53 | UDP |
| ISAKMP | 500 | UDP |
| NAT-T | 4500 | UDP |
| IPSec | / | AH/ESP |

## 1.2 Packet filters (stateless)

Examples of rules:

```bash
# SSH
# - Allow outgoing SSH connections
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT  -p tcp ! --syn --sport 22 -j ACCEPT

# - Allow incoming SSH connections
iptables -A INPUT  -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
```

In this weeks exercise we just defined the in/out traffic for several protocols: ssh, http, https, icmp (defined type of icmp request).

## 1.3 Statefull filters

### Exercise 1: INPUT, OUTPUT traffic

Focus on the state of the connection: NEW, ESTABLISHED, RELATED, INVALID

When writing rules we can use the following trick. Before hand **allow only established and related** traffic for both **in** and **out traffic** and then just for **each specific protocol allow only new connections**.

```bash
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

```bash
# SSH
# - Allow outgoing SSH connections to remote SSH servers
iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# - Allow incomming connections to local SSH server
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT
```

Or combine multiple protocols into one single command

```bash
iptables -A OUTPUT -p tcp -m multiport --ports 22,80,443 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp -m multiport --ports 22,80,443 -m state --state NEW -j ACCEPT
```

### Exercise 2 - Forwarding

**Network example**

The additional assignment was to set forwarding rules. We did this on a simulated network with two clients and one router connecting both of their networks.

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled.png)

We configured the router machine to have 3 NICs, one connected to the internet (Nat network) and one for each internal network of both machines (client_subnet, server_subnet).

When doing **internal networks** you have to **configure their IPs manually** since they don’t have access to a DHCP server. Such configurations are done in the `/etc/netplan/01-network-manager-all.yaml` file and changes are applied with `sudo netplan apply`.

<aside>
💡 **Router**

</aside>

**Configure router’s IPs for both networks:**

```bash
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp-identifier: mac
    enp0s8:
      addresses: [10.0.0.1/24]
    enp0s9:
      addresses: [172.16.0.1/24]
```

**Enable routing for IPv4 so it works like a router**: 

`echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward`

**Enable internet-bound traffic from subnets (router working as nat)**: 

`sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE` 

Example of **forwarding rules** on the router:

```bash
# Allow routing of packets that belong to ESTABLISHED or RELATED connections.
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Forward pings
iptables -A FORWARD -p icmp --icmp-type echo-request -m state --state NEW  -j ACCEPT
```

<aside>
💡 **Client/Server**

</aside>

In netplan file we have to configure 3 things: assign them an IP, DNS server, and tell them to send packets through our router.

```bash
network:
  version: 2
  ethernets:
    enp0s3:
      # assign the IP address
      addresses: [10.0.0.2/24]
      # set the default route through isp
      routes:
        - to: default
          via: 10.0.0.1
      # use Google's DNS
      nameservers:
        addresses: [8.8.8.8]
```

# ➡️ 2. SSH

Generate SSH **server keys** (e.g. ed25519): 

`sudo ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key`

Show server’s public key fingerprint: 

`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`

Generate SSH **client keys** (e.g. ecdsa):

`ssh-keygen -t ecdsa`

## Authenticate client with public key

Enable public key authentication by sending public key to server and link to specific account:

`ssh-copy-id isp@$SERVER`

Disable password-based login attempts by editing the `/etc/ssh/sshd_config` file on server. Add `PasswordAuthentication no` , save and restart the SSH server with: `sudo service ssh restart`.

SSH connection configurations:

- Normal — `ssh isp@$SERVER`
- Force public key — `ssh -i ~/.ssh/id_rsa isp@$SERVER`
- Force username/password auth — `ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no isp@$SERVER`

## **Tunneling with SSH**

Create a tunnel **between our machine and the machine running the service and then access the service as if it was running on our machine. All requests that are sent through the tunnel will appear to the service as normal requests originating from localhost .

Configure Apache web server to only allow localhost connections by editing the `/etc/apache2/sites-available/000-default.conf` on the server, save the file and apply changes with: `sudo service apache2 reload` .

```bash
<Directory /var/www/html>
    Require ip 127.0.0.1/8
</Directory>
```

**Setup the tunnel with:**

`ssh -L 127.0.0.1:8080:127.0.0.1:80 -N $SERVER`

Now when visiting 127.0.0.1:8080 in web browser we get a response.

## **Reverse SSH Tunneling**

(A bit of extra configuring was done. Firstly we disabled IPv6, applied iptables rule to only allow outgoing ssh traffic from the server, and we removed the Apache configuration from before).

Similar to a normal SSH tunnel, the difference is in the agent that initiates the tunnel.

`ssh -R 127.0.0.1:8080:127.0.0.1:80 -N isp@$CLIENT`

Now when visiting 127.0.0.1:8080 in web browser we get a response.

# ➡️ 3. VPN (IPSec, IKE)

## 3.1 IPSec

IPSec is a **protocol suite** that provides security at the network layer: protects IP packets.

Consists of the following protocols:

- Authentication Headers **(AH)**
- Encapsulating Security Payloads **(ESP)**
- Security Associations **(SA)**

**Transport mode**

- Adds protection to the original packet
- Normally between two network hosts

**Tunneling mode**

- Creates a new IP packet that encapsulates the original one
- Normally between two network gateways: **used to set up VPNs**

So we have the available protocols and their modes in which we can use them to send protected data over the internet, but how do we know the decryption algorithms, keys, macs, etc.? We use SAs for this.

- SA are agreements between two peers on how to do crypto
- SA are stored in SA database (SADB)
- We use SPI to do lookups in the DB
- IPSec SAs are unidirectional, each IPSec connection has two SAs: inbound and outbound SAs

Internet Key Exchange (IKE) works in two phases:

- Phase 1: **establish ISAKMP SA**
    
    Establish a secure and authenticated communication channel to protect the management channel and further IKE communications
    
- Phase 2: **establish IPSec SA**
    
    Negotiate two uni-directional **IPSec SAs** to protect the actual data (with IPSec). Use ISAKMP SA to do this securely.
    

## 3.2 StrongSwan Documentation Links

### Examples:
- Road warrior PSK - [https://www.strongswan.org/uml/testresults4/ikev2/rw-psk-ipv4/](https://www.strongswan.org/uml/testresults4/ikev2/rw-psk-ipv4/)
- Road warrior X.509/cert and IP pool/virtual IP - [https://www.strongswan.org/uml/testresults4/ikev2/ip-pool/](https://www.strongswan.org/uml/testresults4/ikev2/ip-pool/)
- Road warrior RADIUS - [https://www.strongswan.org/testing/testresults/ikev2-stroke/rw-eap-md5-radius/](https://www.strongswan.org/testing/testresults/ikev2-stroke/rw-eap-md5-radius/)
- Net to net with cert - [https://www.strongswan.org/uml/testresults4/ikev2/net2net-cert](https://www.strongswan.org/uml/testresults4/ikev2/net2net-cert)
- AES_GCM_16_256 cipher suite - [https://www.strongswan.org/uml/testresults4/ikev2/alg-aes-gcm/index.html](https://www.strongswan.org/uml/testresults4/ikev2/alg-aes-gcm/index.html)

### Tutorials:
- Creating certificates 1 - [https://docs.strongswan.org/docs/5.9/pki/pkiQuickstart.html](https://docs.strongswan.org/docs/5.9/pki/pkiQuickstart.html)
- Creating certificates 2 - [https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-22-04](https://www.digitalocean.com/community/tutorials/how-to-set-up-an-ikev2-vpn-server-with-strongswan-on-ubuntu-22-04)
- IKEv2 Cipher Suites - [https://docs.strongswan.org/docs/5.9/config/IKEv2CipherSuites.html](https://docs.strongswan.org/docs/5.9/config/IKEv2CipherSuites.html)

## 3.3 Exercise

### 3.3.1 Network example

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled%201.png)

We use StrongSwan which is an open-source implementation of IKE.

### 3.3.2 Create a IPSec VPN Tunnel

<aside>
💡 The NICs and IP addresses setup of all 4 machines is identical in principal to the last network example.

</aside>

We have to configure the `/etc/ipsec.conf` and `/etc/ipsec.secrets` files on both routers. The routers will be using a pre-shared key to authenticate each other.

<aside>
💡 **hq_router**

</aside>

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn net-net
        leftsubnet=10.1.0.0/16
				leftid=@hq
        leftfirewall=yes
        right=$BRANCH_IP
        rightsubnet=10.2.0.0/16
        rightid=@branch
        auto=add
```

```bash
@hq @branch : PSK "secret"
```

Finally, restart the IPsec `sudo ipsec restart` so that the changes get loaded.

<aside>
💡 **branch_router**

</aside>

> The setup is exactly the same, only the left and right parameters are switched.
> 

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn net-net
        leftsubnet=10.2.0.0/16
        leftid=@branch
        leftfirewall=yes
        right=$HQ_IP
        rightsubnet=10.1.0.0/16
        rightid=@hq
        auto=add
```

```bash
@hq @branch : PSK "secret"
```

Finally, restart the IPsec `sudo ipsec restart` so that the changes get loaded.

### 3.3.3 Configure cipher suites
Which cipher suites are being used? Run `sudo ipsec statusall` to find out. Now change the configuration files `/etc/ipsec.conf` on both routers so that the the ESP and the IKE traffic will be secured with the following cipher suite: AES_GCM_16_256.

```bash
conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret
        ike=aes256gcm16-aesxcbc-modp2048!
	      esp=aes256gcm16-modp2048!
```

### 3.3.4 Establish the VPN Link

To establish the tunnel, invoke `sudo ipsec up net-net` on either router (**but only on one**).

### 3.3.5 Add road-warrior with PSK

On the `hq_router`, create a new IPsec connection that enables *RoadWarrior* scenarios, that is, allow remote users to connect to company's intranet. Such clients should receive a virtual IP from the `10.3.0.0/16` network.

For this we add another machine with only 1 NIC that is connected to the same “public” network. The public IP of this machine is denoted as `$RW_A_IP`

<aside>
💡 **hq_router**

</aside>

In the ipsec.conf and ipsec.secrets we append the following:

```bash
...
conn net-net
				leftsubnet=10.1.0.0/16,10.3.0.0/16
				...
conn rw
				leftsubnet=10.1.0.0/16,10.2.0.0/16
				left=$HQ_IP
				leftfirewall=yes
				leftid=@hq
				right=%any
				rightsourceip=10.3.0.0/16
				auto=add
...
```

```bash
...
# had '@hq' in front but was removed
: PSK "test"
...
```

run `sudo ipsec restart`

<aside>
💡 **rw_alice**

</aside>

```bash
config setup

conn %default
	ikelifetime=60m
	keylife=20m
	rekeymargin=3m
	keyingtries=1
	keyexchange=ikev2
	authby=secret

conn home
	left=$RW_A_IP
	leftsourceip=%config
	leftid=@rw_alice
	leftfirewall=yes
	right=$HQ_IP
	rightsubnet=10.1.0.0/16,10.2.0.0/16,10.3.0.0/16
	rightid=@hq
	auto=add
```

```bash
@rw_alice : PSK "test"
```

run `sudo ipsec restart`

<aside>
💡 **branch_router**

</aside>

We only need to change one small thing in the config file:

```bash
...
conn net-net
	...
	rightsubnet=10.1.0.0/16,10.3.0.0/16
	...
```

run `sudo ipsec restart`

Now on `hq_router` re-establish the original VPN connection with the remote branch with `sudo ipsec up net-net` .

And on `rw_alice` establish the new VPN connection to the HQ with `sudo ipsec up home` .

### 3.3.6 Authenticate HQ and branch with certificates (road warrior PSK)

**Create certificates**

Let’s designate `hq_router` as the CA and prepare all certificates and keys for clients (both routers).

First let’s install the tool for generating certificates: `sudo apt install strongswan-pki` 

Then we create temporary directory to hold all certs and keys, before we copy the files from it to our machines.

```bash
mkdir -p ~/pki/{cacerts,certs,private}
chmod 700 ~/pki 
```

Next we want to generate the main key and cert for CA.

```bash
pki --gen --type ed25519 --outform pem > ~/pki/private/caKey.pem

pki --self --ca --lifetime 3650 --in ~/pki/private/caKey.pem --dn "C=SL, O=UL-FRI, CN=VPN root CA" \
		--outform pem > ~/pki/cacerts/caCert.pem
```

Now we want to generate the keys and certificates for both machines/routers.

```bash
pki --gen --type ed25519 --outform pem > ~/pki/private/hqKey.pem
pki --gen --type ed25519 --outform pem > ~/pki/private/branchKey.pem
```

```bash
pki --pub --in ~/pki/private/hqKey.pem | pki --issue --lifetime 1825 \ 
		--cacert ~/pki/cacerts/caCert.pem --cakey ~/pki/private/caKey.pem --dn "C=SL, O=UL-FRI, CN=hq" \ 
		--san @hq --outform pem > ~/pki/certs/hqCert.pem

pki --pub --in ~/pki/private/branchKey.pem | pki --issue --lifetime 1825 \ 
		--cacert ~/pki/cacerts/caCert.pem --cakey ~/pki/private/caKey.pem --dn "C=SL, O=UL-FRI, CN=branch" \ 
		--san @branch --outform pem > ~/pki/certs/branchCert.pem
```

**Move certificates**

Next, copy the client's certificate and private key to the appropriate machines. Additionally, you will also have to copy the CA's certificate to both machines. Place files in the appropriate subfolders within `/etc/ipsec.d/`.

For `hq_router` (current machine) we can just copy the files into `/etc/ipsec.d/` by running: 

`sudo cp -r ~/pki/* /etc/ipsec.d/`

To move the appropriate files to branch_router we can use scp to copy it into its home directory and then move it into the right one.

```bash
sudo scp ~/pki/cacerts/caCert.pem $BRANCH_IP:~
sudo scp ~/pki/certs/branchCert.pem $BRANCH_IP:~
sudo scp ~/pki/private/branchKey.pem $BRANCH_IP:~
```

And now on `branch_router`:

```bash
sudo mv caCert.pem /etc/ipsec.d/cacerts/
sudo mv branchCert.pem /etc/ipsec.d/certs/
sudo mv branchKey.pem /etc/ipsec.d/private/
```

**Configure VPN connection**

`/etc/ipsec.conf` for `hq_router`:

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        #authby=secret

conn net-net
				leftcert=hqCert.pem
        leftsubnet=10.1.0.0/16,10.3.0.0/16
				leftid=@hq
        leftfirewall=yes
        right=$BRANCH_IP
        rightsubnet=10.2.0.0/16
        rightid=@branch
        auto=add

conn rw
				authby=secret # Road warrior is still PSK
				leftsubnet=10.1.0.0/16,10.2.0.0/16
				left=$HQ_IP
				leftfirewall=yes
				leftid=@hq
				right=%any
				rightsourceip=10.3.0.0/16
				auto=add
```

`/etc/ipsec.secrets` for `hq_router`:

Because we used a ED25519 key type we must use PKCS8, other examples are RSA and ECDSA.

```bash
: PKCS8 hqKey.pem

# had '@hq' in front but was removed
: PSK "test" # Road warrior is still PSK
```

`/etc/ipsec.conf` for `branch_router`:

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        #authby=secret

conn net-net
				leftcert=branchCert.pem
        leftsubnet=10.2.0.0/16
        leftid=@branch
        leftfirewall=yes
        right=$HQ_IP
        rightsubnet=10.1.0.0/16,10.3.0.0/16
        rightid=@hq
        auto=add
```

`/etc/ipsec.secrets` for `branch_router`:

Because we used a ED25519 key type we must use PKCS8, other examples are RSA and ECDSA.

```bash
: PKCS8 branchKey.pem
```

Finally restart ipsec on both machine with: `sudo ipsec restart` and the establish the connection on for example the `hq_router` by running: `sudo ipsec up net-net`

### 3.3.7 Convert road warrior to use certificates

<aside>
💡 use `hq_router` to create a key and certificate for the road warrior and copy the necessary files onto the machine at `/etc/ipsec.d/`

</aside>

`/etc/ipsec.conf` for `hq_router`:

```bash
...
conn rw
				#authby=secret
				leftcert=hqCert.pem
				leftsubnet=10.1.0.0/16,10.2.0.0/16
				left=$HQ_IP
				leftfirewall=yes
				leftid=@hq
				right=%any
				rightsourceip=10.3.0.0/16
				auto=add
```

`/etc/ipsec.secrets` for `hq_router`:

```bash
: PKCS8 hqKey.pem
```

`/etc/ipsec.conf` for `rw_alice`:

```bash
config setup

conn %default
				ikelifetime=60m
				keylife=20m
				rekeymargin=3m
				keyingtries=1
				keyexchange=ikev2
				#authby=secret

conn home
				leftcert=rwAliceCert.pem
				left=$RW_A_IP
				leftsourceip=%config
				leftid=@rw_alice
				leftfirewall=yes
				right=$HQ_IP
				rightsubnet=10.1.0.0/16,10.2.0.0/16,10.3.0.0/16
				rightid=@hq
				auto=add
```

`/etc/ipsec.secrets` for `rw_alice`:

```bash
: PKCS8 rwAliceKey.pem
```

Finally restart ipsec on both machine with: `sudo ipsec restart` and the establish the connection on the `rw_alice` machine by running: `sudo ipsec up home`

# ➡️ 4. AAA (RADIUS)

- AAA enables users to access resources for which they are authorised
- AAA serves for logging and accounting to support business requirements (from billing to resources management)
- AAA systems aim at user friendliness by focusing on **single sign-on** principle and supporting business requirements

## RADIUS

It is based on client-server model, where client is called **Network Access Server (NAS)**

End users, which access the system are therefore not considered clients of the RADIUS server, but as a client of NAS.

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled%202.png)

The protocol works so that the end user sends the appropriate data to the NAS which then forwards it to the RADIUS server. The RADIUS server then accepts or denies the request and send the NAS the appropriate configuration, the NAS then allows or denies access to the end user.

### RADIUS messages:

- **Access Request**: generated by NAS and sent to the server.
- **Access Challenge**: generated by a server and sent to NAS to provide challenge for the end-user.
- **Access Accept**: generated by server and sent to NAS after successful authentication and provides permission to access resources.
- **Access Reject**: This message is sent from server and requires from NAS to block access.
- and 4 other…

RADIUS uses UDP/1812-181.

A packet consists of a header and at least one attribute-value pair (AVP).

AVPs are encoded as “type-length-value” or TLVs

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled%203.png)

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled%204.png)

RADIUS **security** employs attribute hiding and authentication. Both based on one-way hash function (MD5) and a shared secret between server and NAS.

RADIUS support **roaming** (accessing the other administrative entity’s network resources) by chaining NAS clients → **Proxy**

We use FreeRADIUS package to implement RADIUS servers in exercises. First two exercises use only one machine, the third one uses two machines.

## Exercise 1 - RADIUS server with simple client

Add a **new client** (NAS) inside the `/etc/freeradius/3.0/clients.conf` file by adding (should already be there):

```bash
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nas_type = other
}
```

Add a **new end-user** inside the `/etc/freeradius/3.0/users` file by adding:

```bash
"alice" Cleartext-Password := "password"
```

Start the **RADIUS** server **service in the foreground** to be able to observe log outputs:

```bash
sudo service freeradius stop
sudo freeradius -X -d /etc/freeradius/3.0
```

Try to **send a authentication request** using the command-line NAS client: 

`echo "User-Name=alice, User-Password=password" | radclient 127.0.0.1 auth testing123 -x`

## Exercise 2 - HTTP authentication with Apache and FreeRADIUS

Now we will configure the Apache HTTP server to act as a real NAS that has to authenticate users. Login will be required to allow access to Apache web server pages.

First, enable `auth_radius` module for apache and restart the apache server:

```bash
sudo a2enmod auth_radius
sudo service apache2 restart
```

Configure Apache Radius settings in `/etc/apache2/ports.conf`

```bash
# FreeRADIUS runs on localhost:1812 (standard RADIUS port).
# Apache will authenticate itself to the AAA server with PSK 'testing123'.
# The request shall time-out after 5 seconds, and retry at most 3 times.
AddRadiusAuth localhost:1812 testing123 5:3

# Next line configures the time (in minutes) in which the authentication cookie
# set by the Apache server expires
AddRadiusCookieValid 1
```

Next, tell Apache which pages require authentication. Open `/etc/apache2/sites-available/000-default.conf` and add the following lines inside `<VirtualHost *:80>` block (the folder `/var/www/html` is the root, so include all pages):

```bash
<Directory /var/www/html>
    Options Indexes FollowSymLinks MultiViews
    AllowOverride None

    # Use basic password authentication
    # AuthType Digest won't work with RADIUS
    AuthType Basic

    # Tell the user the realm to which they are authenticating.
    AuthName "RADIUS Authentication for my site"

    # Set RADIUS to be provider for this basic authentication
    AuthBasicProvider radius

    # Require that mod_auth_radius returns a valid user,
    # otherwise access is denied.
    Require valid-user
</Directory>
```

Reload Apache’s configuration file with `sudo service apache2 reload` and again start the FreeRADIUS server in the foreground.

When opening a web browser on `http://localhost` or using `curl --user alice:password http://localhost -v` you should be prompted to authenticate via username and password. After this you are able to see the web page.

## Exercise 3 - Roaming and federation

Let `$RADIUS1` and `$RADIUS2` denote the IP addresses of `radius1` and `radius2`, respectively.

On `radius1`, create a new domain (or realm) called `domain.com`. Open `/etc/freeradius/3.0/proxy.conf` and add the following:

```bash
home_server hs_domain_com {
        type = auth+acct
        ipaddr = $RADIUS2
        port = 1812
        secret = testing123
}

home_server_pool pool_domain_com {
        type = fail-over
        home_server = hs_domain_com
}

realm domain.com {
        pool = pool_domain_com
        nostrip
}
```

On `radius2`, create a new (local) domain called `domain.com`. Open `/etc/freeradius/3.0/proxy.conf` and add the following two lines:

```bash
realm domain.com {
}
```

On `radius2`, define a new AAA client (AAA proxy) and define its credentials. Open `/etc/freeradius/3.0/clients.conf`  and add the following lines.

```bash
client $RADIUS1 {
    secret = testing123
}
```

On `radius2`, create a new supplicant (end-user). Open `/etc/freeradius/3.0/users` and define:

```bash
"bob" Cleartext-Password := "password"
```

Perform the same test again from `radius1` . This time **use bob’s credentials**.

When opening a web browser on `http://localhost` or using `curl --user bob@domain.com:password http://localhost -v` you should be prompted to authenticate via username and password. After this you are able to see the web page.

In this case, the first AAA server, `radius1`  acts as a proxy and forwards the auth-request to the second AAA server, `radius2` which finally authenticates the user.

## Exercise 4 - VPN IPSec road warrior with RADIUS authentication

![Untitled](Personal%20notes%20-%20Networks%208d64050f661646c9bdeb3d7ed4f6061b/Untitled%205.png)

We will only be configuring and testing `router` and `rw` machines.

### Network setup

The `router` machine get the following `/etc/netplan/01-network-manager-all.yaml` config:

```bash
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp-identifier: mac
    enp0s8:
      addresses: [10.1.0.1/16]
```

The `server` machine get the following `/etc/netplan/01-network-manager-all.yaml` config:

```bash
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [10.1.0.2/16]
      routes:
        - to: default
          via: 10.1.0.1
      nameservers:
        addresses: [8.8.8.8]
```

Apply changes with `sudo netplan apply` .

Leave `rw` machine as is, with one NIC connected to public network.

`$ROUTER` and `$RW` are variables that define the public IPs of both machines.

### VPN setup for road warrior with virtual IP

Here the road warrior and VPN router still use PSK to authenticate.

`/etc/ipsec.conf` for `router`:

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn rw
				left=$ROUTER
        leftsubnet=10.1.0.0/16
        leftfirewall=yes
        leftid=@router
        right=%any
        rightsourceip=10.3.0.0/16
        auto=add
```

`/etc/ipsec.secrets` for `router`:

```bash
: PSK "test"
```

`/etc/ipsec.conf` for `rw`:

```bash
config setup

conn %default
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret

conn home
				left=$RW
				leftsourceip=%config
        leftfirewall=yes
        leftid=bob
        right=$ROUTER
        rightsubnet=10.1.0.0/16
				rightid=@router
        auto=add
```

`/etc/ipsec.secrets` for `rw`:

```bash
bob : PSK "test"
```

Now restart the background ipsec service with `sudo ipsec restart`, or start it in the foreground with `sudo ipsec start —nofork` or both machines!

From the `rw` machine establish the VPN connection with `sudo ipsec up home` .

The connection should be established successfully, running `ip addr` shows that we have a virtual IP of 10.3.0.1 and we can ping the private network of the router with `ping 10.1.0.1` .

### Use RADIUS server to authenticate road warrior

Add a new user to RADIUS server by adding the following line to `/etc/freeradius/3.0/users` on `router`:

```bash
"bob" Cleartext-Password := "password"
```

Update the `/etc/ipsec.conf` file on `router`:

```bash
...
conn %default
        ...
				# Remove authby
        # authby=secret
conn rw
				...
				# Add auth types
				leftauth=psk
				rightauth=eap-radius
```

Update the `/etc/ipsec.conf` file on `rw`:

```bash
...
conn %default
        ...
				# Remove authby
        # authby=secret

conn home
				...
				# Add auth types
				leftauth=eap
				rightauth=psk
```

Update the `/etc/ipsec.secrets` file on `rw`:

```bash
bob : PSK "test"
bob : EAP "password"
```

You'll have to install an additional package to connect Radius with StrongSwan: besides `strongswan freeradius freeradius-utils`, you'll also need to install the `libcharon-extra-plugins`. Then use file `/etc/strongswan.conf` to tell the StrongSwan how to connect to Radius.

Change the `/etc/strongswan.conf` on `router` to the following:

```bash
charon {
				load_modular = yes
				plugins {
								include strongswan.d/charon/*.conf
								# this is the part that you add
								eap-radius {
												secret = testing123
												server = 127.0.0.1
								}
				}
}
```

Restart the ipsec services on both machines, for good measure restart the radius server on `router`. Now when we establish a VPN connection from `rw` using `sudo ipsec up home`, the radius server is the one that authenticates us (as well as the router with PSK).