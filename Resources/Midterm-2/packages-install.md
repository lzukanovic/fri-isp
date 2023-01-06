# Copy text
> We install the following packages on the root VM before making clones from it so they have them installed already.

# Firewall packages
Install packages that will be used for testing firewall rules:
```
sudo apt-get install openssh-server apache2 curl git
```

- Generate default digital certificates for Apache2: `sudo make-ssl-cert generate-default-snakeoil --force-overwrite`
- Enable Apache2 SSL Site: `sudo a2ensite default-ssl`
- Enable Apache2 TLS/SSL module: `sudo a2enmod ssl`
- Restart Apache server: `sudo service apache2 restart`
- Check if Apache2 works by running the web browser and opening both http://localhost and https://localhost. Alternatively, test with curl.
- Check if SSH server works by running `ssh localhost`, answer with yes and provide password isp. Press ctrl+d to exit.

## Script
`git clone https://github.com/lem-course/isp-iptables.git`

# SSH packages
```
sudo apt update

sudo apt install openssh-server openssh-client wireshark apache2 curl
```

# VPN packages
```
sudo apt update

sudo apt install strongswan strongswan-pki libcharon-extra-plugins apache2 wireshark
```

# RADIUS packages
```
sudo apt update

sudo apt install freeradius freeradius-utils apache2 libapache2-mod-auth-radius wireshark libcharon-extra-plugins
```