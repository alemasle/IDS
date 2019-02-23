apt-get update
apt-get install -y apache2 curl
rm -rf /var/www
mkdir -p /var/www
cp -a /vagrant/www/* /var/www
chmod a+Xr -R /var/www/*
ln -fs /vagrant/hosts /etc/hosts
ln -fs /vagrant/000-default.conf /etc/apache2/sites-enabled/000-default.conf
a2enmod rewrite
systemctl restart apache2
mkdir -p /home/vagrant/.msf4 && touch /home/vagrant/.msf4/initial_setup_complete && chown vagrant:vagrant /home/vagrant/.msf4/initial_setup_complete 
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall

