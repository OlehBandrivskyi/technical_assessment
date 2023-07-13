#!/bin/bash
sudo apt update -y &&
sudo apt install -y nginx
echo "Hello, bloxroute!" > /var/www/html/index.html
