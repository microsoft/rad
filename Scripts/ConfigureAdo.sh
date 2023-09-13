#!/bin/sh
sudo apt-get update
sudo apt-get install -y wget apt-transport-https software-properties-common
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y powershell
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
sudo /usr/bin/pwsh -command "Install-Module -Name Az -Scope AllUsers -Force"
sudo /usr/bin/pwsh -command "az extension add --name application-insights"
sudo /usr/bin/pwsh -command "Install-Module -Name Pester -Scope AllUsers -Force -SkipPublisherCheck"
sudo /usr/bin/pwsh -command "Update-Module -Name Pester -Scope AllUsers -Force"
sudo /usr/bin/pwsh -command "Install-Module -Name PSScriptAnalyzer -Scope AllUsers -Force -SkipPublisherCheck"

sudo apt install docker.io -y
sudo adduser AzDevOps
sudo usermod -aG sudo AzDevOps
sudo usermod -aG docker AzDevOps

#load dotnet
sudo apt update
sudo apt install apt-transport-https -y
sudo apt install dotnet-runtime-3.1

#Docker-Comppse Upgrade
sudo apt install curl -y
sudo apt-get update
sudo apt-get upgrade -y
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/bin/docker-compose
sudo chmod +x /usr/bin/docker-compose

sudo curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo mv kubectl /usr/bin
sudo chmod +x /usr/bin/kubectl

sudo echo "Version 1.0" > version.txt