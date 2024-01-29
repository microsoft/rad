#!/bin/bash
sudo apt-get update
sudo apt-get install -y wget apt-transport-https software-properties-common
wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install -y powershell=7.2.0-1.deb
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
sudo /usr/bin/pwsh -command "Install-Module -Name Az -RequiredVersion 8.3.0 -AllowClobber -Force -Scope AllUsers"
sudo /usr/bin/pwsh -command "az extension add --name application-insights"
sudo /usr/bin/pwsh -command "Install-Module -Name Pester -Scope AllUsers -Force -SkipPublisherCheck"
sudo /usr/bin/pwsh -command "Update-Module -Name Pester -Scope AllUsers -Force"
sudo /usr/bin/pwsh -command "Install-Module -Name PSScriptAnalyzer -Scope AllUsers -Force -SkipPublisherCheck"

sudo apt install docker.io -y
sudo usermod -aG sudo [[ADMIN_USER_NAME]]
sudo usermod -aG docker [[ADMIN_USER_NAME]]

#load dotnet
sudo apt update
sudo apt install apt-transport-https -y
sudo apt install dotnet-runtime-3.1 -y

#Docker-Comppse Upgrade
sudo apt install curl -y
sudo apt-get update
# sudo apt-get upgrade -y
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/bin/docker-compose
sudo chmod +x /usr/bin/docker-compose

sudo curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo mv kubectl /usr/bin
sudo chmod +x /usr/bin/kubectl

sudo /usr/bin/pwsh -command "az config set extension.use_dynamic_install=yes_without_prompt"

# INSTALL BICEP RUNTIME
sudo curl -Lo bicep https://github.com/Azure/bicep/releases/latest/download/bicep-linux-x64
sudo chmod +x ./bicep
sudo sudo mv ./bicep /usr/local/bin/bicep

# INSTALL RUNNER SOFTWARE
cd /home/[[ADMIN_USER_NAME]]
RUNNER_BINARY="actions-runner-linux-x64-2.310.2.tar.gz"
RUNNER_DOWNLOAD_URL="https://github.com/actions/runner/releases/download/v2.310.2/actions-runner-linux-x64-2.310.2.tar.gz"
curl -o "${RUNNER_BINARY}" -L "${RUNNER_DOWNLOAD_URL}"

# RUNNER 0
RUNNER_DIRECTORY="actions-runner0"
RUNNER_NAME="[[RUNNER_NAME]]_0"
cd /home/[[ADMIN_USER_NAME]]
mkdir "${RUNNER_DIRECTORY}"
cp "./${RUNNER_BINARY}" "./${RUNNER_DIRECTORY}/${RUNNER_BINARY}"
cd "./${RUNNER_DIRECTORY}"
tar xzf "./${RUNNER_BINARY}"
sudo chown [[ADMIN_USER_NAME]]:[[ADMIN_USER_NAME]] -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
sudo chmod 777 -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
su [[ADMIN_USER_NAME]] -c "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/config.sh --url https://github.com/[[ORG_NAME]]/[[REPO_NAME]]/ --unattended --token [[TOKEN]] --name ${RUNNER_NAME} --labels [[LABEL]]"
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" install [[ADMIN_USER_NAME]]
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" start

# RUNNER 1
RUNNER_DIRECTORY="actions-runner1"
RUNNER_NAME="[[RUNNER_NAME]]_1"
cd /home/[[ADMIN_USER_NAME]]
mkdir "${RUNNER_DIRECTORY}"
cp "./${RUNNER_BINARY}" "./${RUNNER_DIRECTORY}/${RUNNER_BINARY}"
cd "./${RUNNER_DIRECTORY}"
tar xzf "./${RUNNER_BINARY}"
sudo chown [[ADMIN_USER_NAME]]:[[ADMIN_USER_NAME]] -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
sudo chmod 777 -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
su [[ADMIN_USER_NAME]] -c "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/config.sh --url https://github.com/[[ORG_NAME]]/[[REPO_NAME]]/ --unattended --token [[TOKEN]] --name ${RUNNER_NAME} --labels [[LABEL]]"
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" install [[ADMIN_USER_NAME]]
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" start

# RUNNER 2
RUNNER_DIRECTORY="actions-runner2"
RUNNER_NAME="[[RUNNER_NAME]]_2"
cd /home/[[ADMIN_USER_NAME]]
mkdir "${RUNNER_DIRECTORY}"
cp "./${RUNNER_BINARY}" "./${RUNNER_DIRECTORY}/${RUNNER_BINARY}"
cd "./${RUNNER_DIRECTORY}"
tar xzf "./${RUNNER_BINARY}"
sudo chown [[ADMIN_USER_NAME]]:[[ADMIN_USER_NAME]] -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
sudo chmod 777 -R "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}"
su [[ADMIN_USER_NAME]] -c "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/config.sh --url https://github.com/[[ORG_NAME]]/[[REPO_NAME]]/ --unattended --token [[TOKEN]] --name ${RUNNER_NAME} --labels [[LABEL]]"
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" install [[ADMIN_USER_NAME]]
sudo /bin/bash "/home/[[ADMIN_USER_NAME]]/${RUNNER_DIRECTORY}/svc.sh" start
