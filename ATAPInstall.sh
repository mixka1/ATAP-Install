#!/bin/bash

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Download the PowerShell .deb package
echo "Downloading PowerShell..."
wget https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/powershell_7.4.5-1.deb_amd64.deb

# Install the downloaded package
echo "Installing PowerShell..."
dpkg -i powershell_7.4.5-1.deb_amd64.deb

# Start PowerShell and install ATAPAuditor module
echo "Starting PowerShell to install the ATAPAuditor module..."
pwsh -Command "Install-Module -Name ATAPAuditor -Force; Save-ATAPHtmlReport -ReportName 'Ubuntu 22.04'"

# Clean up by removing the downloaded .deb file
echo "Cleaning up..."
rm powershell_7.4.5-1.deb_amd64.deb

echo "PowerShell and ATAPAuditor installation complete!"

