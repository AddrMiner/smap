#!/bin/bash

# user input
defaultInstallPath="$HOME/smap"
read -r -p "Enter install path or press Enter for default($defaultInstallPath): " installPath
if [ -z "$installPath" ]; then
  installPath=$defaultInstallPath
fi
if [ ! -d "$installPath" ]; then
  mkdir -p "$installPath"  
fi
echo "smap will be installed to $installPath"

# 1. Install dependencies
# shellcheck disable=SC2143
if [[ "$(grep -Ei 'debian|ubuntu' /etc/*release)" ]]; then
  sudo apt-get install -y libpcap-dev
elif [[ "$(grep -Ei 'fedora|centos|redhat' /etc/*release)" ]]; then
  sudo yum install -y libpcap-devel
fi

# 2. Install with cargo
cargo install --path . --root "$installPath"

# 3. copy resource folder
read -r -p "Do you need to keep the resource files (please confirm that all resource files are working properly) (y or ..): " keepResFiles
if [ "$keepResFiles" != "y" ]; then
  cp -r   ./block_list  ./probe_modules_payload  "$installPath"
fi

# 4. clear
rm -rf ./target


# 5. Add cargo bin path to PATH
read -r -p "Whether to add the program path to the environment variable(y or ..): " addEnv
if [ "$addEnv" = "yes" ] || [ "$addEnv" = "y" ]; then
  echo "export PATH=\"$installPath/bin:\$PATH\"" >> ~/.bashrc
  echo "Please type \" source ~/.bashrc \" in the current terminal to refresh the environment variables"
fi

