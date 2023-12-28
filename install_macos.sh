#!/bin/zsh

# user input
defaultInstallPath="$HOME/smap"
read -r "installPath?Enter install path or press Enter for default($defaultInstallPath): "
if [ -z "$installPath" ]; then
  installPath=$defaultInstallPath
fi
if [ ! -d "$installPath" ]; then
  mkdir -p "$installPath"
fi
echo "smap will be installed to $installPath"

# 1. Install with cargo
cargo install --path . --root "$installPath"

# 2. copy resource folder
cp -r   ./block_list  ./probe_modules_payload  "$installPath"

# 3. clear
rm -rf ./target

# 4. Add cargo bin path to PATH
read -r "addEnv?Whether to add the program path to the environment variable(y or ..): "
if [ "$addEnv" = "yes" ] || [ "$addEnv" = "y" ]; then
  echo "export PATH=\"$installPath/bin:\$PATH\"" >> ~/.zshrc
  echo "Please type \" source ~/.zshrc \" in the current terminal to refresh the environment variables"
fi