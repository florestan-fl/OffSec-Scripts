# PSNmap

A comprehensive Nmap-like script that implements main feature of Nmap in Powershell using only builtin commands.

## Prerequisites

- A Powershell environment. Tested version:
```ps
PS > $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.1.26100.7462
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.26100.7462
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
```
- A database of services (provided by https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml for instance)

## Run

`Get-Help PSNmap.ps1` to get the needed help.
