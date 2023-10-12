# Firewall Access Review Tool
![FART](https://github.com/NoodleStorm/FART/assets/35268084/9d84f493-b0e8-4af5-821c-9297d10c44f4)
## What is it
The FART is was created using 90% powershell and 9% KQL and 1% magic. Its a tool that connects to Azure, downloads and parses your NSG's, then searches the flow logs for a 'hit' on that NSG rule. This is done to assist the reviewer in identifing redundant rules.
## Why I created it
I created this to assist with PCI DSS Requirement 1.1.7 and because its good security practice.
## Roadmap Items
- Make this into a cmdlett and let you target subs etc
- Build in Fancy status bar
- Highlight insecure ports / protocols
- Highlight over permissive rules
- cmdlettize it
## How to use it
### Pre Reqs
#### Configure Flow Logs
No point reinventing the wheel...
https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview#enabling-nsg-flow-logs

I personally recomend getting at least 30 days worth of traffic, this will allow time for things like updates to happen etc.
