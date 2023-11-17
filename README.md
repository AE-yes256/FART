# Firewall Access Review Tool
## What is it
The FART is was created using 90% powershell and 9% KQL and 1% magic. Its a tool that connects to Azure, downloads and parses your NSG's, then searches the flow logs for a 'hit' on that NSG rule. This is done to assist the reviewer in identifying redundant rules. 
## Why I created it
I created this to assist with PCI DSS Requirement 1.1.7 and because its good security practice.
## Roadmap Items
- [X] Make this into a cmdlett and let you target subs
- [X] Build in Fancy status bar
- [X] Make Hit Count optional via flag
- [X] Check if user is already connected to Azure rather than always forcing authentication
- [X] Build in some error checking for user inputs 
- [ ] Check if NSG's are present and alert if not
- [ ] Check if Flow logs are enabled and alert if not
- [ ] Highlight insecure ports / protocols
- [ ] Provide other flags to apply profiles to the report (PCI etc...) 
- [ ] Highlight over permissive rules
- [ ] Make Recomendations on rules that can be removed or reworked 
## How to run
Select the Subscription
```powershell
PS C:\tmpp> Get-AzNSG-Review -SelectSub
```
OR
All the Subscriptions
```powershell
PS C:\tmpp> Get-AzNSG-Review -All
```
AND
Enable HitCount - HitCount is **disabled** by default.
```powershell
PS C:\tmpp> Get-AzNSG-Review -All -HitCount
```
### Pre Reqs
#### Configure Flow Logs
No point reinventing the wheel...
https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview#enabling-nsg-flow-logs

I personally recomend getting at least 30 days worth of traffic, this will allow time for things like updates to happen etc.
