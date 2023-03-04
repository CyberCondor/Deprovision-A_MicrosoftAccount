# Deprovision-A_MicrosoftAccount.ps1
## SYNOPSIS
This script can be used to "deprovision" a Microsoft account.

## DESCRIPTION
**The following actions are performed on the account to be deprovisioned:**
- Reset PW - AD/Azure
- Disable account - AD
- Remove Memberships - AD
- Change description - AD 
- Move to Deprovisioning OU - AD
- Block sign in - Azure
- Remove licenses - Azure
- Add License if applicable - Azure
- Revoke Access Tokens - Azure
- Forward email if applicable - Exchange Online
- Set up mailbox access if applicable - Exchange Online
- Set Auto Reply Email if applicable - Exchange Online
- Remove Account shared mailbox permissions - Exchange Online
- Remove group memberships - Exchange Online / Azure
- Hide account from Global Address Lists - Exchange Online/AD
- Disable active sync for mailbox - Exchange Online

### PARAMETER Server
Specifies the Active Directory server domain to query.

### PARAMETER Logging
Specifies if logging is turned on or not.

### EXAMPLE
PS C:\> Deprovision-A_MicrosoftAccount.ps1 -Server CyberCondor.local -Logging Y

## Input
name, email, or SAMAccountName of an account to be deprovisioned

## Output
Verbose confirmation of actions performed successfully or unsuccessfully

If Logging is TRUE, set logging Path:
```$Logging_Path\$YearAndMonth\$AccountToDeprovision.SamAccountName_$($AccountToDeprovision.Name -replace ' ','')_$CurrentDate.txt```
