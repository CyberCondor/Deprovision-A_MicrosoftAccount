<#
.SYNOPSIS
This script can be used to "deprovision" a Microsoft account.

.DESCRIPTION
The following actions are performed on the account to be deprovisioned:

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

.PARAMETER Server
Specifies the Active Directory server domain to query.

.PARAMETER Logging
Specifies if logging is turned on or not.

.EXAMPLE
PS C:\> Deprovision-A_MicrosoftAccount.ps1

## Input
name, email, or SAMAccountName of an account to be deprovisioned

## Output
Verbose confirmation of actions performed successfully or unsuccessfully
    If Logging is TRUE, set logging Path:
    $Logging_Path\$YearAndMonth\$AccountToDeprovision.SamAccountName_$($AccountToDeprovision.Name -replace ' ','').txt  
#>
param(
    [Parameter(mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [system.String]$Server,

    [Parameter(mandatory=$True, Position=0, ValueFromPipeline=$false)]
    [system.Boolean]$Logging
)
Write-Host "`n888~-_                                                 ,e,        ,e,                           "
Write-Host "888   \   e88~~8e  888-~88e  888-~\  e88~-_  Y88b    /  '   d88~\  '   e88~-_  888-~88e           " 
Write-Host "888    | d888  88b 888  888b 888    d888   i  Y88b  /  888 C888   888 d888   i 888  888           " 
Write-Host "888    | 8888__888 888  8888 888    8888   |   Y88b/   888  Y88b  888 8888   | 888  888           " 
Write-Host "888   /  Y888    , 888  888P 888    Y888   |    Y8/    888   888D 888 Y888   | 888  888           " 
Write-Host "888_-~    '88___/  888-_88'  888     '88_-~      Y     888 \_88P  888  '88_-~  888  888           " 
Write-Host "     e             888      e    e      ,e,                                           88~\   d8   " 
Write-Host "    d8b                    d8b  d8b      '   e88~~\ 888-~\  e88~-_   d88~\  e88~-_  _888__ _d88__ " 
Write-Host "   /Y88b                  d888bdY88b    888 d888    888    d888   i C888   d888   i  888    888   " 
Write-Host "  /  Y88b                / Y88Y Y888b   888 8888    888    8888   |  Y88b  8888   |  888    888   " 
Write-Host " /____Y88b              /   YY   Y888b  888 Y888    888    Y888   |   888D Y888   |  888    888   " 
Write-Host "/      Y88b            /          Y888b 888  '88__/ 888     '88_-~  \_88P   '88_-~   888    '88_/ " 
Write-Host "     e                                                   d8                                       " 
Write-Host "    d8b      e88~~\  e88~~\  e88~-_  888  888 888-~88e _d88__                                     " 
Write-Host "   /Y88b    d888    d888    d888   i 888  888 888  888  888                                       " 
Write-Host "  /  Y88b   8888    8888    8888   | 888  888 888  888  888                                       " 
Write-Host " /____Y88b  Y888    Y888    Y888   | 888  888 888  888  888                                       " 
Write-Host "/      Y88b  '88__/  '88__/  '88_-~  '88_-888 888  888  '88_/                                   `n" 
                                                                                                                                             
if($Logging){
    $Logging_Path = $null
    While(!($Logging_Path)){
        $Logging_Path = Read-Host "Enter a the full path of the directory you want to send logs to"
        if(!($Logging_Path) -or (!(Test-Path -Path $Logging_Path)) -or (!(Test-Path -Path $Logging_Path -PathType Container))){
            Write-Host "$Logging_Path not found or is not a Directory"
            $Logging_Path = $null
        }
    }
}

Write-Host "`n`t`tAttempting to query Active Directory.'n" -BackgroundColor Black -ForegroundColor Yellow
try{Get-ADUser -server $Server -filter 'Title -like "*Admin*"' > $null -ErrorAction stop
}
catch{$errMsg = $_.Exception.message
    if($errMsg.Contains("is not recognized as the name of a cmdlet")){
        Write-Warning "`t $_.Exception"
        Write-Output "Ensure 'RSAT Active Directory DS-LDS Tools' are installed through 'Windows Features' & ActiveDirectory PS Module is installed"
    }
    elseif($errMsg.Contains("Unable to contact the server")){
        Write-Warning "`t $_.Exception"
        Write-Output "Check server name and that server is reachable, then try again."
    }
    else{Write-Warning "`t $_.Exception"}
    break
}

function Get-ExistingUsers_AD{
    try{$ExistingUsers = Get-ADUser -Server $Server -Filter * -Properties SamAccountName,UserPrincipalName,DistinguishedName,Name,Mail,EmailAddress,Description,Title,Office,WhenCreated,WhenChanged,PasswordLastSet,Enabled,Manager |
            Select SamAccountName,UserPrincipalName,DistinguishedName,Name,Mail,EmailAddress,Description,Title,Office,WhenCreated,WhenChanged,PasswordLastSet,Enabled,Manager  -ErrorAction Stop
        return $ExistingUsers
    }
    catch{$errMsg = $_.Exception.message
        Write-Warning "`t $_.Exception"
        return $null
    }
}

function Get-UserRunningThisProgram($ExistingUsers){
    foreach($ExistingUser in $ExistingUsers){if($ExistingUser.SamAccountName -eq $env:UserName){return $ExistingUser ;break}}
    Write-Warning "User Running this program not found."
    return $null
}

function TryConnect-ExchangeOnline($UserRunningThisProgram){
    Try{Get-Mailbox -Identity $UserRunningThisProgram.UserPrincipalName > $null -ErrorAction Stop
        return $true
    }
    Catch{$errorMessage = $_.Exception.message
        if($errorMessage -like "*is not recognized as the name of a cmdlet*"){               
            Write-Host "Calling Connect-ExchangeOnline"
            Try{Connect-ExchangeOnline -ErrorAction Stop
                return $true
            }
            Catch{$errorMessage = $_.Exception.message
                if($errorMessage -like "*is not recognized as the name of a cmdlet*"){               
                    Write-Warning "`t $_.Exception"
                    Write-Host "You need to install the ExchangeOnlineManagement Module in Admin PowerShell. 'Install-Module ExchangeOnlineManagement'"           
                }
                else{Write-Warning "`t $_.Exception"}       
            }         
        }
        else{Write-Warning "`t $_.Exception"}       
    }
    return $false
}
function TryConnect-AzureAD($UserRunningThisProgram){
    try{Get-AzureADUser -ObjectId $UserRunningThisProgram.UserPrincipalName > $null -ErrorAction stop
        return $true
    }
    catch{$errMsg = $_.Exception.message
        if($errMsg -like "*is not recognized as the name of a cmdlet*"){
            Write-Warning "`t $_.Exception"
            Write-Output "Ensure 'AzureAD PS Module is installed. 'Install-Module AzureAD'"
        }
        elseif($_.Exception -like "*Connect-AzureAD*"){
            Write-Warning "`t $_.Exception"
            Write-Output "Calling Connect-AzureAD"
            try{Connect-AzureAD -ErrorAction stop
            }
            catch{$errMsg = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
        else{Write-Warning "`t $_.Exception"}
    }
    return $false
}

function Remove-CloudGroupsAssignedTo($ExistingUser){
    write-host "Searching for AzureAD Security Groups"
    $MemberID = (Get-AzureADUser -ObjectId $ExistingUser.UserPrincipalName).objectId
    Get-AzureADUserMembership -ObjectId $MemberID -All $true | Where-Object { $_.ObjectType -eq "Group" -and $_.SecurityEnabled -eq $true -and $_.MailEnabled -eq $false -and $_.LastDirSyncTime -eq $null} |
        foreach{
            Try{Remove-AzureADGroupMember -ObjectId $_.ObjectID -MemberId $MemberID -ErrorAction Stop
                write-host "`tRemoved $($ExistingUser.Name) from $($_.DisplayName)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }

    write-host "Searching for Unified Groups and Teams"
    $MemberDN = (get-mailbox -Identity $ExistingUser.UserPrincipalName -IncludeInactiveMailbox).DistinguishedName
    Get-Recipient -Filter "Members -eq '$MemberDN'" -RecipientTypeDetails 'GroupMailbox' |
        foreach{
            Try{Remove-UnifiedGroupLinks -Identity $_.ExternalDirectoryObjectId -Links $ExistingUser.UserPrincipalName -LinkType Member -Confirm:$false -ErrorAction Stop
                write-host "`tRemoved $($ExistingUser.Name) from $($_.RecipientType): $($_.DisplayName) - $($_.PrimarySmtpAddress)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception ****If you recieve this warning, this person might be an owner, subscriber, or aggregator and not simply a member****"
                Write-Warning $($_.DisplayName)
                Try{Remove-UnifiedGroupLinks -Identity $_.ExternalDirectoryObjectId -Links $ExistingUser.UserPrincipalName -LinkType Subscribe -Confirm:$false -ErrorAction Stop
                    write-host "`tRemoved $($ExistingUser.Name) from $($_.RecipientType): $($_.DisplayName) - $($_.PrimarySmtpAddress)" -ForegroundColor green
                }
                Catch{$errorMessage = $_.Exception.message
                    Write-Warning "`t $_.Exception ****If you recieve this warning, this person might be an owner or aggregator and not simply a member or subscriber****"
                    Write-Warning $($_.DisplayName)
                }
            }            
        }

    write-host "Searching for Distribution Groups"
    Get-Recipient -Filter "Members -eq '$MemberDN'" |
        foreach{
            Try{Remove-DistributionGroupMember -Identity $_.ExternalDirectoryObjectId -Member $MemberDN -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction Stop
                write-host "`tRemoved $($ExistingUser.Name) from $($_.RecipientType): $($_.DisplayName) - $($_.PrimarySmtpAddress)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }       
        }
}
function Remove-SharedMailboxPermissionsFor($ExistingUser){
    write-Host "Searching for shared mailboxes to remove...`n"   
    $MailboxRecipientDetails = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize:Unlimited
    $FullAccess = $MailboxRecipientDetails | Get-MailboxPermission -User $ExistingUser.UserPrincipalName | Select-Object Identity,AccessRights
    Try{$SendAs = $MailboxRecipientDetails | Get-RecipientPermission -Trustee $ExistingUser.UserPrincipalName | 
        Where-Object {($_.IsInherited -eq $False) -and -not ($_.Trustee -like "NT AUTHORITY\SELF")} | Select-Object Identity,AccessRights -ErrorAction Stop
    }
    Catch{$errorMessage = $_.Exception.message
        Write-Warning "`t $_.Exception"
        Write-Warning "`t Check permissions needed to run the 'Get-RecipientPermission' and 'Get-EXORecipientPermission' commands"
    } 

    if($FullAccess -ne $null){
        foreach($Mailbox in $FullAccess){
            Try{Remove-MailboxPermission -Identity $Mailbox.Identity -User $ExistingUser.UserPrincipalName -AccessRights $Mailbox.AccessRights -Confirm:$false –BypassMasterAccountSid -ErrorAction Stop
                Write-Host "Removed $($ExistingUser.Name) from $($Mailbox.AccessRights) access to $($Mailbox.Identity)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
    }
    if($SendAs -ne $null){
        foreach($Mailbox in $SendAs){
            Try{Remove-MailboxPermission -Identity $Mailbox.Identity -User $ExistingUser.UserPrincipalName -AccessRights $Mailbox.AccessRights -Confirm:$false –BypassMasterAccountSid -ErrorAction Stop
                Write-Host "Removed $($ExistingUser.Name) from $($Mailbox.AccessRights) access to $($Mailbox.Identity)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
    }
}
function Make-NewPassword($ExistingUser){
    $MinPasswordLength = 38
    if(!($ExistingUser.NewPassword)){$ExistingUser | Add-Member -NotePropertyMembers @{NewPassword=$null}}
    $k = ""
    $a = @()
    for($i = 0;$i -le $MinPasswordLength; $i++){ 
        $a += ((48..59) + (65..90) + (33,36,37,38,45) + (97..122) | Get-Random -Count 1)
    }
    for($i = 0;$i -lt $a.length; $i++){ 
        $x = $a[$i] -bxor $i
        $b = [char]$x
        $k += $b
    }
    $ExistingUser.NewPassword = ConvertTo-SecureString $k -AsPlainText -Force
    if(($ExistingUser.NewPassword -eq $null) -or ($ExistingUser.NewPassword.length -lt $MinPasswordLength)){return $false}
    else{return $true}
}
function Get-UsersOU($ExistingUser){   
    for($i = 10; $i -lt $ExistingUser.CanonicalName.length; $i++){
        if($ExistingUser.CanonicalName[$i] -ne "/"){
            $OU += $ExistingUser.CanonicalName[$i]
        }
        else{$i = $ExistingUser.CanonicalName.length}
    }
    $ExistingUser | Add-Member -NotePropertyMembers @{OU=$OU}
}
function Set-DeprovisioningOU($ExistingUser){
    $DeprovisionOU = Get-ADOrganizationalUnit -Server $Server -Filter * | where{($_.DistinguishedName -like "*DisabledUsers*") -or ($_.DistinguishedName -like "*Termed*")}
    if($DeprovisionOU){
        if($DeprovisionOU.Length -gt 1){                       $index = 1
            $DeprovisionOU | select Name | ft
            $FoundOU = $false
            while($FoundOU -eq $false){
                $Selection = Read-Host "Pick a Deprovision OU"
                $OU = $DeprovisionOU | where{$_.Name -eq $Selection}
                if($OU){$FoundOU = $true}
            }
        }
        Try{$ExistingUser | Add-Member -NotePropertyMembers @{DeprovisionOU=$OU} -ErrorAction Stop}Catch{}
    }
}

function Locate-ExistingUser($User, $ExistingUsers){
    $UserFound = $false
    foreach($ExistingUser in $ExistingUsers){
        if(($User -ne " ") -and ($User -ne "`n") -and ($User -ne $null) -and ($User.length -gt 2)){
            if(($ExistingUser.Name -like "$User") -or ($ExistingUser.EmailAddress -like "$User") -or ($ExistingUser.mail -like "$User") -or ($ExistingUser.SamAccountName -like "$User") -or ($ExistingUser.UserPrincipalName -like "$User")){
                Write-Host "`n$User is found in AD.`n" ; $UserFound = $true
                Write-Host $ExistingUser.Name
                Write-Host $ExistingUser.SamAccountName
                Write-Host $ExistingUser.UserPrincipalName
                Write-Host $ExistingUser.Title
                Write-Host $ExistingUser.Description
                Write-Host $ExistingUser.Office
                write-Host "Manager: $($ExistingUser.Manager)"
                Write-Host "Created: $($ExistingUser.whenCreated)"
                $ConfirmationCheck = Read-Host -Prompt "`nIs this the correct user? (Y or N)"
                if($ConfirmationCheck -eq "Y"){
                    return $ExistingUser
                }
                else{Write-Host "You've indicated that this found user is not correct." ; break}
            }
        }
    }
    if($UserFound -eq $false){Write-Host "Cannot find $User in AD."}
    return $null
}
function Remove-UserLicenses($ExistingUser){
    $userToOffboard = Get-AzureADUser -ObjectId $ExistingUser.UserPrincipalName
    $AssignedLicensesTable = $userToOffboard | Get-AzureADUserLicenseDetail | Select-Object @{n = "License"; e = {$_.SkuPartNumber}},skuid
    Sleep 1.3
    if($AssignedLicensesTable){
        $LicensesToRemove = @{removeLicenses = @($AssignedLicensesTable.skuid)}
        Try{Set-AzureADUserLicense -ObjectId $userToOffboard.ObjectId -AssignedLicenses $LicensesToRemove -ErrorAction Stop  
            Sleep 1.3     
            write-host "Removed licenses:"
            $AssignedLicensesTable | ft
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
    }
    else{write-host "No Licenses to Remove."}
}

function Add-LicenseToUser($SkuPartNumber, $ExistingUser){
    $userToOffboard = Get-AzureADUser -ObjectId $ExistingUser.UserPrincipalName
    $LicenseSku = Get-AzureADSubscribedSku | Where {$_.SkuPartNumber -eq $SkuPartNumber}
    Sleep 1.3
    $License = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicense
    $License.SkuId = $LicenseSku.SkuId
    $LicensesToAdd = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
    $LicensesToAdd.AddLicenses = $License
    Try{Set-AzureADUserLicense -ObjectId $userToOffboard.ObjectId -AssignedLicenses $LicensesToAdd -ErrorAction Stop
        Sleep 3
        $AddedLicense = $userToOffboard | Get-AzureADUserLicenseDetail | Select-Object @{n = "License"; e = {$_.SkuPartNumber}},skuid | Where{$_.License -eq $SkuPartNumber}
        if($AddedLicense){
            write-host "Added License: $SkuPartNumber" -ForegroundColor Green
        }
        else{Write-Warning "$SkuPartNumber NOT added - Must be done Manually"}
    }
    Catch{$errorMessage = $_.Exception.message
        Write-Warning "`t $_.Exception"
        Write-Warning "$SkuPartNumber NOT added - Must be done Manually - ***Check if License is available***"
    }
}

function Get-AvailableLicenseDetails{
    $LicenseDetails = Get-AzureADSubscribedSku | select SkuPartNumber,consumedUnits,PrepaidUnits
    foreach($LicenseDetail in $LicenseDetails){
        $AvailableLicenses = ($LicenseDetail.PrePaidUnits.Enabled - $LicenseDetail.ConsumedUnits)
        if($LicenseDetail.SkuPartNumber -eq "EMS"){$LicenseDetail | Add-Member -NotePropertyMembers @{Name="Enterprise Mobility + Security E3";AvailableLicenses=$AvailableLicenses}}
        elseif($LicenseDetail.SkuPartNumber -eq "ENTERPRISEPACK"){$LicenseDetail | Add-Member -NotePropertyMembers @{Name="Office 365 E3";AvailableLicenses=$AvailableLicenses}}
        elseif($LicenseDetail.SkuPartNumber -eq "EXCHANGEENTERPRISE"){$LicenseDetail | Add-Member -NotePropertyMembers @{Name="Exchange Online (Plan 2)";AvailableLicenses=$AvailableLicenses}}
    }
    $LicenseDetails = $LicenseDetails | select Name,AvailableLicenses
    return $LicenseDetails
}

function main{
    ### Get Account to Deprovision
    $AccountToDeprovision = $null
    $TempVar = $null
    while(($AccountToDeprovision -eq $null) -and ($TempVar -ne "Q")){
        $TempVar = Read-Host -Prompt "`nEnter the name, email, or SAMAccountName of the user to be deprovisioned (Q to quit)"
        if($TempVar -ne "Q"){$AccountToDeprovision = Locate-ExistingUser $TempVar $ExistingUsers}
    }
    if($TempVar -eq "Q"){break}
    
    Write-Output "`n"  ### Forward Emails? VVV
    $continue = $false
    while($continue -eq $false){
        $ForwardEmailsRecipient = $null
        $ForwardEmails = Read-Host -Prompt "`nForward $($AccountToDeprovision.Name)'s emails? (Y or N)"
        if($ForwardEmails -eq "Y"){
            $TempVar = $null
            while(($ForwardEmailsRecipient -eq $null) -and ($TempVar -ne "Q")){
                $TempVar = Read-Host -Prompt "`nEnter the name, email, or SAMAccountName of the recipient for forwarded emails (Q to quit)"
                if($TempVar -ne "Q"){$ForwardEmailsRecipient = Locate-ExistingUser $TempVar $ExistingUsers ;$continue = $true}
            }
            if($TempVar -eq "Q"){break}
        }
        if($ForwardEmails -eq "N"){$continue = $true}
    }
    if($TempVar -eq "Q"){break}
    
    Write-Output "`n" ### Set FullAccess to Mailbox? VVV
    $continue = $false
    while($continue -eq $false){
        $AccessToMailboxRecipient = $null
        $AccessToMailbox = Read-Host -Prompt "`nSet FullAccess to $($AccountToDeprovision.Name)'s mailbox? (Y or N)"
        if($AccessToMailbox -eq "Y"){
            $TempVar = $null
            while(($AccessToMailboxRecipient -eq $null) -and ($TempVar -ne "Q")){
                $TempVar = Read-Host -Prompt "`nEnter the name, email, or SAMAccountName of the recipient for FullAccess mailbox permissions (Q to quit)"
                if($TempVar -ne "Q"){$AccessToMailboxRecipient = Locate-ExistingUser $TempVar $ExistingUsers ;$continue = $true}
            }
            if($TempVar -eq "Q"){break}
        }
        if($AccessToMailbox -eq "N"){$continue = $true}
    }
    if($TempVar -eq "Q"){break}
    
    Write-Output "`n" ### Set Auto Reply for Mailbox? VVV
    $continue = $false
    while($continue -eq $false){
        $AutoReplyMessage = $null
        $SetAutoReply = Read-Host -Prompt "Set Auto Reply for $($AccountToDeprovision.Name)'s mailbox? (Y or N)"
        if($SetAutoReply -eq "Q"){break}
        if($SetAutoReply -eq "Y"){$continue = $true
            $AutoReplyMessage = Read-Host -Prompt "Enter Auto Reply Message"
        }
        if($SetAutoReply -eq "N"){$continue = $true}
    }
    if($SetAutoReply -eq "Q"){break}
    
    clear ### Confirm? VVV
    
    Write-Warning "The following account will be deprovisioned:"
    $AccountToDeprovision | Select Name,SamAccountName,UserPrincipalName,Office,Title,Department,Manager,Description,WhenChanged,PasswordLastSet | fl
    
    if(($ForwardEmailsRecipient -ne $null) -or ($AccessToMailboxRecipient -ne $null) -or ($AutoReplyMessage)){
        Write-Host "`n`t`tConditions:`n"
        if($ForwardEmailsRecipient -ne $null){
            Write-Host "`t`t`t`tEmails will be forwarded to $($ForwardEmailsRecipient.Name)"
        }
        if($AccessToMailboxRecipient -ne $null){
            $NewDescription = "*Deprovisioned $($CurrentDate)* - AccessToMailbox: $($AccessToMailboxRecipient.Name) - " + $AccountToDeprovision.Description
            Write-Host "`t`t`t`tFullAccess to mailbox will be granted to $($AccessToMailboxRecipient.Name)"
        }
        if($AutoReplyMessage){Write-Host "`t`t`t`tAuto Reply Message Set to: $($AutoReplyMessage)"}
    }
    if($AccessToMailboxRecipient -eq $null){
        $NewDescription = "*Deprovisioned $($CurrentDate)* - " + $AccountToDeprovision.Description
    }
    $AvailableLicenseDetails = Get-AvailableLicenseDetails
    
    Get-UsersOU $AccountToDeprovision
    Set-DeprovisioningOU $AccountToDeprovision
    
    Write-Host "`nCurrent OU:   $($AccountToDeprovision.DistinguishedName)`n"
    Write-Host "Deprovision OU: $($AccountToDeprovision.DeprovisionOU)`n"
    Write-Host "New Description: $($NewDescription)`n"
    write-host "Available License Details:"
    $AvailableLicenseDetails | ft
    
    $ConfirmationCheck = Read-Host -Prompt "`nConfirm (Y or N)"
    
    if(($ConfirmationCheck -eq "Y") -and ($AccountToDeprovision -ne $null)){  
        Make-NewPassword $AccountToDeprovision
        if(($AccountToDeprovision.NewPassword -eq $null) -or ($AccountToDeprovision.NewPassword.length -lt 30)){Write-Warning "User's password is null" ; break}
    
        if($Logging_Path){
            if(!(Test-Path "$($Logging_Path)\$($YearAndMonth)")){mkdir "$($Logging_Path)\$($YearAndMonth)"}
            Try{Start-Transcript -Append -Path "$($Logging_Path)\$($YearAndMonth)\$($AccountToDeprovision.SamAccountName)_$($AccountToDeprovision.Name -replace ' ','')_$CurrentDate.txt" -ErrorAction Stop  
                Write-Host "`n Logging Started @ $((get-date -format "yyy-MM-dd HH:mm ") + (Get-TimeZone).DisplayName) `n" -ForegroundColor Green    
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
                Try{Stop-Transcript -ErrorAction Stop      
                    Try{Start-Transcript -Append -Path "$($Logging_Path)\$($YearAndMonth)\$($AccountToDeprovision.SamAccountName)_$($AccountToDeprovision.Name -replace ' ','')_$CurrentDate.txt" -ErrorAction Stop
                        Write-Host "`n Logging Started @ $((get-date -format "yyy-MM-dd HH:mm ") + (Get-TimeZone).DisplayName) `n" -ForegroundColor Green 
                    }
                    Catch{$errorMessage = $_.Exception.message
                        Write-Warning "`t $_.Exception"
                        break
                    }
                }
                Catch{$errorMessage = $_.Exception.message
                    Write-Warning "`t $_.Exception"
                    break
                }
            }
        }
        Write-Host "$($UserRunningThisProgram.Name) ($($UserRunningThisProgram.Title)) - Started this program @ $(date)`n"
    
        Write-Warning "`n`nProcessing Account Deprovisioning for $($AccountToDeprovision.Name)...`n"
        
        ##Reset PW - AD
        $PasswordReset = $false
        while($PasswordReset -eq $false){ 
            Try{Set-ADAccountPassword -Server $Server -Identity $AccountToDeprovision.SamAccountName -Reset -NewPassword $AccountToDeprovision.NewPassword -ErrorAction Stop
                Write-Host "Password Reset" -ForegroundColor green
                $PasswordReset = $true
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
                Make-NewPassword $AccountToDeprovision                 
            }
        }
    
        ##Disable account - AD
        Try{Disable-ADAccount -Server $Server -Identity $AccountToDeprovision.SamAccountName -ErrorAction Stop
            Write-Host "Account Disabled" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
      
        ##Remove Memberships - AD
        $UserAssignedADGroups = Get-ADPrincipalGroupMembership -server $Server -Identity $AccountToDeprovision.SamAccountName | where{$_.Name -ne "Domain Users"}
        if($UserAssignedADGroups){
            Try{Remove-ADPrincipalGroupMembership -Server $Server -Identity $AccountToDeprovision.SamAccountName -MemberOf $UserAssignedADGroups -Confirm:$false -ErrorAction Stop
                Write-Host "AD Group Memberships Removed:" -ForegroundColor green
                foreach($Group in $UserAssignedADGroups){write-host "`t`t $($Group.Name)"}
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
        else{Write-Host "No AD Group Memberships to Remove*"}
    
        ##Change description - AD *If access to the account mailbox is set, note this in description also*
        if(($AccountToDeprovision.Description -ne "*Deprovisioned*") -and ($NewDescription)){
            Try{Set-ADUser -server $Server -Identity $AccountToDeprovision.SamAccountName -Description $NewDescription
                Write-Host "Description updated to '$($NewDescription)'" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
        else{Write-Host "Description UNCHANGED: $($AccountToDeprovision.Description)"}
          
        ##Move to Deprovisioning OU - AD
        if($AccountToDeprovision.DeprovisionOU){
            Try{Move-ADObject -server $Server -Identity $AccountToDeprovision.DistinguishedName -TargetPath $AccountToDeprovision.DeprovisionOU -ErrorAction Stop
                Write-Host "Moved $($AccountToDeprovision.Name) to $($AccountToDeprovision.OU) Deprovision OU: $($AccountToDeprovision.DeprovisionOU)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
        else{Write-Warning "AD Location/OU UNCHANGED: $($AccountToDeprovision.DistinguishedName)"}
    
        ##Forward email if applicable - Exchange Online
        if($ForwardEmailsRecipient){
            Try{Set-Mailbox -Identity $AccountToDeprovision.UserPrincipalName -ForwardingAddress $ForwardEmailsRecipient.UserPrincipalName -Confirm:$false -ErrorAction Stop
                Write-Host "Set forwarding emails to: $($ForwardEmailsRecipient.Name)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
        ##Set up mailbox access if applicable - Exchange Online
        if($AccessToMailboxRecipient){
            Try{Add-MailboxPermission -Identity $AccountToDeprovision.UserPrincipalName -User $AccessToMailboxRecipient.UserPrincipalName -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
                Write-Host "Set FullAccess permissions for $($AccountToDeprovision.Name)'s mailbox to $($AccessToMailboxRecipient.Name)" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
    
        ##Set Auto Reply Email if applicable - Exchange Online
        if($AutoReplyMessage){
            Try{Set-MailboxAutoReplyConfiguration -Identity $AccountToDeprovision.UserPrincipalName -AutoReplyState Enabled -InternalMessage $AutoReplyMessage -ExternalMessage $AutoReplyMessage -ErrorAction Stop
                Write-Host "Set auto reply email" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
    
        ##Block sign in - Azure
        Try{Set-AzureADUser -ObjectID $AccountToDeprovision.UserPrincipalName -AccountEnabled $false -ErrorAction Stop
            Write-Host "Blocked sign-in through Azure" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
    
        ##Reset PW - Azure
        Try{Set-AzureADUserPassword –ObjectId $AccountToDeprovision.UserPrincipalName –Password  $AccountToDeprovision.NewPassword -ErrorAction Stop
            Write-Host "Reset Password in Azure" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
    
        ##Remove licenses - Azure
        Remove-UserLicenses $AccountToDeprovision
    
        ##Add License if applicable - Azure
        Add-LicenseToUser "EXCHANGEENTERPRISE" $AccountToDeprovision 
    
        ##Revoke Access Tokens - Azure
        Try{Revoke-AzureADUserAllRefreshToken -ObjectId $AccountToDeprovision.UserPrincipalName -ErrorAction Stop
            Write-Host "Revoked all refresh tokens through Azure" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
        ##Revoke access to registered device - Azure
        #Try{Get-AzureADUserRegisteredDevice -ObjectId $AccountToDeprovision.UserPrincipalName | Set-AzureADDevice -AccountEnabled $false -ErrorAction Stop
        #    Write-Host "Revoked access to registered device through Azure" -ForegroundColor green
        #}
        #Catch{$errorMessage = $_.Exception.message
        #    Write-Warning "`t $_.Exception"
        #}
          
        ##Remove Account shared mailbox permissions - Exchange Online
        Remove-SharedMailboxPermissionsFor $AccountToDeprovision
        
        ##Remove group memberships - Exchange Online / Azure
        Remove-CloudGroupsAssignedTo $AccountToDeprovision
      
        ##Hide account from Global Address Lists - Exchange Online
        Try{Set-Mailbox -Identity $AccountToDeprovision.UserPrincipalName -HiddenFromAddressListsEnabled $true -ErrorAction Stop
            Write-Host "Account hidden from Global Address Lists" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
            Try{Set-ADUser -server $Server -Identity $AccountToDeprovision.SAMAccountName -Add @{msExchHideFromAddressLists="TRUE"} -ErrorAction Stop
                Write-Host "Account hidden from Global Address Lists" -ForegroundColor green
            }
            Catch{$errorMessage = $_.Exception.message
                Write-Warning "`t $_.Exception"
            }
        }
    
        ##Disable active sync for mailbox - Exchange Online
        Try{Set-CASMailbox -identity $AccountToDeprovision.SAMAccountName -ActiveSyncEnabled $false -ErrorAction Stop
            Write-Host "Disabled active sync for account's mailbox" -ForegroundColor green
        }
        Catch{$errorMessage = $_.Exception.message
            Write-Warning "`t $_.Exception"
        }
    
        Get-ADUser -Server $Server -filter "SamAccountName -eq '$($AccountToDeprovision.SamAccountName)'" -Properties * | fl
    }
    else{Write-Host "Okay, $($AccountToDeprovision.Name) will not be Deprovisioned."}
    
    Write-Host "`nProgram completed @ $(date)`n"
    
    if($Logging_Path){Try{Stop-Transcript -ErrorAction Stop}Catch{}}
}

$YearAndMonth = get-date -format yyy-MM
$CurrentDate = get-date -format yyy-MM-dd 
$ExistingUsers = Get-ExistingUsers_AD
if($ExistingUsers -eq $null){break}
$UserRunningThisProgram = Get-UserRunningThisProgram $ExistingUsers
if($(TryConnect-AzureAD        $UserRunningThisProgram) -eq $true){Write-Host "Connected to AzureAD PowerShell Module"}else{break}
if($(TryConnect-ExchangeOnline $UserRunningThisProgram) -eq $true){Write-Host "Connected to Exchange Online PowerShell Module"}else{break}

Write-Host "$($UserRunningThisProgram.Name) ($($UserRunningThisProgram.Title)) - Started this program @ $(date)`n"

$quit = "p"
while($quit -ne "q"){
    $quit = Read-Host "`nEnter 'q' to quit or anything else to Deprovision a Microsoft Account"
    if($quit -ne "q"){main}
}
