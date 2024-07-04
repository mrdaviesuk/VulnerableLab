##
## Vulnerable Domain Validation Script
## Paul Davies / Daniel Harris
## July 2024 - v1.0
##

# Enable Verbose Output of Found Objects
$verbose = $true

Write-Host "`n################################################"
Write-Host " Vulnerable Domain Validation Script - Running"
Write-Host "################################################`n"

Write-Host "[+] Loading ActiveDirectory Module"
Try{
Import-Module ActiveDirectory
}
Catch{
    Write-Host "[-] ERROR: ActiveDirectory Module Not Loaded - Script Terminating"
    Exit;
}

Write-Host "[+] Constructing Search Base`n"
# Get Current Domain & Set OU Search-Base Scope
$domain = (Get-ADDomain).DNSRoot
$ouName = "Exposed-Ground" 
$ouPath = "OU=$ouName,DC=$($domain -replace '\.', ',DC=')"

If(!(Test-Path (Join-Path 'AD:\' -ChildPath $ouPath)))
{
    Write-Host "[-] ERROR: $ouPath Is Not a Valid OU Search Base - Script Terminating"
    Exit;
}

Write-Host -ForegroundColor Green "[+] Starting User-Related Evaluation"
Write-Host "[+] Enumerating User Accounts Under:" $ouPath

# Return All Users Under the Search Base
$ouUsers = Get-ADUser -SearchBase $ouPath -Filter * -Properties *
Write-Host "[+]" $ouUsers.Count "Users Returned from Search Path`n"

# Return All users with RC4 as SupportedEncryptionTypes
$ouRC4Users = $ouUsers | Where-Object msDS-SupportedEncryptionTypes -eq 4
Write-Host -ForegroundColor Yellow "[+]" $ouRC4Users.Count "Users are Configured with an msDS-SupportedEncryptionTypes value of 4"
If(($null -ne $ouRC4Users) -and ($verbose)){
    $ouRC4Users | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, msDS-SupportedEncryptionTypes, KerberosEncryptionType, objectsid
}

# Return All users with an SPN Defined
$ouSPNUsers = $ouUsers | Where-Object servicePrincipalName -ne $null
Write-Host -ForegroundColor Yellow "[+]" $ouSPNUsers.Count "Users are Configured with an SPN"
If(($null -ne $ouSPNUsers) -and ($verbose)){
    $ouSPNUsers | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, servicePrincipalName, objectsid
}

# Return All Kerbroastable Accounts - Accounts with RC4 Set & an SPN Associated
$ouKROASTUsers = $ouRC4Users | Where-Object servicePrincipalName -ne $null
Write-Host -ForegroundColor Yellow "[+]" $ouKROASTUsers.Count "Users are Configured with Combination which makes them Kerbroastable"
If(($null -ne $ouKROASTUsers) -and ($verbose)){
    $ouKROASTUsers | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, servicePrincipalName, KerberosEncryptionType, objectsid
}

# Return All users where a Password is NOT Required
$ouNPWDUsers = $ouUsers | Where-Object PasswordNotRequired -eq $true
Write-Host -ForegroundColor Yellow "[+]" $ouNPWDUsers.Count "Users are Configured with a Password Not Required"
If(($null -ne $ouNPWDUsers) -and ($verbose)){
    $ouNPWDUsers | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, PasswordNotRequired, objectsid
}

# Return All users where DoesNotRequirePreAuth is Enabled 
$ouDNRPAUsers = $ouUsers | Where-Object DoesNotRequirePreAuth -eq $true
Write-Host -ForegroundColor Yellow "[+]" $ouDNRPAUsers.Count "Users are Configured with PreAuthNotRequired - Making them AS-Rep-roastable"
If(($null -ne $ouDNRPAUsers) -and ($verbose)){
    $ouDNRPAUsers | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, DoesNotRequirePreAuth, objectsid
}

# Return All Members of the Domain Admins Group
$domainAdmins = Get-ADGroup "Domain Admins" -Properties *
$domainAdminsDirect = Get-ADGroupMember "Domain Admins"
Write-Host -ForegroundColor Yellow "[+]" ($domainAdminsDirect | Where-Object objectClass -EQ User).Count "Users are Configured Directly as Domain Admins"
If($verbose){
    $domainAdminsDirect | Where-Object objectClass -eq User | Sort-Object name | FT Name, objectClass, SID
}
# Return Nested Groups
If (($domainAdmins.Members).Count -gt ($domainAdminsDirect | Where-Object objectClass -EQ User).Count){
    Write-Host -ForegroundColor Yellow "[+]" (($domainAdmins.Members).Count - ($domainAdminsDirect | Where-Object objectClass -EQ User).Count) "Group(s) Nested in Domain Admins"
    If($verbose){
        $domainAdminsDirect | Where-Object objectClass -EQ Group | Sort-Object name | FT Name, objectClass, SID
    }
}
# Return All Domain Admin Users Including those in Nested Groups
$domainAdminsRecursive = Get-ADGroupMember "Domain Admins" -Recursive
Write-Host -ForegroundColor Yellow "[+]" ($domainAdminsRecursive | Where-Object objectClass -EQ User).Count "Users are Configured Directly & Indirectly (via Nested Groups) as Domain Admins"
If($verbose){
    $domainAdminsRecursive | Sort-Object name | FT Name, objectClass, SID
}

# Return All Domain Admins with SPNs
$domainAdminSPNs = Get-AdUser -Filter "servicePrincipalName -like '*'" -Properties * | Where-Object ObjectSid -In $domainAdminsRecursive.SID.value
Write-Host -ForegroundColor Yellow "[+]" ($domainAdminSPNs).Count "Users are Domain Admins with an SPN Configured"
If($verbose){
    $domainAdminSPNs | Sort-Object Surname | FT Surname, GivenName, UserPrincipalName, emailaddress, servicePrincipalName, objectsid
}

# Return All Guest Accounts
$guestAccounts = Get-ADGroupMember "Guests" -Recursive | Get-ADUser -Properties *
Write-Host -ForegroundColor Yellow "[+]" @($guestAccounts | Where-Object Enabled -eq $true).count "of" @($guestAccounts).Count "Guest Accounts in the Domain are Enabled."
If(($null -ne $guestAccounts) -and ($verbose)){
    $guestAccounts | Sort-Object Name |  FT Name, Surname, GivenName, UserPrincipalName, emailaddress, objectsid
}

Write-Host -ForegroundColor Green "`n[+] Starting Computer Related Evaluation"

# Return all COmputer Objects under the Search Base
$ouComputers = Get-ADComputer -SearchBase $ouPath -Filter * -Properties *
ForEach ($computer in $ouComputers){
   $userACLS = (Get-ACL (Join-Path "AD:\" $Computer.DistinguishedName)).Access | Where-Object {($_.InheritanceFlags -eq $false) -and ($_.ObjectFlags -eq "None") -and ($_.IdentityReference -notmatch "Domain Admins") -and ($_.IdentityReference -notmatch "BUILTIN") -and ($_.IdentityReference -notmatch "NT AUTHORITY")} 
   
   If($null -ne $userACLS){
        Write-Host "[+]" $computer.Name "has" @($userACLS).Count "Unusual ACL Entries"
        If($verbose -eq $true){
            $userACLS | FT AccessControlType, ActiveDirectoryRights, IdentityReference
        }
   }
}

Write-Host -ForegroundColor Green "`n[+] Starting Certificate Services Related Evaluation"


Write-Host "`n################################################"
Write-Host " Vulnerable Domain Validation Script - Finished"
Write-Host "################################################"