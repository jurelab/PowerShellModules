# PowerShellModules

JLabOperatingSystem.psm1

Test-JLabComputerStatus => This cmdlet tests if computer is Pingable, in AD, DNS and WinRM Capable.

Convert-JLabNpsLogFileToPsObjects => This cmdlet converts NPS, "IAS or RADIUS" log file to Power Shell Objects.    

Send-JLabOMSLogAnalyticsHTTPCollectorAPI => This cmdlet Send data to Log Analytics with the HTTP Data Collector API.

Get-JLabCertificateStore => This Cmdlet Displays Certificates. If no Parameter is provided Computers Personal Certificate Store is returned. You can run it on local computer or provide ComputerName-s

Get-JLabUserLocalGroup => This cmdlet gets users in computer local group. By default members of Administrators is returned.  This was written before MS published Get-LocalGroup.. cmdlets :)

Add-JLabUserLocalGroup => This cmdlet Adds users to computer local group.

Remove-JLabUserLocalGroup => This cmdlet removes users from computer local group.

Test-MyLDAPuser => This Function tests AD Account, and displays its LDAP Path Get-MyHotFixesInstalled => This Function gets Installed 

HotfixesGet-MyLogedUsers => This Function gets Last loged Users

Get-MyOSArchitecture => This function queries OS Architecture and returns its value as a string (32-bit or 64-bit)
Get-MyOSVersion => This function gets OS Version and returns its value as a String (for example: Microsoft Windows 8.1 Enterprise)
Get-MyPerfToPID => This Function Maps Process Monitor Service Names To PID
Install-MyDotNET35 => This Function Installs .NET Framework 3.5 SP1 on Windows Server 2008, 2008 R2, 2012 and 2012 R2
