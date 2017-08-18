 
function Get-JLabUserLocalGroup {
<#
.Synopsis
   This cmdlet gets users in computer local group.
.DESCRIPTION
   This cmdlet gets users in computer local group. By default members of Administrators is returned.
.EXAMPLE
   Get-JLabUserLocalGroup
   Gets Members in local administrators group on local computer
.EXAMPLE
   Get-JLabUserLocalGroup -ComputerName "server01","server02"
   Gets Local Administrators on computers: server01 and server02
.EXAMPLE
   Get-JLabUserLocalGroup -ComputerName (Get-Content -Path C:\Users\john.doe\Desktop\computers.txt) -Credential john.doe -LocalGroupName "Power Users"
   Gets Power Users on computers provided in computers.txt file using credentials: john.doe
.INPUTS
    String
.OUTPUTS
   PSCustomObject
.NOTES
   Created By: Jure Labrovic

   Web Page: https://jurelab.wordpress.com/

   Revision:
   Version 1.0   6.11.2015
#>

    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://jurelab.wordpress.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]        
        [Alias("Group")]
        [string] 
        $LocalGroupName="Administrators",
        # Param2 help description
        [Parameter(ParameterSetName='Parameter Set 1')]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]
        $ComputerName,
        [string]
        $ErrorLog="$env:USERPROFILE\Desktop\JLabGetUsersInGroupErrorLog.txt",
        [switch]
        $LogErrors,
        [string]
        $Credential

    )

    Begin
    {
        if ($LogErrors){
            Write-Verbose "[$($MyInvocation.InvocationName)]: [$($MyInvocation.InvocationName)]: Log file can be found in: $ErrorLog"
        }

        if ($Credential){
            $Creds=Get-Credential -UserName $Credential -Message "Enter password"
        }  
    }
    Process
    {
        $ArrayOfComputers=@()
        
        Write-Verbose "[$($MyInvocation.InvocationName)]: Begin Process Block"
        
        if (!$ComputerName){
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name not provided running on localhost"
            $Users = net localgroup $LocalGroupName | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4

            $Object = New-Object psobject
            $Object | Add-Member ComputerName $env:COMPUTERNAME
            $Object | Add-Member GroupName $LocalGroupName
            $Object | Add-Member User $Users
            
            $ArrayOfComputers += $Object            
        }
        else{
            
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name provided checking groups on these computers $ComputerName"
            foreach ($Computer in $ComputerName){             
                
                try
                {                   
                    Write-Verbose "[$($MyInvocation.InvocationName)]: Testing if computer reachable"
                    if (Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop -Quiet){
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Computer $Computer Reachable. Connecting.."
                        if ($Creds){
                            Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials were provided. Running as user: $Credential"
                            $Users = Invoke-Command -ComputerName $Computer -ScriptBlock {
                                                                                    # From: http://powershell.org/wp/2013/04/02/get-local-admin-group-members-in-a-new-old-way-3/
                                                                                    net localgroup Administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4
                                                                                }-ArgumentList $LocalGroupName -Credential $Creds -ErrorAction Continue
                            $Object = New-Object psobject
                            $Object | Add-Member ComputerName $Computer
                            $Object | Add-Member GroupName $LocalGroupName
                            $Object | Add-Member User $Users

                            $ArrayOfComputers += $Object    
                        }
                        else{
                            Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials not provided. Running as user: $env:USERNAME"
                            $Users = Invoke-Command -ComputerName $Computer -ScriptBlock {
                                                                                    # From: http://powershell.org/wp/2013/04/02/get-local-admin-group-members-in-a-new-old-way-3/
                                                                                    net localgroup Administrators | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4                                                                          
                                                                                }-ArgumentList $LocalGroupName -ErrorAction Continue
                            $Object = New-Object psobject
                            $Object | Add-Member ComputerName $Computer
                            $Object | Add-Member GroupName $LocalGroupName
                            $Object | Add-Member User $Users

                            $ArrayOfComputers += $Object
                        }
                    }
                    else{Write-Output "Computer $Computer not reachable"}           
                }
                catch{ 
                    Write-Output "Something went Wrong. Last Error Was: $($Error[0])"
                }
            }# END Foreach
        }

        # Return All Objects
        $ArrayOfComputers
    }
    End
    {
    }
}

function Add-JLabUserLocalGroup {
<#
.Synopsis
   This cmdlet Adds users to computer local group.
.DESCRIPTION
   This cmdlet Adds users to computer local group.
.EXAMPLE
   Add-JLabUserLocalGroup -UserName "lisa.simpson","homer.simpson" -Domain contoso
   Adds Lisa and Homer (contoso domain users) to Local Administrators group on local computer.
.EXAMPLE
   Add-JLabUserLocalGroup -ComputerName "server01","server02" -UserName "lisa.simpson","homer.simpson" -Domain contoso
   Adds Lisa and Homer (contos odomain users) to Local Administrators group on computers: server01 and server02
.EXAMPLE
   Add-JLabUserLocalGroup -ComputerName (Get-Content -Path C:\Users\john.doe\Desktop\computers.txt) -UserName "lisa.simpson","homer.simpson" -Domain contoso -LocalGroupName "Power Users" -Credential john.doe
   Adds Lisa and Homer (contoso domain users) to Local "Power Users" group on computers provided in computers.txt
.INPUTS
    String
.NOTES
   Created By: Jure Labrovic

   Web Page: https://jurelab.wordpress.com/

   Revision:
   Version 1.0   6.11.2015
#>

    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://jurelab.wordpress.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Parameter Set 1')]   
        [Alias("Computer")]
        [string[]] 
        $ComputerName,
      
        [Alias("Group")]
        [string]
        $LocalGroupName="Administrators",

        [Parameter(Mandatory=$true,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]        
        [Alias("User")]
        [string[]]
        $UserName,

        [Parameter(Mandatory=$true,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]        
        [Alias("DomainName")]
        [string]
        $Domain,

        [string]
        $ErrorLog="$env:USERPROFILE\Desktop\JLabAddUserToGroupErrorLog.txt",
        
        [switch]
        $LogErrors,
        
        [string]
        $Credential
    )

    Begin
    {
        if ($LogErrors){
            Write-Verbose "[$($MyInvocation.InvocationName)]: [$($MyInvocation.InvocationName)]: Log file can be found in: $ErrorLog"
        }

        if ($Credential){
            $Creds=Get-Credential -UserName $Credential -Message "Enter password"
        }  
    }
    Process
    {
         Write-Verbose "[$($MyInvocation.InvocationName)]: Begin Process Block"
        
        if (!$ComputerName){
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name not provided running on localhost"
            
            # Modified from Ed Wilson script Use PowerShell to Add Local Users to Local Groups
            $Adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$LocalGroupName,group"
            
            $AlreadyMembers=(Get-JLabUserLocalGroup -ComputerName localhost).user          

            foreach ($User in $UserName){
                
                if ($AlreadyMembers -notcontains "$Domain\$User"){
                    Write-Verbose "[$($MyInvocation.InvocationName)]: User: $User not member of $LocalGroupName on $env:COMPUTERNAME. Adding..."                
                    # Modified from Ed Wilson script Use PowerShell to Add Local Users to Local Groups            
                    $Adsi.psbase.Invoke("Add",([ADSI]"WinNT://$Domain/$User").path)
                }
                else { Write-Warning "[$($MyInvocation.InvocationName)]: User: $User already member of $LocalGroupName on $env:COMPUTERNAME"}
            }         
        }
        else{
          
             
                try
                {
                                
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name(s) provided => $ComputerName"
            
            $PingableComputers = @()
                       
            foreach ($Comp in $ComputerName){                
                If (Test-Connection -ComputerName $Comp -Count 1 -ErrorAction Stop -Quiet){
                    Write-Verbose "[$($MyInvocation.InvocationName)]: Computer: $Comp reachable adding to new array..."
                    $PingableComputers+=$Comp
                }
                else {Write-Warning "[$($MyInvocation.InvocationName)]: Computer: $Comp not reachable.."}
            }
            Write-Verbose "[$($MyInvocation.InvocationName)]: These computers are reachable $PingableComputers. Trying to add users." 
                    
                    if ($Creds){
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials were provided running as: $Credential"                                                                    

                        Invoke-Command -ComputerName $PingableComputers -ScriptBlock {
                                                param(
                                                    $Domain,                                                    
                                                    $UserName,
                                                    $LocalGroupName
                                                    )
                                                $Users = net localgroup $LocalGroupName | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4

                                                
                                                foreach ($User in $UserName){ 
                                                        if ($Users -contains "$Domain\$User"){
                                                            Write-Warning "User: $User already member of $LocalGroupName on $env:COMPUTERNAME"
                                                         }
                                                         else{
                                                            net localgroup $LocalGroupName "$Domain\$User" /add | Out-Null
                                                        }
                                                }
                                            }-ArgumentList $Domain,$UserName,$LocalGroupName -Credential $Creds -ErrorAction Continue
                    }
                    else{
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials Not provided running as: $env:USERNAME" 
                        
                        Invoke-Command -ComputerName $PingableComputers -ScriptBlock {
                                                param(
                                                    $Domain,                                                    
                                                    $UserName,
                                                    $LocalGroupName
                                                    )
                                                $Users = net localgroup $LocalGroupName | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4

                                                
                                                foreach ($User in $UserName){ 
                                                        if ($Users -contains "$Domain\$User"){
                                                            Write-Warning "User: $User already member of $LocalGroupName on $env:COMPUTERNAME"
                                                         }
                                                         else{
                                                            net localgroup $LocalGroupName "$Domain\$User" /add | Out-Null
                                                        }
                                                }
                                            }-ArgumentList $Domain,$UserName,$LocalGroupName -ErrorAction Continue
                    }

                }                
                catch{ 
                    Write-Warning "Something went Wrong. Last Error Was: $($Error[0])"
                }
        }        
    }
    End
    {
    }
}

function Remove-JLabUserLocalGroup {
<#
.Synopsis
   This cmdlet removes users from computer local group.
.DESCRIPTION
   This cmdlet removes users from computer local group.
.EXAMPLE
   Remove-JLabUserLocalGroup -UserName "lisa.simpson","homer.simpson" -Domain contoso
   Removes Lisa and Homer (contoso domain users) from Local Administrators group on local computer.
.EXAMPLE
   Remove-JLabUserLocalGroup -ComputerName "server01","server02" -UserName "lisa.simpson","homer.simpson" -Domain contoso
   Removes Lisa and Homer (contos odomain users) from Local Administrators group on computers: server01 and server02
.EXAMPLE
   Remove-JLabUserLocalGroup -ComputerName (Get-Content -Path C:\Users\john.doe\Desktop\computers.txt) -UserName "lisa.simpson","homer.simpson" -Domain contoso -LocalGroupName "Power Users" -Credential john.doe
   Removes Lisa and Homer (contoso domain users) from
   
   
   
   
   
   
   
   
   
    Local "Power Users" group on computers provided in computers.txt
.INPUTS
    String
.NOTES
   Created By: Jure Labrovic

   Web Page: https://jurelab.wordpress.com/

   Revision:
   Version 1.0   6.11.2015
#>

    [CmdletBinding(DefaultParameterSetName='Parameter Set 1', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  HelpUri = 'https://jurelab.wordpress.com/',
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Param1 help description
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Parameter Set 1')]   
        [Alias("Computer")]
        [string[]] 
        $ComputerName,
      
        [Alias("Group")]
        [string]
        $LocalGroupName="Administrators",

        [Parameter(Mandatory=$true,
                   ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]        
        [Alias("User")]
        [string[]]
        $UserName,

        [Parameter(Mandatory=$true,
            ParameterSetName='Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]        
        [Alias("DomainName")]
        [string]
        $Domain,

        [string]
        $ErrorLog="$env:USERPROFILE\Desktop\JLabRemoveUserToGroupErrorLog.txt",
        
        [switch]
        $LogErrors,
        
        [string]
        $Credential
    )

    Begin
    {
        if ($LogErrors){
            Write-Verbose "[$($MyInvocation.InvocationName)]: [$($MyInvocation.InvocationName)]: Log file can be found in: $ErrorLog"
        }

        if ($Credential){
            $Creds=Get-Credential -UserName $Credential -Message "Enter password"
        }  
    }
    Process
    {
         Write-Verbose "[$($MyInvocation.InvocationName)]: Begin Process Block"
        
        if (!$ComputerName){
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name not provided running on localhost"
            
            
            $AlreadyMembers=(Get-JLabUserLocalGroup -ComputerName localhost).user          

            foreach ($User in $UserName){
                
                if ($AlreadyMembers -notcontains "$Domain\$User"){
                    Write-Warning "[$($MyInvocation.InvocationName)]: User: $User not found in $LocalGroupName on $env:COMPUTERNAME."                
                    

                }
                else { Write-Verbose "[$($MyInvocation.InvocationName)]: User: $User Found in $LocalGroupName on $env:COMPUTERNAME. Removing.."
                       net localgroup $LocalGroupName "$Domain\$User" /delete | Out-Null 
                }
            }         
        }
        else{
          
             
            try
            {
                                
            Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name(s) provided => $ComputerName"
            
            $PingableComputers = @()
                       
            foreach ($Comp in $ComputerName){                
                If (Test-Connection -ComputerName $Comp -Count 1 -ErrorAction Stop -Quiet){
                    Write-Verbose "[$($MyInvocation.InvocationName)]: Computer: $Comp reachable adding to new array..."
                    $PingableComputers+=$Comp
                }
                else {Write-Warning "[$($MyInvocation.InvocationName)]: Computer: $Comp not reachable.."}
            }
            Write-Verbose "[$($MyInvocation.InvocationName)]: These computers are reachable $PingableComputers. Trying to add users." 
                    
                    if ($Creds){
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials were provided running as: $Credential"                                                                    

                        Invoke-Command -ComputerName $PingableComputers -ScriptBlock {
                                                param(
                                                    $Domain,                                                    
                                                    $UserName,
                                                    $LocalGroupName
                                                    )
                                                $Users = net localgroup $LocalGroupName | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4

                                                
                                                foreach ($User in $UserName){ 
                                                        if ($Users -contains "$Domain\$User"){
                                                            Write-Verbose "User: $User member of $LocalGroupName on $env:COMPUTERNAME. Removing User from Group..."
                                                            net localgroup $LocalGroupName "$Domain\$User" /delete | Out-Null
                                                         }
                                                         else{
                                                            Write-Warning "Could not find User: $User on Computer $env:COMPUTERNAME in group $LocalGroupName"
                                                        }
                                                }
                                            }-ArgumentList $Domain,$UserName,$LocalGroupName -Credential $Creds -ErrorAction Continue
                    }
                    else{
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials Not provided running as: $env:USERNAME" 
                     
                     
                        Invoke-Command -ComputerName $PingableComputers -ScriptBlock {
                                                param(
                                                    $Domain,                                                    
                                                    $UserName,
                                                    $LocalGroupName
                                                    )
                                                $Users = net localgroup $LocalGroupName | where {$_ -AND $_ -notmatch "command completed successfully"} | select -skip 4

                                                
                                                foreach ($User in $UserName){ 
                                                        if ($Users -contains "$Domain\$User"){
                                                            Write-Verbose "User: $User member of $LocalGroupName on $env:COMPUTERNAME. Removing User from Group..."
                                                            net localgroup $LocalGroupName "$Domain\$User" /delete | Out-Null
                                                         }
                                                         else{
                                                            Write-Warning "Could not find User: $User on Computer $env:COMPUTERNAME in group $LocalGroupName"
                                                        }
                                                }
                                            }-ArgumentList $Domain,$UserName,$LocalGroupName -ErrorAction Continue
                    }

                }# END Try                
                catch{ 
                    Write-Warning "Something went Wrong. Last Error Was: $($Error[0])"

　
                }
        }        
    }
    End
    {
    }
}

function Get-JLabCertificateStore {
<#
.SYNOPSIS
   This Cmdlet Displays Certificates. If no Parameter is provided Computers Personal Certificate Store is returned
.DESCRIPTION
   This Cmdlet Displays Certificates. If no Parameter is provided Computers Personal Certificate Store is returned. You can run it on local computer or provide ComputerName-s
.EXAMPLE
    Get-JLabCertificateStore | select -ExpandProperty CertificateList | select DnsNameList,FriendlyName,NotAfter,NotBefore,HasPrivateKey,Thumbprint,Serial*,Subject
    Retruns Computers Personal Certificate Store
.EXAMPLE
    Get-JLabCertificateStore -CertificateStore 'Cert:\CurrentUser\My' | select -ExpandProperty CertificateList | select subject,friendlyname,thumbprint,notafter
    Retruns Current Users Personal Certificate Store
.EXAMPLE
    Get-JLabCertificateStore -ComputerName Computer01 -Credential contoso\homer.simpson | select -ExpandProperty CertificateList | select DnsNameList,FriendlyName,NotAfter,NotBefore,HasPrivateKey,Thumbprint,Serial*,Subject
    Returns Certificates from Remote Computer with Alternate Credentials
.EXAMPLE
    Get-JLabCertificateStore -ComputerName (Get-Content -Path "$env:USERPROFILE\Desktop\Computers.txt") -Credential contoso\homer.simpson | select -ExpandProperty CertificateList | select DnsNameList,FriendlyName,NotAfter,NotBefore,HasPrivateKey,Thumbprint,Serial*,Subject
    Returns Certificates from List of Remote Computers with Alternate Credentials
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   Created By: Jure Labrovic
   Web Page: https://jurelab.wordpress.com/

   Revision:
   Version 1.0   22.11.2016
.COMPONENT
   The component this cmdlet belongs to NA
.ROLE
   The role this cmdlet belongs to NA
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>
    [CmdletBinding()]

    param(
        [string[]]$CertificateStore = 'Cert:\LocalMachine\My',
        [string[]]
        $ComputerName=$env:COMPUTERNAME,
        [string]
        $ErrorLog="$env:USERPROFILE\Desktop\JLabGetUsersInGroupErrorLog.txt",
        [switch]
        $LogErrors,
        [string]
        $Credential
        )

　
    Begin
    {
        if ($LogErrors){
            Write-Verbose "[$($MyInvocation.InvocationName)]: [$($MyInvocation.InvocationName)]: Log file can be found in: $ErrorLog"
        }

        if ($Credential){
            $Creds=Get-Credential -UserName $Credential -Message "Enter password"
        }  
    }
    Process
    {
        $ArrayOfComputers=@()        
            
        Write-Verbose "[$($MyInvocation.InvocationName)]: Computer Name provided checking groups on these computers $ComputerName"
        
        foreach ($Computer in $ComputerName){             
          $Object = $null      
            try
            {
                if ($Computer -eq $env:COMPUTERNAME){
                    Write-Verbose "[$($MyInvocation.InvocationName)]: This is Local Computer working with local credentials"

                    $Certificates = Get-ChildItem $CertificateStore

                     foreach ($Certificate in $Certificates){  
                                        $ReverseSerial = $null
                 
                                        $SerialNumber = $Certificate.SerialNumber
        
                                        If ($SerialNumber){   
            
                                            # Reverse Serial Number 
                                            $SerialNumberLength = $SerialNumber.Length
                                            $SerialNumberHalf = $SerialNumberLength/2

                                            $SerialNumberLengthBin = $SerialNumberLength - 1

                                            $i = 1

                                            for ($s = $SerialNumberHalf; $s -gt 0; $s-- ){
                                                if ($ReverseSerial -eq $null){
                                                    $ReverseSerial = $SerialNumber[$SerialNumberLengthBin-1]+$SerialNumber[$SerialNumberLengthBin] + " "
                                                }
                                                else{
                                                    $First = $SerialNumber[$SerialNumberLengthBin-$i]
                                                    $Last = $SerialNumber[$SerialNumberLengthBin-$i+1]

                                                    $ReverseSerial = $ReverseSerial + $First + $Last  + " "
                                                }
                                                $i = $i+2
                                            }
            
                                            $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue $ReverseSerial

                                            # END Reverse Serial Number
                                        }
                                        else {
                                            $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue 'NA'
                                        }

                        } # END Modify Certificate List
                            
                    $Object = New-Object psobject

　
                    $Object | Add-Member ComputerName $Computer
                    $Object | Add-Member CertificateList $Certificates

                    $ArrayOfComputers += $Object  
                }
            else{              
                                   
                Write-Verbose "[$($MyInvocation.InvocationName)]: Testing if computer reachable"
                if (Test-Connection -ComputerName $Computer -Count 2 -ErrorAction Stop -Quiet){

                    Write-Verbose "[$($MyInvocation.InvocationName)]: Computer $Computer Reachable. Connecting.."
                        
                    if ($Creds){
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials were provided. Running as user: $Credential"
                        $Certificates = Invoke-Command -ComputerName $Computer -ScriptBlock {param ([string]$CertificateStore)
                                                                                Get-ChildItem $CertificateStore
                                                                            }-ArgumentList $CertificateStore -Credential $Creds -ErrorAction Continue
                            
                            
                                Write-Verbose "[$($MyInvocation.InvocationName)]: These Certificates were found on $Computer`n$Certificates"
                                # Modify Certificate List
                                foreach ($Certificate in $Certificates){  
                                        $ReverseSerial = $null
                 
                                        $SerialNumber = $Certificate.SerialNumber
        
                                        If ($SerialNumber){   
            
                                            # Reverse Serial Number 
                                            $SerialNumberLength = $SerialNumber.Length
                                            $SerialNumberHalf = $SerialNumberLength/2

                                            $SerialNumberLengthBin = $SerialNumberLength - 1

                                            $i = 1

                                            for ($s = $SerialNumberHalf; $s -gt 0; $s-- ){
                                                if ($ReverseSerial -eq $null){
                                                    $ReverseSerial = $SerialNumber[$SerialNumberLengthBin-1]+$SerialNumber[$SerialNumberLengthBin] + " "
                                                }
                                                else{
                                                    $First = $SerialNumber[$SerialNumberLengthBin-$i]
                                                    $Last = $SerialNumber[$SerialNumberLengthBin-$i+1]

                                                    $ReverseSerial = $ReverseSerial + $First + $Last  + " "
                                                }
                                                $i = $i+2
                                            }
            
                                            $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue $ReverseSerial

                                            # END Reverse Serial Number
                                        }
                                        else {
                                            $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue 'NA'
                                        }

                                    } # END Modify Certificate List
                            
                        $Object = New-Object psobject
                        $Object | Add-Member ComputerName $Computer
                        $Object | Add-Member CertificateList $Certificates

                        $ArrayOfComputers += $Object    
                    }
                    else{
                        Write-Verbose "[$($MyInvocation.InvocationName)]: Credentials not provided. Running as user: $env:USERNAME"
                        $Certificates = Invoke-Command -ComputerName $Computer -ScriptBlock {param ([string]$CertificateStore)
                                                                                Get-ChildItem $CertificateStore                                                                          
                                                                            }-ArgumentList $CertificateStore -ErrorAction Continue
                                # Modify Certificate List
                                foreach ($Certificate in $Certificates){  
                                    $ReverseSerial = $null
                 
                                    $SerialNumber = $Certificate.SerialNumber
        
                                    If ($SerialNumber){   
            
                                        # Reverse Serial Number 
                                        $SerialNumberLength = $SerialNumber.Length
                                        $SerialNumberHalf = $SerialNumberLength/2

                                        $SerialNumberLengthBin = $SerialNumberLength - 1

                                        $i = 1

                                        for ($s = $SerialNumberHalf; $s -gt 0; $s-- ){
                                                if ($ReverseSerial -eq $null){
                                                    $ReverseSerial = $SerialNumber[$SerialNumberLengthBin-1]+$SerialNumber[$SerialNumberLengthBin] + " "
                                                }
                                                else{
                                                    $First = $SerialNumber[$SerialNumberLengthBin-$i]
                                                    $Last = $SerialNumber[$SerialNumberLengthBin-$i+1]

                                                    $ReverseSerial = $ReverseSerial + $First + $Last  + " "
                                                }
                                                $i = $i+2
                                            }
            
                                        $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue $ReverseSerial

                                        # END Reverse Serial Number
                                    }
                                    else {
                                        $Certificate | Add-Member -NotePropertyName SerialNumberReverse -NotePropertyValue 'NA'
                                    }

                                } # END Modify Certificate List                            
                            
                            
                        $Object = New-Object psobject
                        $Object | Add-Member ComputerName $Computer
                        $Object | Add-Member CertificateList $Certificates

　
                        $ArrayOfComputers += $Object
                    }
                }
                else{Write-Output "Computer $Computer not reachable"} 
                }          
            }# End Try
            catch{ 
                    Write-Output "Something went Wrong. Last Error Was: $($Error[0])"
                }
        } # END Foreach Computer
            

    # Return All Objects
    $ArrayOfComputers
    }
    End
    {
    }
}

　
function Test-JLabComputerStatus {
<#
.Synopsis
   This cmdlet tests if computer is Pingable, in AD, DNS and WinRM Capable.
.DESCRIPTION
   This cmdlet tests if computer is Pingable, in AD, DNS and WinRM Capable.
.EXAMPLE
   Test-JLabComputerStatus
   Gets Members in local administrators group on local computer
.EXAMPLE
   Test-JLabComputerStatus -ComputerName "server01","server02" -DomainName "contoso.com"
   Tests if Computers are accessible: server01 and server02.
.OUTPUTS
   PSCustomObject
.NOTES
   Created By: Jure Labrovic

   Web Page: https://jurelab.wordpress.com/

   Revision:
   Version 1.0   4.7.2017
#>
    [CmdletBinding()]

    param(
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    HelpMessage = 'Computer name or IP address'
                    )] 
        [string[]]$ComputerName,
        [string]$DomainName
        )

    BEGIN {
        Write-Verbose "Start BEGIN Block"
        Write-Verbose "END BEGIN Block"
    }
    PROCESS {
        foreach ($Computer in $ComputerName){
            Write-Verbose "Begin PROCESS Block"
            
            try{
                Write-Verbose "[PROCESS][$Computer]: Trying to ping" 
                $IsPinging = Test-NetConnection $Computer -ErrorAction Stop -WarningAction SilentlyContinue
                
                if ($($IsPinging.PingSucceeded)){
                    $IsPinging = $true
                }
                else {
                    $IsPinging = $false
                }                             
            }
            catch{
                $IsPinging = $false
                Write-Verbose "[PROCESS][Test-NetConnection][$Computer]:$Error[0].exception"
            }        

            try{
                Write-Verbose "[PROCESS][$Computer]: Checking if in AD"
                
                if ($Computer.EndsWith(".$DomainName")){
                    $ComputerMod = $Computer.Replace(".$DomainName",'')          
                    $IsInAD = Get-ADComputer -Filter {name -eq $ComputerMod}
                }
            else {
                $IsInAD = Get-ADComputer -Filter {name -eq $Computer}
            }

                if ($IsInAD){
                    $IsInAD = $true
                }
                else {
                    $IsInAD = $false
                }  

            }
            catch{
                $IsInAD = $false 
                Write-Verbose "[PROCESS][Get-ADComputer][$Computer]:$Error[0].exception"
            }
            
            try{
                Write-Verbose "[PROCESS][$Computer]:Checking if in DNS"

                 if ($Computer.EndsWith(".$DomainName")){          
                    $IsInDNS = Resolve-DnsName "$Computer" -DnsOnly -ErrorAction Stop -WarningAction Stop          
                }
                else {
                    $CompDomain = $Computer+"."+$DomainName
                    $IsInDNS = Resolve-DnsName $CompDomain  -DnsOnly -ErrorAction Stop -WarningAction Stop
                }

                if ($IsInDNS){
                    $IsInDNS = $true
                }
                else {
                    $IsInDNS = $false
                }   
            }
            catch{
                $IsInDNS = $false
                Write-Verbose "[PROCESS][Resolve-DnsName][$Computer]:$Error[0].exception"
            }

            try{
                Write-Verbose "[PROCESS][$Computer]: Testing WinRM"
                $WinRMworks = Test-WSMan $Computer -ErrorAction:Stop -WarningAction:Stop

                if ($WinRMworks){
                    $WinRMworks = $true
                }
                else {
                    $WinRMworks = $false
                } 
                

            }
            catch{
                $WinRMworks = $false
                Write-Verbose "[PROCESS][Test-WSMan][$Computer]:$Error[0].exception"
            } 

            if ( $IsInAD -and $IsPinging -and $IsInDNS -and $WinRMworks ){
                Write-Host -ForegroundColor Green "[OK] Computer $Computer is accessible."
                $CompAccessible = $true
            }
            else{
                Write-Host -ForegroundColor Yellow "[BAD]$Computer is not accessible."
                Write-Host -ForegroundColor Yellow " [BAD]$Computer Additional info:"
                $CompAccessible = $false               

                if (!$IsPinging){
                   Write-Host -ForegroundColor Yellow " [BAD]$Computer => Ping Failed."     
                }
                else{
                  Write-Host -ForegroundColor Green " [OK]$Computer => Ping OK."  
                }
                if (!$IsInAD){
                   Write-Host -ForegroundColor Yellow " [BAD]$Computer => NOT in Active Directory."     
                }
                else{
                   Write-Host -ForegroundColor Green " [OK]$Computer => Is in Active Directory." 
                }
                if (!$IsInDNS){
                   Write-Host -ForegroundColor Yellow " [BAD]$Computer => not in DNS."     
                }
                else {
                     Write-Host -ForegroundColor Green " [OK]$Computer => Is in DNS."
                }
                if (!$WinRMworks){
                   Write-Host -ForegroundColor Yellow " [BAD]$Computer => WinRM not working."     
                }
                else{
                    Write-Host -ForegroundColor Green " [OK]$Computer => WinRM working."
                }

            }

            $Props = @{
                'ComputerName' = $Computer;
                'IsPingable' = $IsPinging;
                'IsInAD' = $IsInAD;
                'IsInDNS' = $IsInDNS;
                'WinRM' = $WinRMworks;
                'Accessible' = $CompAccessible           
            }

            $Obj = New-Object -TypeName psobject -Property $Props
            Write-Output $Obj

　
            Write-Verbose "END PROCESS Block"            
        }    
    }
    END{}
}

　
　
　
　
## Older Scripts....
####################################################################################################################################################
# Created By Jure Labrovic
# Version 1.0
# Release Date: 11.8.2014
# http://jurelab.wordpress.com

# CmdLets: CmdLets: Install-MyDotNET35, Get-MyOSVersion, Get-MyOSArchitecture, Test-MyLDAPuser
#
####################################################################################################################################################

####################################################################################################################################################
# Created By Jure Labrovic
# Version 1.1
# http://jurelab.wordpress.com

# Modify Date: 28.11.2014
# Modification: Added New function: Get-MyPerfToPID

# CmdLets: Install-MyDotNET35, Get-MyOSVersion, Get-MyOSArchitecture, Test-MyLDAPuser, Get-MyPerfToPID
#
####################################################################################################################################################

####################################################################################################################################################
# Created By Jure Labrovic
# Version 1.1
# http://jurelab.wordpress.com

# Modify Date: 21.7.2015
# Modification: Added New function: Get-MyHotFixesInstalled

# CmdLets: Install-MyDotNET35, Get-MyOSVersion, Get-MyOSArchitecture, Test-MyLDAPuser, Get-MyPerfToPID, Get-MyHotFixesInstalled
#
####################################################################################################################################################

　
# Install-MyDotNet Installs .NET Framework 3.5 SP1 on Windows Server 2008, 2008 R2, 2012 and 2012 R2
# Install .NET - Works with 2008 and above Server Platforms
Function Install-MyDotNET35{
<#
.SYNOPSIS
    This Function Installs .NET Framework 3.5 SP1 on Windows Server 2008, 2008 R2, 2012 and 2012 R2
.NOTES
    This Function Works with 2008 and above Server Platforms.
    Install works with 2008 Servers
    For 2012 it Only Checks if .NET35 is installed
.EXAMPLE
    Install-MyDotNET35
    Installs .NET35 on local system
.EXAMPLE
    Install-MyDotNET35 -ComputerName server01.contoso.com
    Installs .NET35 on local or remote system
.LINK
    http://jurelab.wordpress.com/
#>
    Param(
    [Parameter(Position=1)]$ComputerName='localhost'
    )
    
    if (($ComputerName -eq 'localhost') -or ($ComputerName.startswith($env:COMPUTERNAME))){ #This Is Local Computer
        
        $OSversionString = ((Get-WmiObject -class Win32_OperatingSystem).Caption)
        
        If($OSversionString -match "2012"){ # If 2012 Server Operating system...
        
        $netIsInstalled=(Get-WindowsFeature net-framework-core).Installed

            if ($netIsInstalled -eq $true){
                ".NET 3.5 Is Already installed on: $env:COMPUTERNAME"
            }
            Elseif ($netIsInstalled -eq $false){
                ".NET 3.5 Is not installed on: $env:COMPUTERNAME Install Script Needs to be prepaired.. No Action taken."                   
            }Else {"Something wrong Happend.."}
        
        }
        Elseif ( $OSversionString -match "2008"){ # If 2008 Server Operating system...

            Import-Module ServerManager
            $netIsInstalled=(Get-WindowsFeature net-framework-core).Installed

            if ($netIsInstalled -eq $true){
                ".NET 3.5 Is Already installed on: $env:COMPUTERNAME"
            }
            Elseif ($netIsInstalled -eq $false){
                ".NET 3.5 Is not installed on: $env:COMPUTERNAME Installing..."
                Add-WindowsFeature net-framework-core    
            }Else {"Something wrong Happend.."}

        
        }Else { "Could Not Determinte OS Value: $env:COMPUTERNAME"} # This is not 2008 or 2012 OS

    }
    else{ # This is remote Computer
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $OSVersionString = ((Get-WmiObject -class Win32_OperatingSystem).Caption)         

            If( $OSVersionString -match "2012"){
                
                $netIsInstalled=(Get-WindowsFeature net-framework-core).Installed

                if ($netIsInstalled -eq $true){
                ".NET 3.5 Is Already installed on: $env:COMPUTERNAME"
            }
            Elseif ($netIsInstalled -eq $false){
                ".NET 3.5 Is not installed: $env:COMPUTERNAME  Install Script Needs to be prepaired.. No Action taken."
                  
            }Else {"Something wrong Happend.."}
                
            }
            Elseif ( $OSVersionString -match "2008"){
                        
            Import-Module ServerManager
            $netIsInstalled=(Get-WindowsFeature net-framework-core).Installed

            if ($netIsInstalled -eq $true){
                ".NET 3.5 Is Already installed on: $env:COMPUTERNAME"
            }
            Elseif ($netIsInstalled -eq $false){
                ".NET 3.5 Is not installed on: $env:COMPUTERNAME Installing..."
                Add-WindowsFeature net-framework-core    
            }Else {"Something wrong Happend.."}
                 
            }Else { "Could Not Determinte OS Value on: $env:COMPUTERNAME"}              
        }
    }    
} # END Install-MyDotNET

　
# This function gets OS Version and returns its value as a String (for example: Microsoft Windows 8.1 Enterprise)
Function Get-MyOSVersion{
<#
.SYNOPSIS
    This function gets OS Version and returns its value as a String (for example: Microsoft Windows 8.1 Enterprise)
.NOTES
    There Are No Notes
.EXAMPLE
    Get-MyOSVersion
    Returns OS Version
.LINK
    http://jurelab.wordpress.com/
#>
    Param(
    [Parameter(Position=1)]$ComputerName='localhost'
    )
    if (($ComputerName -eq 'localhost') -or ($ComputerName.startswith($env:COMPUTERNAME))){
            Return ((Get-WmiObject -class Win32_OperatingSystem).Caption)
        }

    else{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {Return ((Get-WmiObject -class Win32_OperatingSystem).Caption)}
    }
} # END Get-MyOSVersion

　
　
# This function queries OS Architecture and returns its value as a string (32-bit or 64-bit)
Function Get-MyOSArchitecture{
<#
.SYNOPSIS
    This function queries OS Architecture and returns its value as a string (32-bit or 64-bit)
.NOTES
    There Are No Notes
.EXAMPLE
    Get-MyOSArchitecture
    Returns OS Architecture
.LINK
    http://jurelab.wordpress.com/
#>
   Param(
    [Parameter(Position=1)]$ComputerName='localhost'
    )

    if (($ComputerName -eq 'localhost') -or ($ComputerName.startswith($env:COMPUTERNAME))){
        $OSarchitecture = (Get-WmiObject -Class Win32_OperatingSystem -ea 0).OSArchitecture
           if (($OSarchitecture -eq '64-bit') -or ($OSarchitecture -eq '32-bit')) {            
            Return $OSarchitecture           
           }else {"Could Not determine OS Architecture"}
    }
    else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
           $OSarchitecture = (Get-WmiObject -Class Win32_OperatingSystem -ea 0).OSArchitecture
           if (($OSarchitecture -eq '64-bit') -or ($OSarchitecture -eq '32-bit')) {            
            Return $OSarchitecture           
           }else {"Could Not determine OS Architecture"}
        }
    }
} # END Get-MyOSArchitecture

　
#This Function tests AD Account, and displays its LDAP Path
Function Test-MyLDAPuser {
<#
.SYNOPSIS
    This Function tests AD Account, and displays its LDAP Path
.NOTES
    There Are No Notes
.EXAMPLE
    Test-MyLDAPuser
    Asks For User Name and Its Password and tests if Account can query AD
.LINK
    http://jurelab.wordpress.com/
#>
    # Get user name and Password
    $Credential = Get-Credential
    Clear-Host

    $UserName=$Credential.UserName
    $Password=$Credential.getnetworkCredential().password

    "LDAP information for user: " + $UserName + "`n---------------------------------------------------"

    # Get LDAP Path
    $Search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
    $Search.Filter = "(&(objectClass=user)(sAMAccountName= $UserName))"
    $OneUser= $Search.FindOne()
    $LDAPpath=$OneUser | select path
    
    "`nLDAP Path`n---------`n " + $LDAPpath.Path
    
      
    # Display User Info    
    $UserInfo=Get-ADUser -LDAPFilter "(&(objectclass=user)(objectcategory=user)(sAMAccountName= $UserName))"
    "`nUser Info`n---------`n "
    $UserInfo

　
    # Test User Credentials
    $Authent=(New-Object directoryservices.directoryentry "",$UserName,$Password).psbase.name -ne $null
    "`nAuthentication Test:`n--------------------"
    "`nAuthentication for user: " + $UserName + " Successful?`n" + $Authent   
} # END Test-MyLDAPuser

# This Function Maps Process Monitor Service Names To PID

function Get-MyPerfToPID{
<#
.SYNOPSIS
    This Function Maps Process Monitor Service Names To PID
.NOTES
    There Are No Notes
.EXAMPLE
    Get-MyPerfToPID
    Retruns All Process Monitor Service Names along with its PID
.EXAMPLE
    Get-MyPerfToPID | where { $_.ProcessNamePerf -match "svch" } | ft -AutoSize
    Returns All Processes which contain "svch" string and Outputs them along with respective PID
.LINK
    http://jurelab.wordpress.com/
#>
    try {
        $Counters=(Get-Counter "\Process(*)\ID Process").CounterSamples | select Path,RawValue -ErrorAction Stop

        $ArrayOfProcesses=@()

        foreach ($Counter in $counters){
            $SplitCounter1=($Counter.Path).Split('(')
            $SplitCounter2=$SplitCounter1[1].Split(')')
            $ProcessName1=$SplitCounter2[0]
    
            $ProcessMistery = New-Object PSObject
            $ProcessMistery | Add-Member -membertype NoteProperty -name ProcessNamePerf -value $ProcessName1
            $ProcessMistery | Add-Member -membertype NoteProperty -name PID -value $Counter.RawValue

            $ArrayOfProcesses += $ProcessMistery
        } 
    }
    catch {}
    $ArrayOfProcesses
} # END Get-MyPerfToPID

　
# Get-MyLogedUsers
Function Get-MyLogedUsers{
<#
.SYNOPSIS
    This Function gets Last loged Users
.NOTES
    There Are No Notes
.EXAMPLE
    Get-MyLogedUsers
    Retruns last 10 loged users
.EXAMPLE
    Get-MyLogedUsers -ComputerName "Server01" -EventsNo 20
    Returns last 20 loged on users for Server01
.LINK
    http://jurelab.wordpress.com/
#>
    Param(
    [Parameter(Position=1)]$ComputerName='localhost',
    [int]$EventsNo=10
    )

        if (($ComputerName -eq 'localhost') -or ($ComputerName.startswith($env:COMPUTERNAME))){ #This Is Local Computer

            $Events=Get-EventLog -LogName "System" | where {$_.eventID -eq 7001}
            $Events10=$Events | select -Last $EventsNo

            # Get Local SID <=> User HashTable
            $ComputerName = $env:COMPUTERNAME
            $Computer = [ADSI]"WinNT://$ComputerName,computer"  
            Format-Table Name, Description -autoSize
            $LocalUsers=$Computer.psbase.Children | Where-Object { $_.psbase.schemaclassname -eq 'user' }

            $UsersHash=@{}
            foreach ($LocalUser in $LocalUsers){
                $ObjUser=New-Object System.Security.Principal.NTAccount($LocalUser.Properties.name.Value)
                $StrSID=$ObjUser.Translate([System.Security.Principal.SecurityIdentifier])
    
                $UsersHash.Add($StrSID.Value,$LocalUser.Properties.Name.Value)
            }
        
        # END Get Local SID <=> User HashTable

        foreach ($Event in $Events10){
            $UserSid=($Event.ReplacementStrings)[1]

            Try{$User=Get-ADUser -Identity $UserSid}
                catch {$null;Write-Host "-----`nLocalUser: " $UsersHash.$UserSid "`n"$Event.TimeGenerated}
            "-----"
            $Event.TimeGenerated
            $User.Name
            }
        }
        else { # This is remote Computer
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                $Events=Get-EventLog -LogName "System" | where {$_.eventID -eq 7001}
                $Events10=$Events | select -Last $EventsNo

                # Get Local SID <=> User HashTable
                $ComputerName = $env:COMPUTERNAME
                $Computer = [ADSI]"WinNT://$ComputerName,computer"  
                Format-Table Name, Description -autoSize
                $LocalUsers=$Computer.psbase.Children | Where-Object { $_.psbase.schemaclassname -eq 'user' }

                $UsersHash=@{}
                foreach ($LocalUser in $LocalUsers){
                    $ObjUser=New-Object System.Security.Principal.NTAccount($LocalUser.Properties.name.Value)
                    $StrSID=$ObjUser.Translate([System.Security.Principal.SecurityIdentifier])
    
                    $UsersHash.Add($StrSID.Value,$LocalUser.Properties.Name.Value)
                }
                # END Get Local SID <=> User HashTable

                foreach ($Event in $Events10){
                    $UserSid=($Event.ReplacementStrings)[1]

                    Try{$User=Get-ADUser -Identity $UserSid}
                        catch {$null;Write-Host "-----`nLocalUser: " $UsersHash.$UserSid "`n"$Event.TimeGenerated}
                    "-----"
                    $Event.TimeGenerated
                    $User.Name
                }
            }
        }
}
# END Get-MyLogedUsers

# Enter HotfixID => can use KB3, 307, KB3065988,..
Function Get-MyHotFixesInstalled {
<#
.SYNOPSIS
    This Function gets Installed Hotfixes
.NOTES
    There Are No Notes
.EXAMPLE
    Get-MyHotFixesInstalled -HotFixID KB3065988
    Checks If HotFix KB3065988 is Installed on Computer
.EXAMPLE
    Get-MyHotFixesInstalled -HotFixID 306
    Returns All HotFixes Matching string 306
.LINK
    http://jurelab.wordpress.com/
#>
    Param(
    [Parameter(Position=1)]$HotFixID=''
    )
    $Hotfixes=Get-HotFix
    $AtLeastOneFound=$false

    foreach ($Hotfix in $Hotfixes){
        if ($Hotfix.HotFixID -match $HotfixID){
            Write-Host -ForegroundColor Green "It Matches $HotfixID => $($Hotfix.HotfixID)"
            $AtLeastOneFound=$true
        }    

    }
    if (!$AtLeastOneFound) {Write-Host -ForegroundColor Red "Hotfix matching string: $HotfixID => Not found"}      
}

function Convert-JLabNpsLogFileToPsObjects {
    <#
    .Synopsis
       This cmdlet converts NPS, "IAS or RADIUS" log file to Power Shell Objects.
    .DESCRIPTION
       This cmdlet converts NPS, "IAS or RADIUS" log file to Power Shell Objects.
    .EXAMPLE
       Convert-JLabNpsLogFileToPsObjects -Path C:\Users\homer.simpson\Desktop\IN0001.log
       Returns Each line from NPS as PowerShell Object
    .EXAMPLE
        .
        $NPSLog = Convert-JLabNpsLogFileToPsObjects -Path C:\Users\homer.simpson\Desktop\IN0001.log
        
        $NpsEdited  = $NPSLog | Select TimeGenerated,UserName,ClientVendor,AuthenticationType,ReasonCode,PacketType,ClientIPAddress,CalledStationID,CallingStationID,ClientFriendlyName,PolicyName,NASIPAddress,NASIdentifier,ProxyPolicyName,ComputerName,ServiceName
        
        $NpsFiltered = $NpsEdited | ? {$_.ReasonCode -ne 'IAS_SUCCESS'}

        First Line Retrieves log data.
        Second Line Displays Data that we might be interested in.
        Third Line Displays All Records which does not have Reason Code Success
    .INPUTS
        File
    .OUTPUTS
       PSCustomObject
    .NOTES
       Created By: Jure Labrovic
    
       Web Page: https://jurelab.wordpress.com/
    
       Revision:
       Version 1.0   17.08.2017
    #>
        [CmdletBinding()]
    
        param(
            [Parameter(Mandatory=$true,
                        ValueFromPipeline=$true,
                        HelpMessage = 'Path to NPS Log File'
                        )] 
            [string]$Path
            )
    
        BEGIN {
            Write-Verbose "START BEGIN Block"
            Write-Verbose " [BEGIN] Creating Hash tables for known values"

            $PacketType = @{
                1 = 'AccessRequest'
                2 = 'AccessAccept'
                3 = 'AccessReject'
                4 = 'AccountingRequest'
                5 =  'AccountingResponse'
                11 = 'AccessChallenge'
                12 = 'StatusServerExperimental'
                13 = 'StatusClientExperimental'
                255 = 'Reserved' 
                999 = 'null'               
            }

            $AuthenticationType = @{
                1 = 'PAP'
                2 = 'CHAP'
                3 = 'MS-CHAP'
                4 = 'MS-CHAPv2'
                5 = 'EAP'
                7 = 'None'
                8 = 'Custom'
                11 = 'PEAP'
                999 = 'null' 
            }
            
            $ReasonCode = @{
                0 = 'IAS_SUCCESS'
                1 = 'IAS_INTERNAL_ERROR'
                2 = 'IAS_ACCESS_DENIED'
                3 = 'IAS_MALFORMED_REQUEST'
                4 = 'IAS_GLOBAL_CATALOG_UNAVAILABLE'
                5 = 'IAS_DOMAIN_UNAVAILABLE'
                6 = 'IAS_SERVER_UNAVAILABLE'
                7 = 'IAS_NO_SUCH_DOMAIN'
                8 = 'IAS_NO_SUCH_USER'
                16 = 'IAS_AUTH_FAILURE'
                17 = 'IAS_CHANGE_PASSWORD_FAILURE'
                18 = 'IAS_UNSUPPORTED_AUTH_TYPE'
                32 = 'IAS_LOCAL_USERS_ONLY'
                33 = 'IAS_PASSWORD_MUST_CHANGE'
                34 = 'IAS_ACCOUNT_DISABLED'
                35 = 'IAS_ACCOUNT_EXPIRED'
                36 = 'IAS_ACCOUNT_LOCKED_OUT'
                37 = 'IAS_INVALID_LOGON_HOURS'
                38 = 'IAS_ACCOUNT_RESTRICTION'
                48 = 'IAS_NO_POLICY_MATCH'
                64 = 'IAS_DIALIN_LOCKED_OUT'
                65 = 'IAS_DIALIN_DISABLED'
                66 = 'IAS_INVALID_AUTH_TYPE'
                67 = 'IAS_INVALID_CALLING_STATION'
                68 = 'IAS_INVALID_DIALIN_HOURS'
                69 = 'IAS_INVALID_CALLED_STATION'
                70 = 'IAS_INVALID_PORT_TYPE'
                71 = 'IAS_INVALID_RESTRICTION'
                80 = 'IAS_NO_RECORD'
                96 = 'IAS_SESSION_TIMEOUT'
                97 = 'IAS_UNEXPECTED_REQUEST'
                999 = 'null'               
            }

　
　
            Write-Verbose "END BEGIN Block"
        }

        PROCESS {
            Write-Verbose "START PROCESS Block"

            $FileContent = Get-Content -Path $Path
            
            foreach ($Record in $FileContent){
                $OneRecordSplit = $Record -split ","

                if ($OneRecordSplit[4] -eq $null){
                    $OneRecordSplit[4] = 999
                }

                if ($OneRecordSplit[23] -eq ""){
                    $OneRecordSplit[23] = 999
                }
                if ($OneRecordSplit[25] -eq $null){
                    $OneRecordSplit[25] = 999
                }
                
                $DateTime = $OneRecordSplit[2]
                $DateTime += " "
                $DateTime += $OneRecordSplit[3]
                $DateTime =  ([DateTime]$DateTime).ToUniversalTime().tostring("yyyy-MM-ddTHH:mm:ss.fffZ")

                $Props = @{
                    'ComputerName' = $OneRecordSplit[0]
                    'ServiceName' = $OneRecordSplit[1]
                    'RecordDate' = $OneRecordSplit[2]
                    'RecordTime' = $OneRecordSplit[3]
                    'PacketType' = $PacketType.Get_Item([convert]::ToInt32($OneRecordSplit[4]))                    
                    'UserName' = $OneRecordSplit[5]
                    'FullyQualifiedDistinguishedName' = $OneRecordSplit[6]
                    'CalledStationID' = $OneRecordSplit[7]
                    'CallingStationID' = $OneRecordSplit[8]
                    'CallbackNumber' = $OneRecordSplit[9]
                    'FramedIPAddress' = $OneRecordSplit[10]
                    'NASIdentifier' = $OneRecordSplit[11]
                    'NASIPAddress' = $OneRecordSplit[12]
                    'NASPort' = $OneRecordSplit[13]
                    'ClientVendor' = $OneRecordSplit[14]
                    'ClientIPAddress' = $OneRecordSplit[15]
                    'ClientFriendlyName' = $OneRecordSplit[16]
                    'EventTimestamp' = $OneRecordSplit[17]
                    'PortLimit' = $OneRecordSplit[18]
                    'NASPortType' = $OneRecordSplit[19]
                    'ConnectInfo' = $OneRecordSplit[20]
                    'FramedProtocol' = $OneRecordSplit[21]
                    'ServiceType' = $OneRecordSplit[22]
                    'AuthenticationType' = $AuthenticationType.Get_Item([convert]::ToInt32($OneRecordSplit[23]))
                    'PolicyName' = $OneRecordSplit[24]
                    'ReasonCode' = $ReasonCode.Get_Item([convert]::ToInt32($OneRecordSplit[25])) 
                    'Class' = $OneRecordSplit[26]
                    'SessionTimeout' = $OneRecordSplit[27]
                    'IdleTimeout' = $OneRecordSplit[28]
                    'TerminationAction' = $OneRecordSplit[29]
                    'EAPFriendlyName' = $OneRecordSplit[30]
                    'AcctStatusType' = $OneRecordSplit[31]
                    'AcctDelayTime' = $OneRecordSplit[32]
                    'AcctInputOctets' = $OneRecordSplit[33]
                    'AcctOutputOctets' = $OneRecordSplit[34]
                    'AcctSessionId' = $OneRecordSplit[35]
                    'AcctAuthentic' = $OneRecordSplit[36]
                    'AcctSessionTime' = $OneRecordSplit[37]
                    'AcctInputPackets' = $OneRecordSplit[38]
                    'AcctOutputPackets' = $OneRecordSplit[39]
                    'AcctTerminateCause' = $OneRecordSplit[40]
                    'AcctMultiSsnID' = $OneRecordSplit[41]
                    'AcctLinkCount' = $OneRecordSplit[42]
                    'AcctInterimInterval' = $OneRecordSplit[43]
                    'TunnelType' = $OneRecordSplit[44]
                    'TunnelMediumType' = $OneRecordSplit[45]
                    'TunnelClientEndpt' = $OneRecordSplit[46]
                    'TunnelServerEndpt' = $OneRecordSplit[47]
                    'AcctTunnelConn' = $OneRecordSplit[48]
                    'TunnelPvtGroupID' = $OneRecordSplit[49]
                    'TunnelAssignmentID' = $OneRecordSplit[50]
                    'TunnelPreference' = $OneRecordSplit[51]
                    'MSAcctAuthType' = $OneRecordSplit[52]
                    'MSAcctEAPType' = $OneRecordSplit[53]
                    'MSRASVersion' = $OneRecordSplit[54]
                    'MSRASVendor' = $OneRecordSplit[55]
                    'MSCHAPError' = $OneRecordSplit[56]
                    'MSCHAPDomain' = $OneRecordSplit[57]
                    'MSMPPEEncryptionTypes' = $OneRecordSplit[58]
                    'MSMPPEEncryptionPolicy' = $OneRecordSplit[59]
                    'ProxyPolicyName' = $OneRecordSplit[60]
                    'ProviderType' = $OneRecordSplit[61]
                    'ProviderName' = $OneRecordSplit[62]
                    'RemoteServerAddress' = $OneRecordSplit[63]
                    'MSRASClientName' = $OneRecordSplit[64]
                    'MSRASClientVersion' = $OneRecordSplit[65]
                    'TimeGenerated' = $DateTime             
                }
                $Obj = New-Object -TypeName psobject -Property $Props
                Write-Output $Obj
            }

　
            Write-Verbose "END PROCESS Block"

        }

        END {
            Write-Verbose "START END Block"
            Write-Verbose " [END] No Action"
            Write-Verbose "END END Block"
        }
}

function Send-JLabOMSLogAnalyticsHTTPCollectorAPI {
    <#
    .Synopsis
       This cmdlet Send data to Log Analytics with the HTTP Data Collector API
    .DESCRIPTION
       This cmdlet Send data to Log Analytics with the HTTP Data Collector API.
    .EXAMPLE
        $CustomerId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  
        $SharedKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        $LogType = "MyRecordType"
        $TimeStampField = "TimeGenerated"
        $JsonData = $Json

        Send-JLabOMSLogAnalyticsHTTPCollectorAPI -CustomerId $CustomerId -SharedKey $SharedKey -LogType $LogType -TimeStampField $TimeStampField -JsonData $JsonData   

        This Command Sends data to OMS Log Analytics. Data in $JsonData variable must be in Json format.
    .INPUTS
        String
    .OUTPUTS
       HTTP Status Code
    .NOTES
       Created By: Jure Labrovic
       Based on: https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
    
       Web Page: https://jurelab.wordpress.com/
    
       Revision:
       Version 1.0   17.08.2017
    #>
        [CmdletBinding()]
    
        param(
            [string]$CustomerId,
            [string]$SharedKey,
            [string]$LogType,
            [string]$TimeStampField,
            $JsonData
            )
    
        BEGIN {
            Write-Verbose "START BEGIN Block"
            Write-Verbose " [BEGIN] NA"
            Write-Verbose "END BEGIN Block"
        }

        PROCESS {
            Write-Verbose "START PROCESS Block"
            Write-Verbose " [PROCESS] NA"

            # Create the function to create the authorization signature
            Function New-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
            {
                $xHeaders = "x-ms-date:" + $date
                $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

                $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
                $keyBytes = [Convert]::FromBase64String($sharedKey)

                $sha256 = New-Object System.Security.Cryptography.HMACSHA256
                $sha256.Key = $keyBytes
                $calculatedHash = $sha256.ComputeHash($bytesToHash)
                $encodedHash = [Convert]::ToBase64String($calculatedHash)
                $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
                return $authorization
            }

　
            # Create the function to create and post the request
            Function Send-OMSData($customerId, $sharedKey, $body, $logType)
            {
                $method = "POST"
                $contentType = "application/json"
                $resource = "/api/logs"
                $rfc1123date = [DateTime]::UtcNow.ToString("r")
                $contentLength = $body.Length
                $signature = New-Signature `
                    -customerId $customerId `
                    -sharedKey $sharedKey `
                    -date $rfc1123date `
                    -contentLength $contentLength `
                    -fileName $fileName `
                    -method $method `
                    -contentType $contentType `
                    -resource $resource
                $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

                $headers = @{
                    "Authorization" = $signature;
                    "Log-Type" = $logType;
                    "x-ms-date" = $rfc1123date;
                    "time-generated-field" = $TimeStampField;
                }

                $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
                return $response.StatusCode

            }

            # Submit the data to the API endpoint
            Send-OMSData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($JsonData)) -logType $logType

            Write-Verbose "END PROCESS Block"
        }

        END {
            Write-Verbose "START END Block"
            Write-Verbose " [END] NA"
            Write-Verbose "END END Block"
        }
} 
