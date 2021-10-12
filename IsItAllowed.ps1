function run-isItAllowed {

#####################################
## Author: James Tarran // Techary ##
#####################################

    function print-TecharyLogo {
        
        $logo = "
        _______        _                      
       |__   __|      | |                     
          | | ___  ___| |__   __ _ _ __ _   _ 
          | |/ _ \/ __| '_ \ / _`` | '__| | | |
          | |  __/ (__| | | | (_| | |  | |_| |
          |_|\___|\___|_| |_|\__,_|_|   \__, |
                                         __/ |
                                        |___/ 
   "
    
    write-host -ForegroundColor Green $logo
    
    }
    
    function Get-AntiVirusProduct {
        [CmdletBinding()]
        param (
        [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('name')]
        $computername=$env:computername
    
    
        )
    
        #$AntivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters # -ErrorVariable myError -ErrorAction 'SilentlyContinue' # did not work            
         $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername
    
        $Script:ret = @()
        foreach($AntiVirusProduct in $AntiVirusProducts){
            #Switch to determine the status of antivirus definitions and real-time protection.
            #The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
            switch ($AntiVirusProduct.productState) {
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
                }
    
            #Create hash-table for each computer
            $ht = @{}
            $ht.Computername = $computername
            $ht.Name = $AntiVirusProduct.displayName
            $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
            $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
            $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
            $ht.'Definition Status' = $defstatus
            $ht.'Real-time Protection Status' = $rtstatus
    
    
            #Create a new object for each computer
            $Script:ret += New-Object -TypeName PSObject -Property $ht 
        }
        Return $ret
    }
    
    function get-firewallstatus{
    
        $FirewallStatus = 0
        $SysFirewallReg1 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
        If ($SysFirewallReg1 -eq 1) {
        $FirewallStatus = 1
        }
    
        $SysFirewallReg2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
        If ($SysFirewallReg2 -eq 1) {
        $FirewallStatus = ($FirewallStatus + 1)
        }
    
        $SysFirewallReg3 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name EnableFirewall | Select-Object -ExpandProperty EnableFirewall
        If ($SysFirewallReg3 -eq 1) {
        $FirewallStatus = ($FirewallStatus + 1)
        }
    
        If ($FirewallStatus -eq 3) {$script:FirewallHardfail = "False"}
        ELSE {$script:FirewallHardfail = "True"}
    
    }
    
    function get-windowsVersion {
    
        $Script:version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    
        if ($Script:version -ge $SupportedWinVer) {$script:WindowsVersionSoftFail = "False"}
        
        else {
            $script:WindowsVersionSoftFail = "True"
        }
    }
    
    function get-UserAdminStatus{
    
        $adminMembers = (Get-LocalGroupMember -group administrators).name

        if ($adminMembers -like "*$env:username*") {$script:AdminStatusHardfail = "True"}
        
        else {$script:AdminStatusHardfail = "False"}
            
    }
    
    function get-VulnerablePorts {
    
        $HardFailPorts = @('21','22','80','23','25','53','110','443','3389')
    
        $OpenPorts = @(get-nettcpconnection -state listen).localPort
    
        $Script:HardFailPortsOpen = (compare-object -ReferenceObject $hardfailports -DifferenceObject $openports -IncludeEqual -ExcludeDifferent).inputobject
    
        if($null -eq $Script:HardFailPortsOpen) {$script:VulnerablePortsHardFail = "False"}
        else{$script:VulnerablePortsHardFail = "True"}
    
    }
    
    function Get-AllowStatus {
    
        if ($script:FirewallHardfail-eq "True" -or $script:AdminStatusHardfail -eq "True" -or $script:VulnerablePortsHardFail -eq "True") {
            write-host -ForegroundColor red "Device is not compliant. Device has failed on the following:"
        
    
            if ($script:FirewallHardfail -eq "True") {
                write-host -ForegroundColor Red "`nAt least one public/private/domain firewall is disabled. Enable the firewall, OR confirm there is an antivirus product that is controlling the firewall instead."
            }
    
            if ($script:AdminStatusHardfail -eq "True") {
                write-host -ForegroundColor red "`nCurrent user account is a local administrator. Remove the account from the administrators group, or create a new local account with no administrator permissions"
            }
    
            if($script:VulnerablePortsHardFail -eq "True") {
                write-host -ForegroundColor Red "`nPort(s) $Script:HardFailPortsOpen open. These are easily exploitable and need to be closed."
            }
    
        }

        else {
            
            write-host -ForegroundColor green "Device is compliant."
        }
    
        if ($script:WindowsVersionSoftFail -eq "True") {
            write-host -ForegroundColor Yellow "`nWindows is out of date. Please update to at least $SupportedWinVer"
        }
    

        
    
    }
    
    # -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    $SupportedWinVer = 2004
    
    print-TecharyLogo
    
    $av = @(Get-AntiVirusProduct).name
    
    get-firewallstatus
    
    get-windowsVersion
    
    get-UserAdminStatus
    
    get-VulnerablePorts
    
    Get-AllowStatus
    
    write-host "`nCurrent AV programs are: $av"
    write-host " "

}