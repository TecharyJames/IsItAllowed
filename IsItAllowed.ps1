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

function get-MajorOSEdition {

    $os = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    if ($os.CurrentBuildNumber -lt 22000)
        {

            $osEdition = "10"

        }
    else {
        $osEdition = "11"
    }

    $osEdition

}

function get-supportedwinver10 {

    # Create an empty array to store the versions
    $versions = @()

    # Use Invoke-WebRequest to get the HTML content of the Wikipedia page
    $ProgressPreference = "silentlycontinue"
    $response = Invoke-WebRequest -Uri "https://en.wikipedia.org/wiki/Windows_10_version_history"

    # Use the ParsedHtml property to access the DOM elements
    $doc = $response.ParsedHtml

    # Find the table element with the class name "wikitable"
    $table = $doc.getElementsByClassName("wikitable") | Select-Object -First 1

    # Loop through the table rows, skipping the first one (header row)
    foreach ($row in $table.rows | Select-Object -Skip 1) {
        # Get the cells of the current row
        $cells = $row.cells

        # Get the text content of the first cell (version)
        $version = $cells[0].innerText

        # Get the background color of the fourth cell (GAC)
        $gacColor = $cells[5].style.backgroundColor

        # If the GAC color is green, add the version to the array
        if ($gacColor -eq "#d4f4b4") {
            $versions += $version.trim()
        }
    }

    # Output the array of versions
    $versions

}

function get-supportedwinver11 {

    # Create an empty array to store the versions
    $proversions = @()
    $entversions = @()

    # Use Invoke-WebRequest to get the HTML content of the Wikipedia page
    $ProgressPreference = "silentlycontinue"
    $response = Invoke-WebRequest -Uri "https://en.wikipedia.org/wiki/Windows_11_version_history"

    # Use the ParsedHtml property to access the DOM elements
    $doc = $response.ParsedHtml

    # Find the table element with the class name "wikitable"
    $table = $doc.getElementsByClassName("wikitable") | Select-Object -First 1

    # Loop through the table rows, skipping the first one (header row)
    foreach ($row in $table.rows | Select-Object -Skip 1) {
        # Get the cells of the current row
        $cells = $row.cells

        # Get the text content of the first cell (version)
        $version = $cells[0].innerText

        # Get the background color of the fourth cell (GAC)
        $gacColor = $cells[5].style.backgroundColor

        # If the GAC color is green, add the version to the array
        if ($gacColor -eq "#d4f4b4") {
            $proversions += $version.trim()
        }

        # Get the background color of the fifth cell (GAC)
        $gacColor = $cells[6].style.backgroundColor

        # If the GAC color is green, add the version to the array
        if ($gacColor -eq "#d4f4b4") {
            $entversions += $version.trim()
            }
    }

    # Output the array of versions in pscustomobject
    $supportedVersions = [pscustomobject]@{

        Pro = $proversions
        Enterprise = $entversions

    }

    $supportedVersions

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

    $Script:version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion

    if ($SupportedWinVer -contains $version) {$script:WindowsVersionSoftFail = "False"}

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
    write-host -ForegroundColor Yellow "`nWindows is out of date. Please update to any of the following versions:"
    $SupportedWinVer
}


}

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

print-TecharyLogo

$MajorOSEdition = get-majorOSEdition

$script:SupportedWinVer = @()

if ($MajorOSEdition -eq 11)
{

    $editionID = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').editionID

    $script:SupportedWinVer = (get-supportedwinver11).$editionID

}
else {
$script:SupportedWinVer = get-supportedwinver10
}

$av = @(Get-AntiVirusProduct).name

get-firewallstatus

get-windowsVersion

get-UserAdminStatus

get-VulnerablePorts

Get-AllowStatus

write-host "`nCurrent AV programs are:"
$av
