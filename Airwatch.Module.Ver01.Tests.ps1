$here = split-path -parent $MyInvocation.MyCommand.path
$module = 'Airwatch'

Describe "$module Module Tests" {

    Context 'Module Setup' {
        It "has the root module $module.psm1" {
            "$here\$module.psm1" |
            should exist
        }
        <#
        It "has the manifest file of $module.psd1" {
            "$here\$module.psd1" |
            should exist
        #>
        It "$module is valid PowerShell Code" {
            $psFile = get-content -path "$here\$module.psm1" -ErrorAction Stop
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize($psfile, [ref]$errors)
            $errors.Count | Should be 0
        }
    } # End Context 'Module Setup'

    Get-Module -Name $module | remove-Module -Force
    Import-Module $module
    Context "Function tests" {
        $function = 'Set-AWUserAttribute'
        It "Result of function $function" {
            $result = $false
            $reply = $null
            $parms = @{'userID'='96145';
                'Server'='https://awc.gdfsuez-es.com';
                'Attribute'='email';
                'value'='a1@company.com';
                'CertificateSubjectName'='CN=4610:APIMGMT-IPRUK'
            }
            $reply = Set-AWUserAttribute @parms
            if ($reply[0].values[0] -like '*CMSURL*'){$result = $true} 
            $result | should be $true
        }
        $function = 'Get-AWUserID'
        It "Result of function $function" {
            $result = $false
            $reply = $null
            $parms = @{'Server'='https://awc.gdfsuez-es.com';
                'Attribute'='username';
                'Value'='aaa1';
                'CertificateSubjectName'='CN=4610:APIMGMT-IPRUK'
            }
            $reply = Get-AWUserID @parms
            if ($reply.users.id.value -eq 96145){$result = $true} 
            $result | should be $true
        }
        $function = 'Get-AWUsers'
        It "Result of function $function" {
            $result = $true
            $reply = $null
            $parms = @{'Server'='https://awc.gdfsuez-es.com';
                'OrganisationalGroup'=1048;
                'CertificateSubjectName'='CN=4610:APIMGMT-IPRUK'
            }
            $reply = Get-AWUsers @parms
            if (($reply.users.username) -eq $null) {$result = $false} 
            $result | should be $false
        }

        $function = 'Get-AWDevices'
        It "Result of function $function" {
            $result = $true
            $reply = $null
            $parms = @{'Server'='https://awc.gdfsuez-es.com';
                'OrganisationalGroup'=1048;
                'CertificateSubjectName'='CN=4610:APIMGMT-IPRUK'
            }
            $reply = Get-AWDevices @parms
            if (($reply.users.username) -eq $null) {$result = $false} 
            $result | should be $false
        }

        $function = 'Get-AWOrganisationalGroups'
        It "Result of function $function" {
            $result = $true
            $reply = $null
            $parms = @{'Server'='https://awc.gdfsuez-es.com';
                'CertificateSubjectName'='CN=4610:APIMGMT-IPRUK'
            }
            $reply = Get-AWOrganisationalGroups @parms
            if (($reply.users.username) -eq $null) {$result = $false} 
            $result | should be $false
        }


    } #End Context 'Function tests'
}
         
