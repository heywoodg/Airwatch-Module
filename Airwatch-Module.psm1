function Get-CMSURLAuthorizationHeader {
        [CmdletBinding()]
        [OutputType([string])]
        Param
        (
            # Input the URL to be
            [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    Position=0)]
            [uri]$URL,

            # Specify the Certificate to be used 
            [Parameter(Mandatory=$true,
                        ValueFromPipeline)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $Certificate
        )

        Begin {            
        }
        Process {
        Try { 
                #Get the Absolute Path of the URL encoded in UTF8
                $bytes = [System.Text.Encoding]::UTF8.GetBytes(($Url.AbsolutePath))

                #Open Memory Stream passing the encoded bytes
                $MemStream = New-Object -TypeName System.Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$bytes) -ErrorAction Stop

                #Create the Signed CMS Object providing the ContentInfo (from Above) and True specifying that this is for a detached signature
                $SignedCMS = New-Object -TypeName System.Security.Cryptography.Pkcs.SignedCms -ArgumentList $MemStream,$true -ErrorAction Stop

                #Create an instance of the CMSigner class - this class object provide signing functionality
                $CMSigner = New-Object -TypeName System.Security.Cryptography.Pkcs.CmsSigner -ArgumentList $Certificate -Property @{IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly} -ErrorAction Stop

                #Add the current time as one of the signing attribute
                $null = $CMSigner.SignedAttributes.Add((New-Object -TypeName System.Security.Cryptography.Pkcs.Pkcs9SigningTime))

                #Compute the Signature
                $SignedCMS.ComputeSignature($CMSigner)

                #As per the documentation the authorization header needs to be in the format 'CMSURL `1 <Signed Content>'
                #One can change this value as per the format the Vendor's REST API documentation wants.
                $CMSHeader = '{0}{1}{2}' -f 'CMSURL','`1 ',$([System.Convert]::ToBase64String(($SignedCMS.Encode())))
                Write-Output -InputObject $CMSHeader
            }
            Catch { 
                Write-host $_.exception -ErrorAction stop
            }
        }
        End {
        }
    } #end function
function Format-HTTPHeader {
        Param ([string]$URL,[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    $Text  = @{
                'Authorization' = "$(Get-CMSURLAuthorizationHeader -URL $URL -Certificate $Certificate)";
                'aw-tenant-code' = "FNS2TF4z1GO/cVFhauwXr+MmpC9tZ7igY86JQZq7eL0=";
            }
            
    Return $Text
    } #end function
function Set-AWUserAttribute {
    <#
    .SYNOPSIS
        This function will set an attribute for an Airwatch user. 
    .DESCRIPTION
        The common attributes that can be set for an Airwatch user are:
            Password (not used for a directory user, only a basic user)
            Firstname
            Lastname
            Email
            ContactNumber
            DisplayName
            MobileNumber
            MessageType
            Group
            OrganizationGroupUuid
            Role
        
        All of the listed attributes are strings.

        The command requires a local certificate for authentication against the Airwatch platform. 
    .EXAMPLE
        Set-AirwatchUserAttribute -userID "96145" -server "https://awc.cn999.awmdm.com" -attribute "email" -value "a1@company.com" -CertificateSubjectName "CN=4610:APIMGMT-COMP"
    .EXAMPLE
        Set-AirwatchUserAttribute -userID "7315" -server "https://awc.cn999.awmdm.com" -attribute "DisplayName" -value "John Smith" -CertificateSubjectName "CN=4610:APIMGMT-COMP"
    #>

        Param ([string]$UserID,[string]$server,[string]$attribute,[string]$value,[String]$CertificateSubjectName,[string]$proxyuse)
    
        Begin {
            #Build string for API connection
            $APIURL = "/API/system/users/$UserID/update"
            [uri]$URI = $server+$APIURL
            $reply = $null
            $Certificate = Get-ChildItem -Path Cert:\CurrentUser\my | Where-Object Subject -eq $CertificateSubjectName
            $headers = Format-HTTPHeader $URI $Certificate
            $headers
            
        }#end Begin
        Process {   

            Try {
                $json = "{
                    ""$Attribute"":""$Value""
                }"
                If (!$ProxyUse) {
                    $reply = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Post  -Headers $headers -ContentType "application/json" -Body $json
                }
                else {
                    $proxy = [system.Net.webrequest]::GetSystemWebProxy()
                    $proxy.Credentials = [System.Net.Credentialcache]::DefaultNetworkCredentials
                    $proxyuri = $proxy.GetProxy($server)
                    $reply = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Post  -Headers $headers -ContentType "application/json" -ProxyUseDefaultCredentials -Proxy $proxyuri -Body $json
                }

            }#end Try
            Catch {
            Write-Error "$($_.Exception.Message) - Line Number $($_.InvocationInfo.ScriptLineNumber)"
            }#end Catch
        }#end process
        End {}
    } #end function
function Get-AWUserID {
    <#
        .SYNOPSIS
            This function will return the Airwatch ID for users where attributes match the value provided.
        .DESCRIPTION
            To find a single user, use a unique field such as username. 
            Some attributes that can be used to search include:
                Firstname
                Lastname
                Email
                locationgroupID
                Role
                Username
        .EXAMPLE
                Get-AWUserID -Server "https://awc.cn999.awmdm.com" -Attribute "username" -Value "aaa1" -certificateSubjectName "CN=4610:APIMGMT-COMP"
    #>

    Param ([string]$server,[string]$attribute,[string]$value,[String]$CertificateSubjectName,[string]$proxyuse)
    
    Begin {
        #Build string for API connection
        $APIURL = "/API/system/users/search?$attribute=$value"
        [uri]$URI = $server+$APIURL
        $reply = $null
        $Certificate = Get-ChildItem -Path Cert:\CurrentUser\my | Where-Object Subject -eq $CertificateSubjectName
        $headers = Format-HTTPHeader $URI $Certificate

    }#end Begin
    Process {   
        Try {
            If (!$ProxyUse) {
                $reply = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" 
            }
            else {
                $proxy = [system.Net.webrequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.Credentialcache]::DefaultNetworkCredentials
                $proxyuri = $proxy.GetProxy($server)
                $reply = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" -ProxyUseDefaultCredentials -Proxy $proxyuri -Body $json
            }

        }#end Try
        Catch {
        Write-Error "$($_.Exception.Message) - Line Number $($_.InvocationInfo.ScriptLineNumber)"
        }#end Catch
        Return $reply
    }#end process
    End {}
    } #end function    
function Get-AWUsers {
    <#
        .SYNOPSIS
            This function will return all Airwatch users from a specified organisational group..
        .DESCRIPTION

        .EXAMPLE
                Get-AWUsers -Server "https://awc.cn999.awmdm.com"  -OrganisationalGroup 1048 -certificateSubjectName "CN=4610:APIMGMT-COMP"
    #>

    Param ([string]$server,[int]$OrganisationalGroup,[String]$CertificateSubjectName,[string]$proxyuse)
    
    Begin {
        #Build string for API connection
        $APIURL = "/API/system/users/search?locationgroupid=$OrganisationalGroup&pagesize=20000"
        [uri]$URI = $server+$APIURL
        $reply = $null
        $Certificate = Get-ChildItem -Path Cert:\CurrentUser\my | Where-Object Subject -eq $CertificateSubjectName
        $headers = Format-HTTPHeader $URI $Certificate

    }#end Begin
    Process {   
        Try {
            If (!$ProxyUse) {
                $users = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" 
                $reply = $users.users
            }
            else {
                $proxy = [system.Net.webrequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.Credentialcache]::DefaultNetworkCredentials
                $proxyuri = $proxy.GetProxy($server)
                $users = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" -ProxyUseDefaultCredentials -Proxy $proxyuri -Body $json
                $reply = $users.users
            }

        }#end Try
        Catch {
        Write-Error "$($_.Exception.Message) - Line Number $($_.InvocationInfo.ScriptLineNumber)"
        }#end Catch
        Return $reply
    }#end process
    End {}
    } #end function    
function Get-AWDevices {
    <#
        .SYNOPSIS
            This function will return all Airwatch devices for a specified organisational group.
        .DESCRIPTION

        .EXAMPLE
                Get-AWDevices -Server "https://awc.cn999.awmdm.com"  -OrganisationalGroup 1048 -certificateSubjectName "CN=4610:APIMGMT-COMP"
    #>

    Param ([string]$server,[int]$OrganisationalGroup,[String]$CertificateSubjectName,[string]$proxyuse)
    
    Begin {
        #Build string for API connection
        $APIURL = "/API/mdm/devices/extensivesearch?organizationgroupid=$OrganisationalGroup&pagesize=20000"
        [uri]$URI = $server+$APIURL
        $reply = $null
        $Certificate = Get-ChildItem -Path Cert:\CurrentUser\my | Where-Object Subject -eq $CertificateSubjectName
        $headers = Format-HTTPHeader $URI $Certificate

    }#end Begin
    Process {   
        Try {
            If (!$ProxyUse) {
                $devices = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" 
                $reply = $devices.devices
            }
            else {
                $proxy = [system.Net.webrequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.Credentialcache]::DefaultNetworkCredentials
                $proxyuri = $proxy.GetProxy($server)
                $devices = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" -ProxyUseDefaultCredentials -Proxy $proxyuri -Body $json
                $reply = $devices.devices
            }

        }#end Try
        Catch {
        Write-Error "$($_.Exception.Message) - Line Number $($_.InvocationInfo.ScriptLineNumber)"
        }#end Catch
        Return $reply
    }#end process
    End {}
    } #end function    
function Get-AWOrganisationalGroups {
    <#
        .SYNOPSIS
            This function will return a list of details about Airwatch organisational groups.
        .DESCRIPTION

        .EXAMPLE
                Get-AWDevices -Server "https://awc.cn999.awmdm.com" -certificateSubjectName "CN=4610:APIMGMT-COMP"
    #>

    Param ([string]$server,[String]$CertificateSubjectName,[string]$proxyuse)
    
    Begin {
        #Build string for API connection
        $APIURL = "/api/system/groups/search"
        [uri]$URI = $server+$APIURL
        $reply = $null
        $Certificate = Get-ChildItem -Path Cert:\CurrentUser\my | Where-Object Subject -eq $CertificateSubjectName
        $headers = Format-HTTPHeader $URI $Certificate

    }#end Begin
    Process {   
        Try {
            If (!$ProxyUse) {
                $OGs = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" 
                $reply = $OGs.LocationGroups
                
            }
            else {
                $proxy = [system.Net.webrequest]::GetSystemWebProxy()
                $proxy.Credentials = [System.Net.Credentialcache]::DefaultNetworkCredentials
                $proxyuri = $proxy.GetProxy($server)
                $OGs = Invoke-restmethod -uri $URI -DisableKeepAlive -Method Get -Headers $headers -ContentType "application/json" -ProxyUseDefaultCredentials -Proxy $proxyuri -Body $json
                $reply = $OGs.LocationGroups
            }

        }#end Try
        Catch {
        Write-Error "$($_.Exception.Message) - Line Number $($_.InvocationInfo.ScriptLineNumber)"
        }#end Catch
        Return $reply
    }#end process
    End {}
    } #end function

Export-ModuleMember -function set-AWUserAttribute
Export-ModuleMember -function Get-AWUserID
Export-ModuleMember -function Get-AWDevices
Export-ModuleMember -function Get-AWOrganisationalGroups


    