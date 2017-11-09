<#

.SYNOPSIS
Generate SSL Certificates

.DESCRIPTION
The script will generate SSL Certificates using ACMESharp's DNS-01

.EXAMPLE
New-ACMEDNS01Certificate -Name hostname -ZoneName domain.tld -DnsMasterServer 127.0.0.1 -DnsValidationServer 8.8.8.8 -Staging -CertificateExport

New-ACMEDNS01Certificate for hostname.domain.tld, using 172.0.0.1 as the DNS server and 8.8.8.8 to validate DNS replication.

.NOTES

.LINK
https://github.com/EddyBeaupre/ACMEDNS01Certificate

#>
function New-ACMEDNS01Certificate {
param (
        # DNS record name.
        [Parameter(Mandatory=$true)][string]$Name,
    
        # DNS record zone.
        [Parameter(Mandatory=$true)][string]$ZoneName,

        # Initialize ACMEVault.
        [Parameter(Mandatory=$false)][switch]$Initialize = $false,

        # Use the Staging servers (For tests).
        [Parameter(Mandatory=$false)][switch]$Staging = $false,

        # Force Initialize ACMEVault.
        [Parameter(Mandatory=$false)][switch]$Force = $false,

        # Contact information,
        [Parameter(Mandatory=$false)][string]$ContactEmail = "",

        # Master DNS Server,
        [Parameter(Mandatory=$false)][string]$DnsMasterServer = "127.0.0.1",

        # Name server for DNS Validation,
        [Parameter(Mandatory=$false)][string]$DnsValidationServer = "127.0.0.1",

        # Export Certificates.
        [Parameter(Mandatory=$false)][switch]$CertificateExport,

        # OutPath for Certificates.
        [Parameter(Mandatory=$false)][string]$CertificatePath,

        # Force overwrite of certificates.
        [Parameter(Mandatory=$false)][switch]$CertificateOverwrite = $false,

        # Silent.
        [Parameter(Mandatory=$false)][switch]$Silent = $false
    )
    Import-Module DnsServer
    Import-Module ACMESharp
    
    filter TimeStamp {"$(Get-Date -UFormat "%Y/%m/%d-%H:%m:%S"): $_"}
    
    function GetTimeStamp {
        param(
            # NoNewline.
            [Parameter(Mandatory=$false)][switch]$Numeric = $false
        )
    
        if($Numeric) {
            return Get-Date -UFormat "%Y%m%d%H%m%S"
        } else {
            return Get-Date -UFormat "%Y/%m/%d-%H:%m:%S"
        }
    }
    
    function WriteLog {
        param(
            # Message.
            [Parameter(Mandatory=$False, Position=1)][string]$Message = " ",
            
            # Color.
            [Parameter(Mandatory=$false)][string]$Color = "White",
            
            # NoNewline.
            [Parameter(Mandatory=$false)][switch]$NoNewline = $false,
            
            # TimeStamp.
            [Parameter(Mandatory=$False)][switch]$TimeStamp = $False
            )
    
        if(!$Silent) {
            if($TimeStamp) {
                Write-Host "$(GetTimeStamp): " -ForegroundColor DarkGreen -NoNewline
            }
            Write-Host "$Message" -ForegroundColor $Color -NoNewline:$NoNewline
        }
    }
    
    function Main-ACMECertificate {
        WriteLog "ACMEVault " -NoNewline 
    
        $ACMEVault = Get-ACMEVault
    
        if ((!$ACMEVault) -or $Initialize) {
            try {
                WriteLog "(" -NoNewline 
                if($Initialize) {
                    WriteLog "Forced, " -NoNewLine -Color Cyan 
                }
            
                $BaseService = "LetsEncrypt"
                if($Staging) {
                    $BaseService = "LetsEncrypt-STAGING"
                }
                WriteLog "Base Service " -NoNewLine 
                WriteLog "$BaseService" -NoNewLine -Color Cyan 
                WriteLog ") : " -NoNewLine 
    
                Initialize-ACMEVault -Force:$Initialize -BaseService $BaseService
            
                WriteLog "initialized." -Color Green 
    
                $ACMEVault = Get-ACMEVault
            } catch {
                WriteLog "failed initialization" -Color Red 
            Exit
            }
        } else {
            WriteLog "(Base Service " -NoNewLine 
            WriteLog "$($ACMEVault.BaseService)" -NoNewline -Color Cyan 
            WriteLog ") : " -NoNewLine 
            WriteLog "Available." -Color Green 
        }
        
        if([string]::IsNullOrWhiteSpace($ACMEVault.Registrations)) {
            try {
                if([string]::IsNullOrWhiteSpace($ContactEmail) -or !(ValidEmailAddress "$ContactEmail")) {
                    $ContactEmail = Read-Host "Please provide a valid contact email address"
                }
    
                WriteLog "Registering contact " -NoNewline 
                WriteLog "$ContactEmail" -NoNewline -Color Cyan 
                WriteLog " : " -NoNewline 
                $ACMERegistration = New-ACMERegistration -Contacts "mailto:$ContactEmail" -AcceptTos
                WriteLog "success." -Color Green 
            } catch {
                WriteLog "fail." -Color Red 
                Exit
            }
        }
    
        ExportAcmeCertificate $(ValidateAcmeCertificate $(ValidateAcmeIdentifier))
    }
    
    function FindAcmeIdentifier {
        param(
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Dns
        )
    
        WriteLog "Searching existing ACME identifier for " -NoNewline 
        WriteLog "$Dns" -Color Cyan -NoNewline 
        WriteLog " : " -NoNewline 
        forEach($identifier in $(Get-ACMEIdentifier)) {
            if(!$($identifier.Status -eq "invalid")) {
                if($identifier.Dns -eq "$Dns") {
                    WriteLog "$($identifier.Alias)." -Color Green 
                    return $identifier
                }
            }
        }
    
        WriteLog "None." -Color DarkGreen 
    
        WriteLog "Creating new ACME identifier for " -NoNewline 
        WriteLog "$Dns" -Color Cyan -NoNewline 
        WriteLog " : " -NoNewline 
        $identifier = New-ACMEIdentifier -Dns $Dns -Alias "$($Dns.replace('.','-'))-$(GetTimeStamp -Numeric)"
        forEach($identifier in $(Get-ACMEIdentifier)) {
            if(!$($identifier.Status -eq "invalid")) {
                if($identifier.Dns -eq "$Dns") {
                    WriteLog "$($identifier.Alias)." -Color Green 
                    return $identifier
                }
            }
        } else {
            WriteLog "Error" -Color Red 
            Exit
        }
    }
    
    function ValidateAcmeIdentifier {
        WriteLog
        $ACMEIdentifier = $(FindAcmeIdentifier "$Name.$ZoneName")
    
        if($($ACMEIdentifier.Status) -eq "valid") {
            return $ACMEIdentifier
        } else {
            WriteLog "ACME Identifier : " -NoNewline
            WriteLog "$($ACMEIdentifier.Alias)." -Color Cyan -NoNewline
            WriteLog " state : " -NoNewline
            WriteLog "$($ACMEIdentifier.Status)." -Color Green
        
            WriteLog "Complete ACMEChallenge for " -NoNewline
            WriteLog "$($ACMEIdentifier.Alias)" -Color Cyan -NoNewline
            WriteLog " state : " -NoNewline
        
            $ResponseFile = [System.IO.Path]::GetTempFileName()
            Remove-Item -Path "$ResponseFile"
            $AcmeChallenge = Complete-ACMEChallenge -IdentifierRef "$($ACMEIdentifier.Alias)" -ChallengeType dns-01 -Handler manual -HandlerParameters @{"WriteOutPath" = "$ResponseFile"; "OutputJson" = $true}
            
            if($AcmeChallenge.Status -eq "pending") {
                WriteLog "$($AcmeChallenge.Status)." -Color Green
            } else {
                WriteLog "$($AcmeChallenge.Status)" -Color Red
                Exit
            }
            
            if(!$(Test-Path "$ResponseFile")) {
                WriteLog "Response file not found." -Color Red
                Exit
            }
    
            $ResponseData = (Get-Content "$ResponseFile")  | ConvertFrom-Json
            Remove-Item -Path "$ResponseFile"
        
            $RecordName = $ResponseData.DnsDetails.RRName.Replace(".$ZoneName", "")
            $RecordData = $ResponseData.DnsDetails.RRValue
            if(!(CreateDnsTxtRecord "$RecordName" "$ZoneName" "$RecordData" $DnsMasterServer)) {
                Exit
            }
    
            WaitForTxtReplication "$RecordName" "$ZoneName" "$RecordData" $DnsValidationServer -Sleep 30
    
            $SubmitACMEChallenge = Submit-ACMEChallenge -IdentifierRef $ACMEIdentifier.Alias -ChallengeType dns-01
    
            WaitForACMEIdentifier $ACMEIdentifier.Alias -Sleep 10
    
            return $(FindAcmeIdentifier $Dns)
        }
    }
    
    function FindAcmeCertificate {
        param(
            # IdentifierRef.
            [Parameter(Mandatory=$true, Position=1)][string]$IdentifierRef
        )
    
        WriteLog "Searching existing ACME certificate for " -NoNewline 
        WriteLog "$IdentifierRef" -Color Cyan -NoNewline 
        WriteLog " : " -NoNewline 
    
        $certificate = $(Get-ACMECertificate -CertificateRef "$IdentifierRef-cert") 2> $null
    
        if(!$($certificate -eq $null)) {
            WriteLog "$($certificate.Alias)." -Color Green 
            return $certificate
        }
        
        WriteLog "Not found." -Color Green 
    
        WriteLog "Creating a new certificate for " -NoNewline
        WriteLog "$IdentifierRef-cert" -Color Cyan -NoNewline
        WriteLog " : " -NoNewline
    
        $certificate = New-ACMECertificate -Generate -IdentifierRef $IdentifierRef -AlternativeIdentifierRefs @("$IdentifierRef") -Alias "$IdentifierRef-cert"
        $certificate = $(Get-ACMECertificate -CertificateRef "$IdentifierRef-cert") 2> $null
    
        if(!$($certificate -eq $null)) {
            WriteLog "Success." -Color Green 
            return $certificate
        }
    
        WriteLog "Error" -Color Red 
        Exit
    }
    
    function ValidateAcmeCertificate {
        param(
            # ACMEIdentifier.
            [Parameter(Mandatory=$true, Position=1)][object]$ACMEIdentifier
        )
    
        WriteLog
        if($ACMEIdentifier.Status -eq "valid") {
            WriteLog "ACME Identifier : " -NoNewline
            WriteLog "$($ACMEIdentifier.Alias)." -Color Cyan -NoNewline
            WriteLog " state : " -NoNewline
            WriteLog "$($ACMEIdentifier.Status)." -Color Green
    
            $ACMECertificate = FindAcmeCertificate "$($ACMEIdentifier.Alias)"
                    
            if([string]::IsNullOrWhiteSpace($ACMECertificate.IssuerSerialNumber)) {
                WriteLog "Submitting certificate request for : " -NoNewline
                WriteLog "$($ACMECertificate.Alias)" -Color Cyan -NoNewline
                WriteLog " : " -NoNewline
                $ACMECertificate = Submit-ACMECertificate -CertificateRef "$($ACMECertificate.Alias)"
                WriteLog "Done." -Color Green
                $ACMECertificate = WaitForACMECertificate -CertificateRef "$($ACMECertificate.Alias)" -Sleep 10
            }
    
            WriteLog "Fetching signed certificates : " -NoNewline
            WriteLog "$($ACMECertificate.Alias)" -Color Cyan -NoNewline
            WriteLog " : " -NoNewline
            $ACMECertificate = Get-ACMECertificate -CertificateRef "$($ACMECertificate.Alias)"
            WriteLog "Done." -Color Green
            return $ACMECertificate
        } else {
            WriteLog "ACME Identifier : " -NoNewline
            WriteLog "$ACMEIdentifier.Alias." -Color Cyan -NoNewline
            WriteLog " state : " -NoNewline
            WriteLog "$($ACMEIdentifier.Status)" -Color Red
            return $null
        }
    }
    
    function ShowFileDetail {
        param(
            # File.
            [Parameter(Mandatory=$true, Position=1)][string]$File = "",
    
            # Path.
            [Parameter(Mandatory=$true, Position=2)][string]$Path = "",
    
            # FilePath.
            [Parameter(Mandatory=$true, Position=3)][string]$Description = "",
    
            # FilePath.
            [Parameter(Mandatory=$true, Position=4)][string]$Type = ""
        )
    
        $Data = Get-FileHash "$(Join-Path $Path $File)"
    
        WriteLog "$Description (" -NoNewline
        WriteLog "$Type" -Color Cyan -NoNewline
        WriteLog ") : " -NoNewLine
        WriteLog "$($Data.Path)" -Color Green
    
        WriteLog "$Description checksum (" -NoNewline
        WriteLog "$($Data.Algorithm)" -Color Cyan -NoNewline
        WriteLog ") : " -NoNewLine
        WriteLog "$($Data.Hash)" -Color Green
    }
    
    function ExportAcmeCertificate {
        param(
            # ACMEIdentifier.
            [Parameter(Mandatory=$true, Position=1)][object]$ACMECertificate
        )
    
        if($ACMECertificate -and $CertificateExport) {
            WriteLog 
            WriteLog "Certificate Path : " -NoNewline
            if([string]::IsNullOrWhiteSpace($CertificatePath)) {
                $ACMEVaultProfile = $(Get-ACMEVaultProfile)
                $CertificatePath = Join-Path "$($ACMEVaultProfile.VaultParameters.RootPath)" "certificates"
                if(!$(Test-Path $CertificatePath)) {
                    New-Item "$CertificatePath" -type directory 2>&1 > $null
                }
                WriteLog "$CertificatePath." -Color Green
            } else {
                if(!(Test-Path $CertificatePath)) {
                    WriteLog "Path " -Color Cyan -NoNewline
                    WriteLog "$CertificatePath" -Color Red -NoNewline
                    WriteLog " does not exists. Aborting." -Color Cyan
                    Exit
                }
            }
        
            $ACMECertificate = Get-ACMECertificate -CertificateRef "$($ACMECertificate.Alias)" -ExportKeyPEM $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-key.pem") -ExportCsrPEM $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-csr.pem") -ExportCertificatePEM $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias).pem") -ExportCertificateDER $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias).der") -ExportIssuerPEM $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-issuer.pem") -ExportIssuerDER $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-issuer.der") -ExportPkcs12 $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias).pkcs12") -Overwrite
            Get-Content $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-key.pem") | Out-File $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-combined.pem")
            Get-Content $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias).pem") | Out-File -Append $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-combined.pem")
            Get-Content $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-issuer.pem") | Out-File -Append $(Join-Path "$CertificatePath" "$($ACMECertificate.Alias)-combined.pem")
    
            ShowFileDetail "$($ACMECertificate.Alias)-issuer.pem" "$CertificatePath" "CA's intermediary certificate" "PEM encoded"
            ShowFileDetail "$($ACMECertificate.Alias)-issuer.der" "$CertificatePath" "CA's intermediary certificate" "DER encoded"
            ShowFileDetail "$($ACMECertificate.Alias)-csr.pem" "$CertificatePath" "Certificate Signing Reques" "PEM encoded"
            ShowFileDetail "$($ACMECertificate.Alias).pem" "$CertificatePath" "Certificate" "PEM encoded"
            ShowFileDetail "$($ACMECertificate.Alias).der" "$CertificatePath" "Certificate" "DER encoded"
            ShowFileDetail "$($ACMECertificate.Alias)-combined.pem" "$CertificatePath" "Combined Key, Certificate and CA's intermediary certificate" "PEM encoded"
            ShowFileDetail "$($ACMECertificate.Alias).pkcs12" "$CertificatePath" "Certificate" "PKCS#12 encoded"
            ShowFileDetail "$($ACMECertificate.Alias)-key.pem" "$CertificatePath" "Certificate Key" "PEM encoded"
        }
    }
    
    function ValidEmailAddress {
        param
        (
            # EmailAddress.
            [Parameter(Mandatory=$true, Position=1)][string]$EmailAddress
        )
    
        WriteLog "Validating email address " -NoNewline
        WriteLog "$EmailAddress" -Color Cyan -NoNewline
        WriteLog " : " -NoNewline
    
        if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
            WriteLog "invalid." -Color Red
            return $false
        }
    
        $Domain = $EmailAddress.Split('@')
        if(!($Domain.Count -eq 2) -or ([string]::IsNullOrWhiteSpace($Domain[1]))) {
            WriteLog "invalid." -Color Red
            return $false
        }
    
        if(!(DnsRecordExists $Domain[1] Mx -Silent)) {
            WriteLog "invalid." -Color Red
            return $false
        }
            
        Try {
            New-Object System.Net.Mail.MailAddress($EmailAddress) 2>&1 > $null
        } Catch {
            WriteLog "invalid." -Color Red
            return $false
        }

        WriteLog "valid." -Color Green
        return $true
    }
    
    function DnsZoneExists {
        param(
            # Zone
            [Parameter(Mandatory=$true, Position=1)][string]$Zone
            )
        
        try {
            WriteLog "Searching for zone " -NoNewline 
            WriteLog "$Zone" -NoNewline -Color Cyan 
            WriteLog " : " -NoNewline 
            if(Get-DnsServerZone -Name "$Zone" -ErrorAction SilentlyContinue) {
                WriteLog "Found." -Color Green 
                return $true
            } else {
                WriteLog "Not found." -Color DarkGreen 
                return $false
            }
        } catch {
            WriteLog "Error" -Color Red 
            return $False
        }
    
    }
    
    function DnsRecordExists {
        param(
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Name,
                
            # Type
            [Parameter(Mandatory=$true, Position=2)][string]$Type,
    
            # Type
            [Parameter(Mandatory=$False, Position=3)][string]$Server
            )
        try {
            WriteLog "Searching for dns record " -NoNewline 
            WriteLog "$Name" -NoNewline -Color Cyan 
            WriteLog " of type " -NoNewline 
            WriteLog "$type" -NoNewLine -Color Cyan 
            if(!([string]::IsNullOrWhiteSpace($Server))) {
                WriteLog " in server " -NoNewline 
                WriteLog "$Server" -NoNewline -Color Cyan 
            }
            WriteLog " : " -NoNewline 
            
            if([string]::IsNullOrWhiteSpace($Server)) {
                $Data = Resolve-DnsName -Name "$Name" -Type $Type -DnsOnly -ErrorAction SilentlyContinue
            } else {
                $Data = Resolve-DnsName -Name "$Name" -Type $Type -DnsOnly -Server $Server -ErrorAction SilentlyContinue
            }
            
            if($Data) {
                forEach($Record in $Data) {
                    if($Record.Type -eq $Type) {
                        WriteLog "Found." -Color Green 
                    return $true
                    }
                }
                WriteLog "Not found." -Color DarkGreen 
                return $false
            }
            WriteLog "Error" -Color Red 
            Exit
        } catch {
            WriteLog "Error" -Color Red 
            return $False
        }
    }
    
    function GetDnsTxtRecord {
        param(
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Name,
    
            # Zone
            [Parameter(Mandatory=$true, Position=2)][string]$Zone,
    
            # Type
            [Parameter(Mandatory=$False, Position=4)][string]$Server = "127.0.0.1"
            )
        try {
            if(DnsZoneExists "$Zone" ) {
                WriteLog "Fetching dns record " -NoNewline 
                WriteLog "$Name.$Zone" -NoNewline -Color Cyan 
                WriteLog " of type " -NoNewline 
                WriteLog "TXT" -NoNewLine -Color Cyan 
                WriteLog " in server " -NoNewline 
                WriteLog "$Server" -NoNewline -Color Cyan 
                WriteLog " : " -NoNewline 
                $Values = New-Object System.Collections.ArrayList
                $Data = Resolve-DnsName -Name "$Name.$Zone" -Type TXT -DnsOnly -Server $Server -ErrorAction SilentlyContinue
                if($Data) {
                    forEach($Record in $Data) {
                        if($Record.Type -eq "TXT") {
                            $Values.Add($Record.Strings) 2>&1 > $null
                        }
                    }
                }
                WriteLog "$($Values.Count)." -NoNewline -Color Green 
                WriteLog " records found" 
                return $Values
            }
            Exit
        } catch {
            WriteLog "Error" -Color Red 
            return $null
        }
    }
    
    function RemoveDnsRecord {
        param(
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Name,
    
            # Zone
            [Parameter(Mandatory=$true, Position=2)][string]$Zone,
    
            # Type
            [Parameter(Mandatory=$true, Position=3)][string]$Type,
            
            # Server
            [Parameter(Mandatory=$false, Position=4)][string]$Server = "127.0.0.1"
            )
        try {
            if(DnsZoneExists "$Zone") {
                if(DnsRecordExists "$Name.$Zone" "$Type" "$Server") {
                    WriteLog "Removing DNS Record " -NoNewline 
                    WriteLog "$Name.$Zone" -NoNewline -Color Cyan 
                    WriteLog " of type " -NoNewline 
                    WriteLog "$type" -NoNewLine -Color Cyan 
                    WriteLog " in server " -NoNewline 
                    WriteLog "$server" -NoNewline -Color Cyan 
                    WriteLog " : " -NoNewline 
                    Remove-DnsServerResourceRecord -ComputerName $Server -Name $Name -ZoneName $Zone -RRType $Type -Force -ErrorAction Stop
                    WriteLog "Ok." -Color Green 
                    return $true
                }
            }
            return $false
        } catch {
            WriteLog "Error" -Color Red 
            return $false
        }
    }
    
    function CreateDnsTxtRecord {
        param(
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Name,
                
            # Zone
            [Parameter(Mandatory=$true, Position=2)][string]$Zone,
    
            # Data
            [Parameter(Mandatory=$true, Position=3)][string]$Data,
            
            # Server
            [Parameter(Mandatory=$false, Position=4)][string]$Server = "127.0.0.1"
            )
        try {
            if(RemoveDnsRecord $Name $Zone TXT $Server) {
                WriteLog "Creating Txt DNS Record " -NoNewline 
                WriteLog "$Name.$Zone" -NoNewline -Color Cyan 
                WriteLog " with data " -NoNewline 
                WriteLog $Data -NoNewLine -Color Cyan 
                WriteLog " in server " -NoNewline 
                WriteLog "$server" -NoNewline -Color Cyan 
                WriteLog " : " -NoNewline 
                Add-DnsServerResourceRecord -ComputerName $Server -Txt -Name $Name -ZoneName $Zone -DescriptiveText "$Data"
                WriteLog "Ok." -Color Green 
            }
            return $true
        } catch {
            WriteLog "Error" -Color Red 
            return $false
        }
    }
    
    function WaitForTxtReplication {
        param (
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$Name,
    
            # Zone
            [Parameter(Mandatory=$true, Position=2)][string]$Zone,
    
            # Data
            [Parameter(Mandatory=$true, Position=3)][string]$Data,
            
            # Server
            [Parameter(Mandatory=$false, Position=4)][string]$Server = "127.0.0.1",
    
            # Server
            [Parameter(Mandatory=$false)][int]$Sleep = 10
            )
    
        $StartTime = $(Get-Date)
        WriteLog "Waiting for DNS Replication of " -NoNewline
        WriteLog "TXT" -NoNewline -Color Cyan
        WriteLog " record " -NoNewline
        WriteLog "$Name.$Zone" -NoNewline -Color Cyan
        WriteLog " on server " -NoNewline
        WriteLog "$Server" -NoNewline -Color Cyan
        WriteLog " : " -NoNewline
        $Sleep = ($Sleep * 1000)
        Do {
            forEach($Value in GetDnsTxtRecord "$Name" "$Zone" $Server -Silent) {
                if($Value -eq $Data) {
                    WriteLog "Ok." -Color Green -NoNewline
                    $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                    WriteLog " Replication took " -NoNewline
                    WriteLog "$([math]::Truncate($TimeSpan.TotalSeconds))" -NoNewline -Color Cyan
                    WriteLog " seconds."
                    return
                }
            }
        
            for($i = 0; $i -lt 100; $i++) {
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                Write-Progress -Id 1 -Activity "Waiting for DNS Replication" -Status "$([math]::Truncate($TimeSpan.TotalSeconds)) seconds elapsed. Next check in $([math]::Truncate(($Sleep - ($i * ($Sleep / 100))) / 1000)) seconds..." -PercentComplete $i
                Start-Sleep -Milliseconds $($Sleep / 100)
            }
        } While($true)
    }

    function WaitForACMEIdentifier {
        param (
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$IdentifierRef,
    
            # Sleep
            [Parameter(Mandatory=$false)][int]$Sleep = 10
        )
    
        $StartTime = $(Get-Date)
        WriteLog "Waiting for ACMEIdentifier update of " -NoNewline
        WriteLog "$IdentifierRef" -NoNewline -Color Cyan
        WriteLog " : " -NoNewline
        $Sleep = ($Sleep * 1000)
        
        Do {
            $ACMEIdentifier = Update-ACMEIdentifier -IdentifierRef $IdentifierRef
            if($ACMEIdentifier.Status -eq "valid") {
                WriteLog "Ok." -Color Green -NoNewline
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                WriteLog " Update took " -NoNewline
                WriteLog "$([math]::Truncate($TimeSpan.TotalSeconds))" -NoNewline -Color Cyan
                WriteLog " seconds."
                return;
            }
            if($ACMEIdentifier.Status -eq "invalid") {
                WriteLog "invalid" -Color Red -NoNewline
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                WriteLog " Update took " -NoNewline
                WriteLog "$([math]::Truncate($TimeSpan.TotalSeconds))" -NoNewline -Color Cyan
                WriteLog " seconds."
                Exit;
            }
            for($i = 0; $i -lt 100; $i++) {
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                Write-Progress -Id 1 -Activity "Waiting for ACMEIdentifier update" -Status "$([math]::Truncate($TimeSpan.TotalSeconds)) seconds elapsed. Next check in $([math]::Truncate(($Sleep - ($i * ($Sleep / 100))) / 1000)) seconds..." -PercentComplete $i
                Start-Sleep -Milliseconds $($Sleep / 100)
            }
        } While($true)
    }
    
    function WaitForACMECertificate {
        param (
            # Dns.
            [Parameter(Mandatory=$true, Position=1)][string]$CertificateRef,
                
            # Sleep
            [Parameter(Mandatory=$false)][int]$Sleep = 10
        )
    
        $StartTime = $(Get-Date)
        WriteLog "Waiting for ACMECertificate update of " -NoNewline
        WriteLog "$CertificateRef" -NoNewline -Color Cyan
        WriteLog " : " -NoNewline
        $Sleep = ($Sleep * 1000)
        
        Do {
            $ACMECertificate = Update-ACMECertificate -CertificateRef $CertificateRef
            if(![string]::IsNullOrWhiteSpace($ACMECertificate.IssuerSerialNumber)) {
                WriteLog "Ok." -Color Green -NoNewline
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                WriteLog " Update took " -NoNewline
                WriteLog "$([math]::Truncate($TimeSpan.TotalSeconds))" -NoNewline -Color Cyan
                WriteLog " seconds."
                return $ACMECertificate;
            }
            for($i = 0; $i -lt 100; $i++) {
                $TimeSpan = New-TimeSpan $StartTime $(Get-Date)
                Write-Progress -Id 1 -Activity "Waiting for ACMECertificate update" -Status "$([math]::Truncate($TimeSpan.TotalSeconds)) seconds elapsed. Next check in $([math]::Truncate(($Sleep - ($i * ($Sleep / 100))) / 1000)) seconds..." -PercentComplete $i
                Start-Sleep -Milliseconds $($Sleep / 100)
            }
        } While($true)
    }

    Main-ACMECertificate
}
