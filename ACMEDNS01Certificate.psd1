@{
    ModuleVersion = '1.0'
    GUID = 'd687cae0-a9c0-4290-bc2f-e91b13a0b2e1'
    Author = 'Eddy Beaupré'
    CompanyName = 'Eddy Beaupré'
    Copyright = '(c) 2017 Eddy Beaupré. Tous droits réservés.'
    Description = 'Generate SSL Certificates using ACMESharp DNS-01'
    RequiredModules = @("ACMESharp")
    FunctionsToExport = @("New-ACMEDNS01Certificate")
    CmdletsToExport = @()
    VariablesToExport = '*'
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @("ACMESharp", "DNS-01")
            ProjectUri = 'https://github.com/EddyBeaupre/ACMEDNS01Certificate'
            ExternalModuleDependencies= @("DnsServer")
        }
    }
    HelpInfoURI = 'https://github.com/EddyBeaupre/ACMEDNS01Certificate'
}

