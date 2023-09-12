param(
    [Parameter(Mandatory = $false)]
    [String]$Password = "12345"
    )
#### Usage ####
# .\Export-ClientCertificates.ps1 -Thumbprints "array","of","thumbprints","and","subject","common","names" -Password "PrivateKeyPassword"
####
    
$passwd = ConvertTo-SecureString -String $Password -Force -AsPlainText

$certPath = "Cert:\CurrentUser\My"



write-host $certprint
$cert = Get-ChildItem $certPath -Recurse | ? { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |  ? {$_.Issuer -eq "CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES" }

write-host "ths"

Foreach ( $cer in $cert ) {
    write-host $cer.SubjectName.Name
    $certSubjectName = $cer.SubjectName.Name
    #Write-Host "Found Subject Name: $certSubjectName"

    if ($cer.SubjectName.Name -match "CN=(?<commonName>[^,]*)") {
            
        $certCommonName = $Matches['commonName']
        #Write-Host "Found Common Name: $certCommonName"
            
        $certThumbprint = $cer.Thumbprint
        #Write-Host "Found Thumbprint: $certThumbprint"
            
        $exportFile = "$certCommonName ($certThumbprint).pfx"
        #Write-Host "Writing to $exportFile"

        $cer | Export-PfxCertificate -FilePath $exportFile -Password $passwd -ChainOption BuildChain
        }
    }
