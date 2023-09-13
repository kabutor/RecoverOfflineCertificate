param(
    [Parameter(Mandatory = $false)]
    [String]$Password = "12345"
    )
    
$passwd = ConvertTo-SecureString -String $Password -Force -AsPlainText

$certPath = "Cert:\CurrentUser\My"

# first IF ? If it's a certificate seconf IF ? it's from the FNMT (spanish cert authority) remove if you don't need it
$cert = Get-ChildItem $certPath -Recurse | ? { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |  ? {$_.Issuer -eq "CN=AC FNMT Usuarios, OU=Ceres, O=FNMT-RCM, C=ES" }


Foreach ( $cer in $cert ) {
    write-host $cer.SubjectName.Name
    $certSubjectName = $cer.SubjectName.Name

    if ($cer.SubjectName.Name -match "CN=(?<commonName>[^,]*)") {
            
        $certCommonName = $Matches['commonName']
        $certThumbprint = $cer.Thumbprint

        
        # export it to the parent directory remove (".." + ) if not
        $exportFile = "..\" + "$certCommonName ($certThumbprint).pfx"


        $cer | Export-PfxCertificate -FilePath  $exportFile -Password $passwd -ChainOption BuildChain
        }
    }
