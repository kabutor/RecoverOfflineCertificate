 
$pfX = Get-ChildItem *.pfx
$pwd = ConvertTo-SecureString -String "12345" -AsPlainText -Force

ForEach ($cert in $pfx){
    
    Import-PfxCertificate -Password $pwd -FilePath $cert -CertStoreLocation Cert:\CurrentUser\My -Exportable
    }