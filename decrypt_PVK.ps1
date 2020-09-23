#Modify this for your user
#you can see the value for SID inside the RSA folder, there is a folder with the S-X-X... format
#pass is the password to log in the user 

$sid= "S-1-5-21-1364892398-2168578162-1322903635-1002"
$pass = "YOUR_PASS"

Get-ChildItem (".\RSA\" + $sid + "\") | 
Foreach-Object {
   

	#Write-Host $_.FullName
    $first_step = "mimikatz.exe `"dpapi::capi /in:" + $_.FullName + "`" `"exit`" |findstr guidMasterKey"
    
	$salida = cmd /c $first_step
    $oneline = ($salida -split '\n')[0]
    
    $master_key = [regex]::Matches($oneline, '{([^/)]+)}')|ForEach-Object { $_.Groups[1].Value }
    write-host $master_key

    #decrypt masterkey with pass
    $second_step = "mimikatz.exe `"dpapi::masterkey /in:.\Protect\" + $sid + "\" + $master_key + " /password:"+ $pass + " `"  `"exit`"|findstr sha1"
    $salida = cmd /c $second_step
    
    $sha1_key = ($salida -split ' ')[3]


    #decrypt private key
    $third_step = "mimikatz.exe `"dpapi::capi /in:" + $_.FullName + " /masterkey:" + $sha1_key + "`" `"exit`" "

    $salida = cmd /c $third_step
    write-host $salida
    
}
