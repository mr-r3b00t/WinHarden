new-Item -Path "Hklm:\\SOFTWARE\Policies\Microsoft\Windows\Installer" -name AlwaysInstallElevated -Value 0 -Force

new-Item "Hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -Value 255 -Force

new-Item "Hklm:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name fAllowToGetHelp -Value 0 -Force

new-Item "Hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoAutorun -Value 0 -Force

new-Item "Hklm:\\SOFTWARE\Policies\Microsoft\Windows\Explorer" -name NoAutoplayfornonVolume -Value 1 -Force

new-Item "Hklm:\\SOFTWARE\Policies\Microsoft\Windows\Installer" -name AlwaysInstallElevated -Value 0 -Force

new-Item "Hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force

new-Item "Hklm:\\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -name DisableIPSourceRouting -Value 2 -Force
New-Item "Hklm:\\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -name DisableNotifications -Value 1 -Force

New-Item "Hklm:\\SYSTEM\CurrentControlSet\Services\mrxsmb10" -name Start -Value 4

New-Item "Hklm:\\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate" -name enableautomaticupdates -Value 1 -Force

New-Item "Hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name LmCompatibilityLevel -Value 5 -Force

New-item "Hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -Value 0 -Force

New-item "Hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 0 -Force

New-item "Hklm:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name SecurityLayer -Value 2 -Force

New-item "Hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force

New-Item "Hklm:\\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate" -name enableautomaticupdates -Value 1 -Force

New-item "Hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 1 -Force

New-Item "hklm:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name SecurityLayer -Value 2 -Force

New-item "hklm:\\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableBehaviorMonitoring -Value 1 -Force

New-Item "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 0 -Force

New-Item "hklm:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name UserAuthentication -Value 1 -Force

New-item "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force
#Remove Windows Mail App
Get-AppxPackage Microsoft.windowscommunicationsapps -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

Set-MpPreference -MAPSReporting Advanced -Force
Set-MpPreference -SubmitSamplesConsent SendAllSamples -Force
Set-MpPreference -PUAProtection Enabled -Force

Set-MpPreference -EnableNetworkProtection Enabled -Force

Set-MpPreference -EnableDnsSinkhole $true -Force

Set-MpPreference -SignatureFallbackOrder {InternalDefinitionUpdateServer|MicrosoftUpdateServer|MMPC}

#Set-MpPreference -SignatureDefinitionUpdateFileSharesSource {\\UNC SHARE PATH|\\UNC SHARE PATH}

Set-MpPreference -SignatureScheduleDay Everyday -Force

Set-MpPreference -SignatureScheduleTime 720

Set-MpPreference -AllowNetworkProtectionOnWinServer $true -Force

Set-MpPreference -CheckForSignaturesBeforeRunningScan $true -Force
