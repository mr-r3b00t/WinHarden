new-item "hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
new-item "hklm:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
new-item "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Explorer"
new-item "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Installer"
new-item "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa"
new-item "hklm:\\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
new-item "hklm:\\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
new-item "hklm:\\SYSTEM\CurrentControlSet\Services\mrxsmb10"
new-item "hklm:\\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate"
new-item "hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
new-item "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
new-item "hklm:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
new-item "hklm:\\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"
new-item "hklm:\\Software\Policies\Microsoft\Edge"
new-item "hklm:\\Software\Policies\Microsoft\Internet Explorer\Main"

New-ItemPropertyProperty -Path "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Installer" -name AlwaysInstallElevated -Value 0 -Force

New-ItemPropertyProperty "hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoDriveTypeAutoRun -Value 255 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name fAllowToGetHelp -Value 0 -Force

New-ItemProperty "hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name NoAutorun -Value 0 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Explorer" -name NoAutoplayfornonVolume -Value 1 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Installer" -name AlwaysInstallElevated -Value 0 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -name DisableIPSourceRouting -Value 2 -Force
New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -name DisableNotifications -Value 1 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Services\mrxsmb10" -name Start -Value 4 -Force

New-ItemProperty "hklm:\\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate" -name enableautomaticupdates -Value 1 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name LmCompatibilityLevel -Value 5 -Force

New-ItemProperty "hklm:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -Value 0 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 0 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name SecurityLayer -Value 2 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force

New-ItemProperty "hklm:\\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate" -name enableautomaticupdates -Value 1 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 1 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name SecurityLayer -Value 2 -Force

New-ItemProperty "hklm:\\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name DisableBehaviorMonitoring -Value 1 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -name NC_ShowSharedAccessUI -Value 0 -Force

New-ItemProperty "hklm:\\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -name UserAuthentication -Value 1 -Force

New-ItemProperty "hklm:\\SYSTEM\CurrentControlSet\Control\Lsa" -name RestrictAnonymous -Value 1 -Force
#Remove Windows Mail App
Get-AppxPackage Microsoft.windowscommunicationsapps -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

Set-MpPreference -MAPSReporting Advanced -Force
Set-MpPreference -SubmitSamplesConsent SendAllSamples -Force
Set-MpPreference -PUAProtection Enabled -Force

Set-MpPreference -EnableNetworkProtection Enabled -Force

Set-MpPreference -EnableDnsSinkhole $true -Force

#Set-MpPreference -SignatureFallbackOrder {InternalDefinitionUpdateServer|MicrosoftUpdateServer|MMPC}

#Set-MpPreference -SignatureDefinitionUpdateFileSharesSource {\\UNC SHARE PATH|\\UNC SHARE PATH}

Set-MpPreference -SignatureScheduleDay Everyday -Force

Set-MpPreference -SignatureScheduleTime 720 -Force

Set-MpPreference -AllowNetworkProtectionOnWinServer $true -Force

Set-MpPreference -CheckForSignaturesBeforeRunningScan $true -Force

New-ItemProperty "hklm:\\Software\Policies\Microsoft\Edge" -name HideFirstRunExperience -Value 1 -Force

New-ItemProperty "hklm:\\Software\Policies\Microsoft\Internet Explorer\Main" -Name DisableFirstRunCustomize -Value 1 -Force
