function Start-Pomodoro {
    <#
        .SYNOPSIS
        Powershell based Pomodoro Timer with 3 short breaks and 1 long break before resetting
        
        .DESCRIPTION
        Powershell based Pomodoro Timer with 3 short breaks and 1 long break before resetting

        .PARAMETER Pomodoro
        Specifies the length of time for working

        .PARAMETER ShortBreak
        Specifies the length of time for a short break
        
        .PARAMETER LongBreak
        Specifies the length of time for a long break
        
        .PARAMETER NumOfShortBreaks
        Specifies the number of short breaks for using long break time

        .PARAMETER DisableNotifications
        Disables Windows Toast Notifications

        .EXAMPLE
        PS> Start-Pomodoro -Pomodoro 20 -ShortBreak 3 -LongBreak 10 -NumOfShortBreaks 3 -DisableNotifications
        Set work time to 20 minutes, short breaks at 3 minutes, a long break at 10 minutes, and disabled notifications

        .EXAMPLE
        PS> Start-Pomodoro -DisableNotifications
        Uses default timings and disabled notifications

        .LINK
        https://github.com/GlennToms/Powershell-Pomodoro-Timer
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [Int]
        $Pomodoro = 20,
        [Parameter()]
        [Int]
        $ShortBreak = 5,
        [Parameter()]
        [Int]
        $LongBreak = 15,
        [Parameter()]
        [Int]
        $NumOfShortBreaks = 3,
        [Parameter()]
        [switch]
        $DisableNotifications
    )
    $IsBreak = $false
    $Minutes = 0
    $SessionCount = 0
    $Skip = $false
    $StopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $TimeSpan = $null


    $RotationTotal = ($Pomodoro * ($NumOfShortBreaks + 1)) + ($ShortBreak * $NumOfShortBreaks) + $LongBreak
    Write-Host "One full rotation is $('{0:hh\:mm\:ss}' -f (New-TimeSpan -Minutes $RotationTotal))" -ForegroundColor DarkCyan

    while ($true) {
        Write-Host ""
        if ($IsBreak) {
            $SessionCount += 1
            if ($SessionCount -le $NumOfShortBreaks) {
                $Minutes = $ShortBreak
                Write-Host -ForegroundColor Cyan "Press 'Enter' to start short break #$SessionCount for $("{0:mm\:ss}" -f (New-TimeSpan -Minutes $Minutes)) minutes"
            }
            else {
                $Minutes = $LongBreak
                Write-Host -ForegroundColor Green "Press 'Enter' to start long break #$SessionCount for $("{0:mm\:ss}" -f (New-TimeSpan -Minutes $Minutes)) minutes"
                $SessionCount = 0
            }
        }
        else {
            $Minutes = $Pomodoro
            Write-Host -ForegroundColor Magenta "Press 'Enter' to start deep work for $("{0:mm\:ss}" -f (New-TimeSpan -Minutes $Minutes)) minutes"
        }
        Wait-KeyPress -Key 'Enter'
        
        
        $IsBreak = !$IsBreak
        $TimeSpan = New-TimeSpan -Minutes $Minutes

        Write-Host "`nCONTROLS"
        Write-Host "SpaceBar: Pause"
        Write-Host "Enter:    Play"
        Write-Host "R:        Restart Timer"
        Write-Host "S:        Skip Timer"

        $StopWatch.Start()
        
        do {
            Write-Host -ForegroundColor Yellow "`r$("{0:mm\:ss}" -f ($Timespan - $StopWatch.Elapsed))" -NoNewline
            
            if ([Console]::KeyAvailable) {
                switch ([Console]::ReadKey($true).Key) {
                    'Enter' { $StopWatch.Start() }
                    'SpaceBar' { $StopWatch.Stop() }
                    'R' { $StopWatch.Restart() }
                    'S' { $Skip = $true }
                    Default {  }
                }
            }
        }
        until ($StopWatch.Elapsed -ge $TimeSpan -or $Skip)
        $StopWatch.Reset()
        $Skip = $false
        
        if ($DisableNotifications -eq $false) {
            if ($IsBreak) {
                New-ToastNotification -ApplicationTitle 'PomodoroTimer' -ToastBody "Deep work ended"
            }
            else {
                New-ToastNotification -ApplicationTitle 'PomodoroTimer' -ToastBody "Break ended"
            }
        }
    }
}

function Wait-KeyPress {
    param (
        $Key
    )
    $KeyNotPressed = $true
    $dots = ""
    while ($KeyNotPressed) {
        Write-Host "`rWaiting   " -NoNewline -ForegroundColor Red
        for ($i = 0; $i -lt 4; $i++) {
            Write-Host "`rWaiting$dots" -NoNewline -ForegroundColor Red
            for ($k = 0; $k -lt 10; $k++) {
                Start-Sleep -Milliseconds 100
                if ([Console]::KeyAvailable) {
                    if ([Console]::ReadKey($true).Key -eq $Key) {
                        $KeyNotPressed = $false
                        break
                    }
                }
                if ($KeyNotPressed -eq $false) {
                    break
                }
            }
            if ($KeyNotPressed -eq $false) {
                break
            }
            $dots += "."
        }
        $dots = ""
    }
}

function New-ToastNotification {
    <#
        .SYNOPSIS
        Creates custom Windows Toast notifications with titles and text
        
        .DESCRIPTION
        Creates custom Windows Toast notifications with titles and text

        .PARAMETER ApplicationTitle
        Specifies the title of the application that created the Toast notification

        .PARAMETER ToastTitle
        Specifies the title of the Toast notification 

        .PARAMETER ToastBody
        Specifies the text of the Toast notification 
        
        .EXAMPLE
        PS> New-ToastNotification -ApplicationTitle "PomodoroTimer" -ToastBody "Deep work ended"
        
        .EXAMPLE
        PS> "This is body text" | New-ToastNotification

        .LINK
        https://github.com/GlennToms/PowerShell-New-ToastNotification
        
        .LINK
        https://den.dev/blog/powershell-windows-notification/

        .LINK
        https://github.com/GlennToms/Powershell-Pomodoro-Timer

        .NOTES
        Updated for use with Pomodoro Timer
    #>
    [cmdletbinding()]
    Param (
        [string]
        $ApplicationTitle = "Powershell",
        [string]
        $ToastTitle,
        [string]
        [parameter(ValueFromPipeline, Mandatory = $true)]
        $ToastBody
    )

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)

    $RawXml = [xml] $Template.GetXml()
    ($RawXml.toast.visual.binding.text | Where-Object { $_.id -eq "1" }).AppendChild($RawXml.CreateTextNode($ToastTitle)) > $null
    ($RawXml.toast.visual.binding.text | Where-Object { $_.id -eq "2" }).AppendChild($RawXml.CreateTextNode($ToastBody)) > $null

    $SerializedXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $SerializedXml.LoadXml($RawXml.OuterXml)

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)
    $Toast.Tag = $ApplicationTitle
    $Toast.Group = $ApplicationTitle
    $Toast.ExpirationTime = [DateTimeOffset]::Now.AddMinutes(1)

    $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($ApplicationTitle)
    $Notifier.Show($Toast);
}

Export-ModuleMember Start-Pomodoro

# Start-Pomodoro