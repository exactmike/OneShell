    Function New-OneShellTimer
    {
        
    <#
      .Synopsis
      Creates a new countdown timer which can show progress and/or issue voice reports of remaining time.
      .Description
      Creates a new PowerShell Countdown Timer which can show progress using a progress bar and can issue voice reports of progress according to the Units and Frequency specified.
      Additionally, as the timer counts down, alternative voice report units and frequency may be specified using the altReport parameter.
      .Parameter Units
      Specify the countdown timer length units.  Valid values are Seconds, Minuts, Hours, or Days.
      .Parameter Length
      Specify the length of the countdown timer.  Default units for length are Minutes.  Otherwise length uses the Units specified with the Units Parameter.
      .Parameter Voice
      Turns on voice reporting of countdown progress according to the specified units and frequency.
      .Parameter ShowProgress
      Shows countdown progress with a progress bar.  The progress bar updates approximately once per second.
      .Parameter Frequency
      Specifies the frequency of voice reports of countdown progress in Units
      .Parameter altReport
      Allows specification of additional voice report patterns as a countdown timer progresses.  Accepts an array of hashtable objects which must contain Keys for Units, Frequency, and Countdownpoint (in Units specified in the hashtable)
  #>
    [cmdletbinding()]
    param(
        [parameter()]
        [validateset('Seconds', 'Minutes', 'Hours', 'Days')]
        $units = 'Minutes'
        ,
        [parameter()]
        $length
        ,
        [switch]$voice
        ,
        [switch]$showprogress
        ,
        [double]$Frequency = 1
        ,
        [hashtable[]]$altReport #Units,Frequency,CountdownPoint
        ,
        [int]$delay
    )

    switch ($units)
    {
        'Seconds' {$timespan = [timespan]::FromSeconds($length)}
        'Minutes' {$timespan = [timespan]::FromMinutes($length)}
        'Hours' {$timespan = [timespan]::FromHours($length)}
        'Days' {$timespan = [timespan]::FromDays($length)}
    }

    if ($voice)
    {
        Add-Type -AssemblyName System.speech
        $speak = New-Object -TypeName System.Speech.Synthesis.SpeechSynthesizer
        $speak.Rate = 3
        $speak.Volume = 100
    }

    if ($altReport.Count -ge 1)
    {
        $vrts = @()
        foreach ($vr in $altReport)
        {
            $vrt = @{}
            switch ($vr.Units)
            {
                'Seconds'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency
                    $vrt.frequency = $vr.frequency
                    $vrt.units = $vr.Units
                    $vrt.countdownpoint = $vr.countdownpoint
                }
                'Minutes'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency * 60
                    $vrt.frequency = $vrt.seconds * $vr.frequency
                    $vrt.units = $vr.units
                    $vrt.countdownpoint = $vr.countdownpoint * 60
                }
                'Hours'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency * 60 * 60
                    $vrt.frequency = $vrt.seconds * $vr.frequency
                    $vrt.units = $vr.units
                    $vrt.countdownpoint = $vr.countdownpoint * 60 * 60
                }
                'Days'
                {
                    #convert frequency units to seconds
                    $vrt.seconds = $vr.frequency * 24 * 60 * 60
                    $vrt.frequency = $vrt.seconds * $vr.frequency
                    $vrt.units = $vr.units
                    $vrt.countdownpoint = $vr.countdownpoint * 60 * 60 * 24
                }
            }
            $ovrt = $vrt | Convert-HashTableToObject
            $vrts += $ovrt
        }
        $vrts = @($vrts | sort-object -Property countdownpoint -Descending)
    }
    if ($delay) {New-Timer -units Seconds -length $delay -voice -showprogress -Frequency 1}
    $starttime = Get-Date
    $endtime = $starttime.AddTicks($timespan.Ticks)

    if ($showprogress)
    {
        $writeprogressparams = @{
            Activity         = "Starting Timer for $length $units"
            Status           = 'Running'
            PercentComplete  = 0
            CurrentOperation = 'Starting'
            SecondsRemaining = $timespan.TotalSeconds
        }
        Write-Progress @writeprogressparams
    }

    do
    {
        if ($nextsecond)
        {
            $nextsecond = $nextsecond.AddSeconds(1)
        }
        else {$nextsecond = $starttime.AddSeconds(1)}
        $currenttime = Get-Date
        [timespan]$remaining = $endtime - $currenttime
        $secondsremaining = if ($remaining.TotalSeconds -gt 0) {$remaining.TotalSeconds.toUint64($null)} else {0}
        if ($showprogress)
        {
            $writeprogressparams.CurrentOperation = 'Countdown'
            $writeprogressparams.SecondsRemaining = $secondsremaining
            $writeprogressparams.PercentComplete = ($secondsremaining / $timespan.TotalSeconds) * 100
            $writeprogressparams.Activity = "Running Timer for $length $units"
            Write-Progress @writeprogressparams
        }

        switch ($Units)
        {
            'Seconds'
            {
                $seconds = $Frequency
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    if ($Frequency -lt 3)
                    {
                        $speak.Rate = 5
                        $speak.SpeakAsync("$secondsremaining") > $null
                    }
                    else
                    {
                        $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                    }
                }
            }
            'Minutes'
            {
                $seconds = $frequency * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                    if ($minutesremaining -ge 1)
                    {
                        $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                    }
                    else
                    {
                        if ($secondsremaining -ge 1)
                        {
                            $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                        }
                    }
                }
            }
            'Hours'
            {
                $seconds = $frequency * 60 * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $hoursremaining = $remaining.TotalHours.tostring("#.##")
                    if ($hoursremaining -ge 1)
                    {
                        $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                    }
                    else
                    {
                        $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                        if ($minutesremaining -ge 1)
                        {
                            $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                        }
                        else
                        {
                            if ($secondsremaining -ge 1)
                            {
                                $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                            }
                        }
                    }
                }
            }
            'Days'
            {
                $seconds = $frequency * 24 * 60 * 60
                if ($voice -and ($secondsremaining % $seconds -eq 0))
                {
                    $daysremaining = $remaining.TotalDays.tostring("#.##")
                    if ($daysremaining -ge 1)
                    {
                        $speak.SpeakAsync("$daysremaining days remaining") > $null
                    }
                    else
                    {
                        $hoursremaining = $remaining.TotalHours.tostring("#.##")
                        if ($hoursremaining -ge 1)
                        {
                            $speak.SpeakAsync("$hoursremaining hours remaining") > $null
                        }
                        else
                        {
                            $minutesremaining = $remaining.TotalMinutes.tostring("#.##")
                            if ($minutesremaining -ge 1)
                            {
                                $speak.SpeakAsync("$minutesremaining minutes remaining") > $null
                            }
                            else
                            {
                                if ($secondsremaining -ge 1)
                                {
                                    $speak.SpeakAsync("$secondsremaining seconds remaining") > $null
                                }
                            }
                        }

                    }
                }
            }
        }
        $currentvrt = $vrts | Where-Object -FilterScript {$_.countdownpoint -ge $($secondsremaining - 1)} | Select-Object -First 1
        if ($currentvrt)
        {
            $Frequency = $currentvrt.frequency
            $Units = $currentvrt.units
            $vrts = $vrts | Where-Object -FilterScript {$_countdownpoint -ne $currentvrt.countdownpoint}
        }
        Start-Sleep -Milliseconds $($nextsecond - (get-date)).TotalMilliseconds
    }
    until ($secondsremaining -eq 0)
    if ($showprogress)
    {
        $writeprogressparams.completed = $true
        $writeprogressparams.Activity = "Completed Timer for $length $units"
        Write-Progress @writeprogressparams
    }

    }

