param($proc)

function PSProcStart()
{
   #Write-Host "PSProcStart"
   Add-Content $outputFile "PSProcStart $($proc.Name) - $(Get-Date)"
}

function PSProcStop()
{
   #Write-Host "PSProcStop"
   Add-Content $outputFile "PSProcStop $($proc.Name) - $(Get-Date)"
}

function PSProcExecute($evtlog)
{
   #Write-Host "PSProcExecute"
   Add-Content $outputFile "PSProcExecute $($proc.Name) - $(Get-Date)"
   Add-Content $outputFile "  Processor instance details:"
   Add-Content $outputFile "    Proc.Id: $($proc.Name)"
   Add-Content $outputFile "    Proc.Next: $($proc.goto_next)"
   Add-Content $outputFile "    Proc.Error: $($proc.goto_error)"
   Add-Content $outputFile "  Event log instance details:"
   Add-Content $outputFile "    Evtlog.Id: $($evtlog.Id)"
   Add-Content $outputFile "    Evtlog.Input.Name: $($($evtlog.Input).Name)"
   Add-Content $outputFile "    Evtlog.Input.InputName: $($($evtlog.Input).InputName)"
   Add-Content $outputFile "    Evtlog.Input.InputType: $($($evtlog.Input).InputType)"
   Add-Content $outputFile "    Evtlog.Input.SelectorName: $($($evtlog.Input).SelectorName)"
   Add-Content $outputFile "    Evtlog.Input.Processor: $($($evtlog.Input).Processor)"
   Add-Content $outputFile "    Evtlog.Created: $($evtlog.Created)"
   Add-Content $outputFile "    Evtlog.Hostname: $($evtlog.Hostname)"
   Add-Content $outputFile "    Evtlog.LogData: $($evtlog.LogData)"
   $procNames = $evtlog.ProcNames -join ','
   Add-Content $outputFile "    Evtlog.ProcNames: $procNames"
   Add-Content $outputFile "  Available variables:"
   foreach ($data in $evtlog.ProcData.GetEnumerator()) {
      Add-Content $outputFile "    $($data.Key): $($data.Value)"
   }

   # add / modify event data
   $evtlog.SetProcData("$($proc.Name).data1", "value1");
   $evtlog.SetProcData("$($proc.Name).data2", "value2");
   $evtlog.SetProcData("$($proc.Name).data3", "value3");

   # call error processor
   #"ERROR"
   # call named processor
   #"GOTO proc_name"
   # call next processor (default behavior)
   "NEXT"
}

#PSProcStart
#PSProcStop
#PSProcExecute $null
#Write-Host "PSProcInit"
$outputFile = "C:\F2B\PSProc.$($proc.Name).out"
Add-Content $outputFile "PSProcInit $($proc.Name) - $(Get-Date)"
