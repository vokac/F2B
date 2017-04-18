function PSProcStart()
{
   #Write-Host "PSProcStart"
   Add-Content C:\F2B\PSProc.out "PSProcStart"
}

function PSProcStop()
{
   #Write-Host "PSProcStop"
   Add-Content C:\F2B\PSProc.out "PSProcStop"
}

function PSProcExecute($evtlog)
{
   #Write-Host "PSProcExecute"
   Add-Content C:\F2B\PSProc.out "PSProcExecute"
   if ($evtlog) {
      Add-Content C:\F2B\PSProc.out "  Instance.Id: $($evtlog.Id)"
      Add-Content C:\F2B\PSProc.out "  Instance.Input.Name: $($($evtlog.Input).Name)"
      Add-Content C:\F2B\PSProc.out "  Instance.Input.InputName: $($($evtlog.Input).InputName)"
      Add-Content C:\F2B\PSProc.out "  Instance.Input.InputType: $($($evtlog.Input).InputType)"
      Add-Content C:\F2B\PSProc.out "  Instance.Input.SelectorName: $($($evtlog.Input).SelectorName)"
      Add-Content C:\F2B\PSProc.out "  Instance.Input.Processor: $($($evtlog.Input).Processor)"
      Add-Content C:\F2B\PSProc.out "  Instance.Created: $($evtlog.Created)"
      Add-Content C:\F2B\PSProc.out "  Instance.Hostname: $($evtlog.Hostname)"
      Add-Content C:\F2B\PSProc.out "  Instance.LogData: $($evtlog.LogData)"
      $procNames = $evtlog.ProcNames -join ','
      Add-Content C:\F2B\PSProc.out "  Instance.ProcNames: $procNames"
      foreach ($data in $evtlog.ProcData.GetEnumerator()) {
         Add-Content C:\F2B\PSProc.out "  $($data.Key): $($data.Value)"
      }
   }
}

#PSProcStart
#PSProcStop
#PSProcExecute $null
#Write-Host "PSProcInit"
Add-Content C:\F2B\PSProc.out "PSProcInit"
