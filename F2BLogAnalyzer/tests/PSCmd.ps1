# NOTE: I don't know how to deal with arguments starting with dash using "param ( ... )"
param (
   [string]$param1 = "empty",
   [string]$param2 = "empty",
   [string]$param3 = "empty"
)
#$param1 = 'empty'
#$param2 = 'empty'
#$param3 = 'empty'
#if ($args.count -gt 0) { $param1 = $args[0] }
#if ($args.count -gt 1) { $param2 = $args[1] }
#if ($args.count -gt 2) { $param3 = $args[2] }

$ret = $param1 + ';' + $param2 + ';' + $param3
Add-Content C:\F2B\PSCmd.out "$ret"
#$ret
