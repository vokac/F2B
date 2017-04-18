function Test-Me($param1, $param2, $param3)
{
	$ret = $param1 + ';' + $param2 + ';' + $param3
	Add-Content C:\F2B\PSFunct.out "PSProcStart" $ret
	$ret
}
