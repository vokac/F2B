#
# build F2B and create installation package
#
 param (
    [string]$config = "Release",
    [string]$platform = "x86", #"Any CPU",
    [string]$VCS = "F2BShared\VCS.resx"
 )
 

# revision
$branch = "unknown"
$commit = "unknown"
$status = "unknown"
if ((Get-Command "git.exe" -ErrorAction SilentlyContinue) -eq $null) { 
   Write-Host "[WARN] Unable to find git.exe in your PATH"
   Write-Host "Reading current revision directly from .git"
   If (-Not (Test-Path ".git\HEAD")) {
      Write-Host "[ERROR] Unable to find .git repository in current directory"
      Exit
   }
   $href = Get-Content ".git\HEAD"
   $href = $href -replace 'ref: ', ''
   $href = $href -replace '/', '\'
   $branch = $href -replace '.*\\'
   $commit = Get-Content ".git\${href}"
} else {
   $branch = Invoke-Expression "git rev-parse --abbrev-ref HEAD"
   $commit = Invoke-Expression "git rev-parse --short=0 HEAD"
   $status = Invoke-Expression "git status --untracked-files=no --porcelain"
}

Write-Host "Update resource file with VCS revision numbers in ""${VCS}"""
Write-Host "  branch: ${branch}"
Write-Host "  commit: ${commit}"
Write-Host "  status: ${status}"
$VCS_template = "${VCS}.template"
$VCS_new = "${VCS}.new"
If (Test-Path $VCS_template) {
   (Get-Content $VCS_template) | ForEach-Object `
      { $_ -replace 'XXX_TYPE_XXX', 'git' `
           -replace 'XXX_BRANCH_XXX', $branch `
           -replace 'XXX_COMMIT_XXX', $commit `
           -replace 'XXX_STATUS_XXX', $status `
      } | Set-Content $VCS_new
   If (-Not (Test-Path $VCS)) {
      Copy-Item "${VCS_new}" "${VCS}"
   } Else {
      $old = Get-Content $VCS
      $new = Get-Content $VCS_new
      $c = Compare-Object $old $new
	  If ($c -ne $null) {
         Copy-Item "${VCS_new}" "${VCS}"
	  }
   }
} Else {
   Write-Host "[ERROR] Template file ""${VCS_template}"" doesn't exists"
   Exit
}


# build
if ((Get-Command "msbuild.exe" -ErrorAction SilentlyContinue) -eq $null) { 
   Write-Host "[ERROR] Unable to find msbuild.exe in your PATH"
   Write-Host "Use vcvarsall.bat from Visual Studion or MSBuild command prompt"
   Exit
}

Write-Host "Starting ${config} ${platform} build"
msbuild /t:Rebuild /p:Configuration=${config} /p:Platform="${platform}"
Write-Host "Finished ${config} ${platform} build"


# install
$CURR = Get-Date -format "yyyyMMdd"
$PKGPATH = "F2B.${CURR}.${config}.${platform}"
Write-Host "Create installation package in ""${PKGPATH}"""
If (Test-Path "${PKGPATH}") {
   Write-Host "[ERROR] Installation package directory ""${PKGPATH}"" already exists"
   Exit
}

$cppdir = if ($platform -eq "x64") {"x64\${config}"} else {"${config}"}
Write-Host "Using cppdir `"${cppdir}`""
New-Item -Type directory "${PKGPATH}" | Out-Null
Copy-Item -Verbose "README.md" "${PKGPATH}"
Copy-Item -Verbose "F2BLogAnalyzer\bin\${config}\F2BLogAnalyzer.*.exe" "${PKGPATH}"
Copy-Item -Verbose "F2BLogAnalyzer\bin\${config}\F2BLogAnalyzer*.config*" "${PKGPATH}"
#Copy-Item -Verbose "F2BLogAnalyzer\App.config" "${PKGPATH}\F2BLogAnalyzer.exe.config"
#Copy-Item -Verbose "F2BLogAnalyzer\App.config.full" "${PKGPATH}\F2BLogAnalyzer.exe.config.full"
#Copy-Item -Verbose "F2BLogAnalyzer\App.config.minimal" "${PKGPATH}\F2BLogAnalyzer.exe.config.minimal"
Copy-Item -Verbose "F2BFirewall\bin\${config}\F2BFirewall.exe" "${PKGPATH}"
Copy-Item -Verbose "F2BFirewall\bin\${config}\F2BFirewall.exe.config" "${PKGPATH}"
Copy-Item -Verbose "F2BFwCmd\bin\${config}\F2BFwCmd.exe" "${PKGPATH}"
Copy-Item -Verbose "F2BFwCmd\bin\${config}\F2BFwCmd.exe.config" "${PKGPATH}"
Copy-Item -Verbose "F2BQueue\bin\${config}\F2BQueue.exe" "${PKGPATH}"
Copy-Item -Verbose "F2BQueue\bin\${config}\F2BQueue.exe.config" "${PKGPATH}"
Copy-Item -Verbose "${cppdir}\F2BWFP.dll" "${PKGPATH}"
Copy-Item -Verbose "F2BLogAnalyzer\tests\*.ps1" "${PKGPATH}"
foreach ($path in @("F2BLogAnalyzer\tests\LogEvent.exe")) {
   if (Test-Path "$path") {
      Copy-Item -Verbose "${path}" "${PKGPATH}"
   }
}
# copy required visual studio redistributable files
# (this only works with visual studio 2015)
$libdir = if ($platform -eq "x64") {"${Env:windir}\system32"} else {"${Env:windir}\SysWOW64"}
Write-Host "Using libdir `"${libdir}`""
$redis = @('concrt140.dll', 'mfc140.dll', 'mfcm140.dll', 'msvcp140.dll', 'ucrtbased.dll', 'vcamp140.dll', 'vccorlib140.dll', 'vcomp140.dll', 'vcruntime140.dll', 'ucrtbase.dll')
foreach ($file in $redis) {
   If ($config -eq "Debug") {
      $file = $file -replace '.dll', 'd.dll'
   }
   $path = "${libdir}\${file}"
   If (Test-Path "${path}") {
      Copy-Item -Verbose "${path}" "${PKGPATH}"
   }
}