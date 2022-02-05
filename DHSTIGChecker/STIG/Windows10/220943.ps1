<#
Rule Title: The default permissions of global system objects must be increased.
Severity: low
Vuln ID: V-220943
STIG ID: WN10-SO-000240

Discussion:
Windows systems maintain a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default DACL that specifies who can access the objects with what permissions. If this policy is enabled, the default DACL is stronger, allowing non-admin users to read shared objects, but not modify shared objects that they did not create.


Check Content:
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\

Value Name: ProtectionMode

Value Type: REG_DWORD
Value: 1

#>

$Params = @{
    Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\"
    Name          = "ProtectionMode"
    ExpectedValue = 1
}

Compare-RegKeyValue @Params