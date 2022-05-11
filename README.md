DHSTIGChecker
======
The purpose of this module is to provide for automated checks of as many items of a given STIG as possible.

# Checks
Individual checks can return one of four values: Not Reviewed, Open, Not A Finding, and Not Applicable
## Not Reviewed
If a check returns 'Not Reviewed', the Vulnerability ID will need to be checked manually.
## Open
If a check returns 'Open', the Vulnerability ID has been evaluated and found to be set incorrectly.
## Not A Finding
If a check returns 'Not A Finding', the Vulnerability ID has been evaluated and found to be set correctly.
## Not Applicable
If a check returns 'Not Applicable', the Vulnerability ID has been evaluated and found to not apply to the system.
# Dependencies
This module has no external dependencies.

# STIGs
This module is able to evaluate the following STIGs for compliance:
- Windows 10 v2r3 (1 Nov 2021)
- Server 2016 v2r3 (1 Nov 2021)
- Server 2019 v2r3 (1 Nov 2021)

## Server 2016
This STIG contains 273 individual checks.
- Total Checks: 273
    - Complete  : 145
        - Partial   : 0
    - Manual    : 0
    - Incomplete: 128

## Server 2019
This STIG contains 275 individual checks.
- Total Checks: 275
    - Complete  : 156
        - Partial   : 0
    - Manual    : 0
    - Incomplete: 119
        - V-205624, V-205628, V-205631, V-205632, V-205640, V-205641, V-205642, V-205645, V-205646, V-205647, V-205648, V-205650, V-205657, V-205658, V-205661, V-205663, V-205664, V-205665, V-205666, V-205667, V-205668, V-205669, V-205670, V-205671, V-205672, V-205673, V-205674, V-205675, V-205677, V-205678, V-205679, V-205680, V-205681, V-205682, V-205683, V-205684, V-205685, V-205695, V-205697, V-205698, V-205699, V-205700, V-205701, V-205702, V-205703, V-205704, V-205705, V-205706, V-205707, V-205710, V-205716, V-205717, V-205718, V-205719, V-205720, V-205721, V-205723, V-205726, V-205727, V-205728, V-205731, V-205732, V-205733, V-205734, V-205735, V-205736, V-205737, V-205738, V-205739, V-205740, V-205741, V-205742, V-205743, V-205744, V-205745, V-205746, V-205747, V-205748, V-205759, V-205761, V-205769, V-205785, V-205786, V-205787, V-205788, V-205789, V-205790, V-205791, V-205792, V-205793, V-205794, V-205799, V-205800, V-205803, V-205807, V-205811, V-205812, V-205813, V-205818, V-205829, V-205843, V-205844, V-205845, V-205846, V-205847, V-205849, V-205850, V-205851, V-205852, V-205853, V-205854, V-205855, V-205864, V-205875, V-205877, V-205907, V-205924, V-214936, V-236001
## Windows 10
This STIG contains 257 individual checks.
- Total Checks: 257
    - Complete  : 228
        - Partial   : 7
    - Manual    : 1
    - Incomplete: 28
        - V-220701, V-220712, V-220713, V-220714, V-220715, V-220717, V-220724, V-220725, V-220733, V-220737, V-220782, V-220783, V-220784, V-220834, V-220861, V-220872, V-220907, V-220921, V-220922, V-220933, V-220946, V-220954, V-220955, V-220968, V-220969, V-220970, V-220971, V-220972

### Partial Checks
A check is considered partial if the logic in the check does not properly validate all possible states or has the possibility of returning an incorrect result. For the purpose of documentation, this category will not include those checks which may differ for LTSC/B version of Windows (See 'Known Issues' for additional details).

The following is a list of vulnerability ID's that are only partially checked.
- V-220705
    - Rule Title: The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
    - This will properly report 'Not Applicable' for classified systems. No additional check is done for determining if this check is being met and requires a manual check.
- V-220707
    - Rule Title: The Windows 10 system must use an anti-virus program.
    - This is not a comprehensive check. It will detect if Windows Defender, McAfee, or Symantec has a serice running. If one of these services is detected, the assumption is made that it is being used as the AV product and will be marked as 'Not a Finding'.
- V-220710
    - Rule Title: Non system-created file shares on a system must limit access to groups that require it.
    - This will properly mark the item as 'Not a Finding' if only the default system shares are discovered. If this finds any non default shares, it will return 'Not Reviewed' and requires a manual check. It may return a false positive/negative if a default share description has been changed or a non-default share uses the same share description as a default share.
- V-220734
    - Rule Title: Bluetooth must be turned off unless approved by the organization.
    - If no Bluetooth device is found, it will be marked as 'Not Applicable'. If any Bluetooth device is found, it will be marked 'Not Reviewed' and requires a manual check.
- V-220735
    - Rule Title: Bluetooth must be turned off when not in use.
    - If no Bluetooth device is found, it will be marked as 'Not Applicable'. If any Bluetooth device is found, it will be marked 'Not Reviewed' and requires a manual check.
- V-220736
    - Rule Title: The system must notify the user when a Bluetooth device attempts to connect.
    - If no Bluetooth device is found, it will be marked as 'Not Applicable'. If any Bluetooth device is found, it will be marked 'Not Reviewed' and requires a manual check.
- V-220738
    - Rule Title: Windows 10 non-persistent VM sessions should not exceed 24 hours.
    - If the configuration file indicates the system is not a non-persistent VDI system, it is marked as 'Not Applicable'. If the system is a non-persistent VDI system, it is marked as 'Not Reviewed' and requires a manual check.

### Manual Checks
- V-220709
    - Rule Title: Alternate operating systems must not be permitted on the same system.

# Functions
This module is a collection of public functions. Below is a brief overview of the functions in this module and their purpose. Additional details and examples for use of these functions can be found by calling the help for the function (Get-Help Verb-Noun).

## Invoke-STIGChecker
This is the primary function which provides the majority of the functionality of this module. It runs the appropriate checks based on the STIG being evaluated. It returns an object containing the results of the checks performed.

# Known Issues
- No evaluation for LTSC/B versions
    - If an individual check requires logic to evaluate an LTSC/B version, it does not exist and may return an incorrect value.
    - These are not counted as partial checks. Due to a lack of these types of systems in my environment this support is not likely to be added.

# To-Do
- [ ] Complete remaining checks
- [ ] Compile results into a simple report
- [ ] Allow exporting of results to a STIG Checklist file

# Resources
Public DoD Cyber Exchange
- Public Page: https://public.cyber.mil/
- GPO Package: https://public.cyber.mil/stigs/gpo/
- STIG Library: https://public.cyber.mil/stigs/compilations/