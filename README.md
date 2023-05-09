DHSTIGChecker
======
The purpose of this module is to provide for automated checks of as many items of a given STIG as possible.

# Dependencies
This module has no external dependencies.

# Checks

## Check Values
Individual checks can return one of four values: Not Reviewed, Open, Not A Finding, and Not Applicable
### Not Reviewed
If a check returns 'Not Reviewed', the Vulnerability ID will need to be checked manually.
### Open
If a check returns 'Open', the Vulnerability ID has been evaluated and found to be set incorrectly.
### Not A Finding
If a check returns 'Not A Finding', the Vulnerability ID has been evaluated and found to be set correctly.
### Not Applicable
If a check returns 'Not Applicable', the Vulnerability ID has been evaluated and found to not apply to the system.

## Check States
For the checks, they can be in one of four possible states:
### Complete
A check is considered complete if the check can validate all possible states. The result will return
### Partial
A check is considered partial if the logic in the check does not properly validate all possible states. For the checks that are performed, the result will return the correct result. For states that cannot be validated, the result will return 'Not Reviewed'. For the purpose of documentation, this category will not include those checks which may differ for LTSC/B version of Windows (See 'Known Issues' for additional details).
### Manual
A check is considered manual if the check cannot be automated. The result will always return 'Not Reviewed'.
### Incomplete
A check is considered incomplete if it has not yet been automated. The result always return 'Not Reviewed'.
# STIGs
This module is able to evaluate the following STIGs for compliance:
- Windows 10 (v2r5)
- Windows 11 (v1r2)
- Server 2016 (v2r5)
- Server 2019 (v2r5)

## Server 2016
This STIG contains 273 individual checks.
- Total Checks: 273
    - Complete  : 174
        - V-224820, V-224827, V-224829, V-224831, V-224837, V-224839, V-224842, V-224857, V-224858, V-224864, V-224865, V-224866, V-224867, V-224868, V-224869, V-224870, V-224871, V-224872, V-224873, V-224874, V-224881, V-224882, V-224884, V-224885, V-224886, V-224887, V-224888, V-224889, V-224890, V-224891, V-224892, V-224893, V-224894, V-224895, V-224896, V-224897, V-224898, V-224899, V-224900, V-224901, V-224902, V-224903, V-224904, V-224905, V-224906, V-224907, V-224908, V-224909, V-224910, V-224911, V-224912, V-224913, V-224914, V-224915, V-224916, V-224917, V-224918, V-224919, V-224920, V-224921, V-224922, V-224924, V-224925, V-224926, V-224927, V-224928, V-224929, V-224930, V-224931, V-224932, V-224933, V-224934, V-224935, V-224936, V-224937, V-224938, V-224939, V-224941, V-224942, V-224943, V-224944, V-224945, V-224946, V-224947, V-224948, V-224949, V-224951, V-224952, V-224953, V-224954, V-224955, V-224956, V-224957, V-224958, V-224959, V-224960, V-224961, V-224962, V-224963, V-225008, V-225009, V-225010, V-225011, V-225012, V-225014, V-225015, V-225021, V-225022, V-225023, V-225024, V-225025, V-225026, V-225027, V-225028, V-225030, V-225031, V-225032, V-225033, V-225034, V-225035, V-225037, V-225038, V-225039, V-225040, V-225041, V-225042, V-225043, V-225044, V-225045, V-225046, V-225047, V-225048, V-225049, V-225050, V-225051, V-225052, V-225053, V-225054, V-225055, V-225056, V-225057, V-225058, V-225059, V-225060, V-225061, V-225062, V-225063, V-225064, V-225065, V-225066, V-225067, V-225068, V-225069, V-225070, V-225071, V-225072, V-225073, V-225074, V-225076, V-225077, V-225078, V-225079, V-225080, V-225082, V-225084, V-225085, V-225086, V-225087, V-225088, V-225089, V-225091, V-225092, V-225093, V-236000
    - Partial   : 49
        - V-224826, V-224841, V-224964, V-224965, V-224966, V-224967, V-224968, V-224969, V-224970, V-224971, V-224972, V-224973, V-224974, V-224975, V-224976, V-224977, V-224978, V-224979, V-224980, V-224981, V-224982, V-224983, V-224984, V-224985, V-224986, V-224987, V-224988, V-224989, V-224990, V-224991, V-224992, V-224993, V-224994, V-224995, V-224996, V-224997, V-224998, V-224999, V-225000, V-225001, V-225002, V-225003, V-225004, V-225005, V-225006, V-225013, V-225018, V-225019, V-225020
    - Manual    : 3
        - V-224825, V-224848, V-224875
    - Incomplete: 47
        - V-224819, V-224821, V-224822, V-224823, V-224824, V-224828, V-224830, V-224832, V-224833, V-224834, V-224835, V-224836, V-224838, V-224840, V-224843, V-224844, V-224845, V-224846, V-224847, V-224849, V-224850, V-224851, V-224852, V-224853, V-224854, V-224855, V-224856, V-224859, V-224860, V-224861, V-224862, V-224863, V-224876, V-224877, V-224878, V-224879, V-224880, V-224883, V-224923, V-224940, V-225007, V-225016, V-225017, V-225029, V-225036, V-225081, V-225083

## Server 2019
This STIG contains 275 individual checks.
- Total Checks: 275
    - Complete  : 177
        - V-205625, V-205626, V-205627, V-205629, V-205630, V-205632, V-205633, V-205634, V-205635, V-205636, V-205637, V-205638, V-205639, V-205643, V-205644, V-205648, V-205649, V-205650, V-205651, V-205652, V-205653, V-205654, V-205655, V-205656, V-205657, V-205658, V-205659, V-205660, V-205662, V-205663, V-205665, V-205676, V-205686, V-205687, V-205688, V-205689, V-205690, V-205691, V-205692, V-205693, V-205694, V-205696, V-205707, V-205708, V-205709, V-205711, V-205712, V-205713, V-205714, V-205715, V-205716, V-205717, V-205718, V-205719, V-205720, V-205722, V-205724, V-205725, V-205729, V-205730, V-205749, V-205750, V-205751, V-205752, V-205753, V-205754, V-205755, V-205756, V-205757, V-205758, V-205760, V-205762, V-205763, V-205764, V-205765, V-205766, V-205767, V-205768, V-205770, V-205771, V-205772, V-205773, V-205774, V-205775, V-205776, V-205777, V-205778, V-205779, V-205780, V-205781, V-205782, V-205783, V-205784, V-205795, V-205796, V-205797, V-205798, V-205801, V-205802, V-205804, V-205805, V-205806, V-205808, V-205809, V-205810, V-205811, V-205812, V-205813, V-205814, V-205815, V-205816, V-205817, V-205819, V-205820, V-205821, V-205822, V-205823, V-205824, V-205825, V-205826, V-205827, V-205828, V-205830, V-205832, V-205833, V-205834, V-205835, V-205836, V-205837, V-205838, V-205839, V-205840, V-205841, V-205842, V-205848, V-205850, V-205852, V-205856, V-205857, V-205858, V-205859, V-205860, V-205861, V-205862, V-205863, V-205865, V-205866, V-205867, V-205868, V-205869, V-205870, V-205871, V-205872, V-205873, V-205874, V-205876, V-205906, V-205907, V-205908, V-205909, V-205910, V-205911, V-205912, V-205913, V-205914, V-205915, V-205916, V-205917, V-205918, V-205919, V-205920, V-205921, V-205922, V-205923, V-205924, V-205925, V-236001
    - Partial   : 49
        - V-205628, V-205645, V-205646, V-205647, V-205666, V-205667, V-205668, V-205669, V-205670, V-205671, V-205672, V-205673, V-205674, V-205675, V-205695, V-205701, V-205702, V-205703, V-205704, V-205705, V-205706, V-205723, V-205726, V-205732, V-205733, V-205738, V-205739, V-205740, V-205741, V-205742, V-205743, V-205744, V-205745, V-205746, V-205747, V-205748, V-205786, V-205787, V-205788, V-205789, V-205790, V-205791, V-205792, V-205793, V-205794, V-205807, V-205818, V-205875, V-205877
    - Manual    : 2
        - V-205710, V-205799
    - Incomplete: 47
        - V-205624, V-205631, V-205640, V-205641, V-205642, V-205661, V-205664, V-205677, V-205678, V-205679, V-205680, V-205681, V-205682, V-205683, V-205684, V-205685, V-205697, V-205698, V-205699, V-205700, V-205721, V-205727, V-205728, V-205731, V-205734, V-205735, V-205736, V-205737, V-205759, V-205761, V-205769, V-205785, V-205800, V-205803, V-205829, V-205843, V-205844, V-205845, V-205846, V-205847, V-205849, V-205851, V-205853, V-205854, V-205855, V-205864, V-214936
## Windows 10
This STIG contains 257 individual checks.
- Total Checks: 257
    - Complete  : 224
        - V-220697, V-220698, V-220699, V-220700, V-220702, V-220703, V-220704, V-220706, V-220708, V-220711, V-220716, V-220718, V-220719, V-220720, V-220721, V-220722, V-220723, V-220726, V-220727, V-220728, V-220729, V-220730, V-220731, V-220732, V-220739, V-220740, V-220741, V-220742, V-220743, V-220744, V-220745, V-220746, V-220747, V-220748, V-220749, V-220750, V-220751, V-220752, V-220753, V-220754, V-220755, V-220756, V-220757, V-220758, V-220759, V-220760, V-220761, V-220762, V-220763, V-220764, V-220765, V-220766, V-220767, V-220768, V-220769, V-220770, V-220771, V-220772, V-220773, V-220774, V-220775, V-220776, V-220777, V-220778, V-220779, V-220780, V-220781, V-220786, V-220787, V-220788, V-220789, V-220790, V-220791, V-220792, V-220794, V-220795, V-220796, V-220797, V-220798, V-220799, V-220800, V-220801, V-220802, V-220803, V-220805, V-220806, V-220807, V-220808, V-220809, V-220810, V-220811, V-220812, V-220813, V-220814, V-220815, V-220816, V-220817, V-220818, V-220819, V-220820, V-220821, V-220822, V-220823, V-220824, V-220825, V-220826, V-220827, V-220828, V-220829, V-220830, V-220831, V-220832, V-220833, V-220835, V-220836, V-220837, V-220838, V-220839, V-220840, V-220841, V-220842, V-220843, V-220844, V-220845, V-220846, V-220847, V-220848, V-220849, V-220850, V-220851, V-220852, V-220853, V-220854, V-220855, V-220856, V-220857, V-220858, V-220859, V-220860, V-220861, V-220862, V-220863, V-220865, V-220866, V-220867, V-220868, V-220869, V-220870, V-220871, V-220872, V-220902, V-220903, V-220904, V-220905, V-220906, V-220908, V-220909, V-220910, V-220911, V-220912, V-220913, V-220914, V-220915, V-220916, V-220917, V-220918, V-220919, V-220920, V-220922, V-220923, V-220924, V-220925, V-220926, V-220927, V-220928, V-220929, V-220930, V-220931, V-220932, V-220934, V-220935, V-220936, V-220937, V-220938, V-220939, V-220940, V-220941, V-220942, V-220943, V-220944, V-220945, V-220947, V-220948, V-220949, V-220950, V-220951, V-220952, V-220954, V-220955, V-220956, V-220957, V-220958, V-220959, V-220960, V-220961, V-220962, V-220963, V-220964, V-220965, V-220966, V-220967, V-220973, V-220974, V-220975, V-220976, V-220977, V-220978, V-220979, V-220980, V-220981, V-220982, V-220983, V-250319, V-252896
    - Partial   : 12
        - V-220705, V-220707, V-220710, V-220715, V-220734, V-220735, V-220736, V-220738, V-220793, V-220834, V-220969, V-220970
    - Manual    : 1
        - V-220709
    - Incomplete: 20
        - V-220701, V-220712, V-220713, V-220714, V-220717, V-220724, V-220725, V-220733, V-220737, V-220782, V-220783, V-220784, V-220907, V-220921, V-220933, V-220946, V-220968, V-220971, V-220972, V-252903

### Partial Checks
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
- V-220715
    - Rule Title: Standard local user accounts must not exist on a system in a domain.
    - This will properly mark the item as 'Not Applicable' for non-domain joined systems. No additional check is done for determining if this check is being met and requires a manual check.
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
- V-220793
    - Rule Title: Windows 10 must cover or disable the built-in or attached camera when not in use.
    - This check is only reporting based on the value of the registry key. It is not checking if the system has a camera
- V-220834
    - Rule Title: Windows Telemetry must not be configured to Full.
    - This check is only verifying two of three possible valid configurations. The third value may cause a false negative which will then require a manual check.
- V-220969
    - The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
    - If the system is not domain-joined, it is marked 'Not Applicable'. If the system is domain-joined, it is marked 'Not Reviewed' and requires a manual check.
- V-220970
    - Rule Title: The Deny log on as a service user right on Windows 10 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
    - If the system is not domain-joined, it is marked 'Not Applicable'. If the system is domain-joined, it is marked 'Not Reviewed' and requires a manual check.

### Manual Checks
- V-220709
    - Rule Title: Alternate operating systems must not be permitted on the same system.

## Windows 11
This STIG contains 253 individual checks.
- Total Checks: 253
    - Complete: 212
        - V-253255, V-253256, V-253257, V-253259, V-253260, V-253261, V-253265, V-253267, V-253268, V-253273, V-253275, V-253276, V-253277, V-253278, V-253279, V-253280, V-253283, V-253284, V-253289, V-253297, V-253298, V-253299, V-253300, V-253301, V-253302, V-253303, V-253304, V-253305, V-253306, V-253307, V-253308, V-253309, V-253310, V-253311, V-253312, V-253313, V-253314, V-253315, V-253316, V-253317, V-253318, V-253319, V-253320, V-253321, V-253322, V-253323, V-253324, V-253325, V-253326, V-253327, V-253328, V-253329, V-253330, V-253331, V-253332, V-253333, V-253334, V-253335, V-253336, V-253337, V-253338, V-253339, V-253343, V-253344, V-253345, V-253346, V-253347, V-253348, V-253349, V-253352, V-253353, V-253354, V-253355, V-253356, V-253357, V-253358, V-253359, V-253360, V-253361, V-253362, V-253363, V-253365, V-253366, V-253367, V-253368, V-253370, V-253372, V-253373, V-253374, V-253375, V-253376, V-253377, V-253378, V-253379, V-253380, V-253381, V-253382, V-253383, V-253384, V-253385, V-253386, V-253387, V-253388, V-253389, V-253390, V-253391, V-253393, V-253394, V-253395, V-253396, V-253397, V-253398, V-253399, V-253400, V-253401, V-253402, V-253403, V-253404, V-253405, V-253406, V-253407, V-253408, V-253409, V-253410, V-253411, V-253412, V-253413, V-253414, V-253415, V-253416, V-253417, V-253418, V-253419, V-253420, V-253421, V-253422, V-253423, V-253424, V-253425, V-253426, V-253427, V-253428, V-253429, V-253430, V-253432, V-253433, V-253434, V-253435, V-253436, V-253437, V-253438, V-253439, V-253440, V-253441, V-253442, V-253443, V-253444, V-253445, V-253446, V-253447, V-253448, V-253449, V-253450, V-253451, V-253452, V-253453, V-253454, V-253455, V-253456, V-253458, V-253459, V-253460, V-253461, V-253462, V-253463, V-253464, V-253465, V-253466, V-253467, V-253468, V-253469, V-253471, V-253472, V-253473, V-253474, V-253475, V-253476, V-253477, V-253478, V-253479, V-253480, V-253481, V-253482, V-253483, V-253484, V-253485, V-253486, V-253487, V-253488, V-253489, V-253490, V-253496, V-253497, V-253498, V-253499, V-253500, V-253501, V-253502, V-253503, V-253504, V-253505, V-253506
    - Partial: 6
        - V-253262, V-253272, V-253350, V-253351, V-253492, V-253493
    - Manual: 1
        - V-253295
    - Incomplete: 34
        - V-253254, V-253258, V-253263, V-253264, V-253266, V-253269, V-253270, V-253271, V-253274, V-253281, V-253282, V-253285, V-253286, V-253287, V-253288, V-253290, V-253291, V-253292, V-253293, V-253294, V-253296, V-253340, V-253341, V-253342, V-253364, V-253369, V-253371, V-253392, V-253431, V-253457, V-253470, V-253491, V-253494, V-253495

### Partial Checks
- V-253262
    - Rule Title: The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.
- V-253272
    - Rule Title: Standard local user accounts must not exist on a system in a domain.
- V-253350
    - Rule Title: Camera access from the lock screen must be disabled.
- V-253351
    - Rule Title: Windows 11 must cover or disable the built-in or attached camera when not in use.
- V-253492
    - Rule Title: The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
- V-253493
    - Rule Title: The "Deny log on as a service" user right on Windows 11 domain-joined workstations must be configured to prevent access from highly privileged domain accounts.
# Functions
This module is a collection of public functions. Below is a brief overview of the functions in this module and their purpose. Additional details and examples for use of these functions can be found by calling the help for the function (Get-Help Verb-Noun).

## Invoke-STIGChecker
This is the primary function which provides the majority of the functionality of this module. It runs the appropriate checks based on the STIG being evaluated. It returns an object containing the results of the checks performed.

Save the output to a variable for manipulation. ($MyResults = Invoke-STIGChecker -Name Windows10 -ConfigPath .\Config\MyEnvConfig.json)

# Known Issues
- No evaluation for LTSC/LTSB versions
    - If an individual check requires logic to evaluate an LTSC/B version, it does not exist and may return an incorrect value.
    - These are not counted as partial checks. Due to a lack of these types of systems in my environment this support is not likely to be added.
- HKCU registry hive checks
    - For checks that are looking in the HKCU registry hive, these will properly report only for the user running the check (I.E. The currently logged in user). As these are a per-user setting, there is no guarantee this is being set for all users on the system. For domain-joined systems, ensure these settings are being applied against all users via Group Policy.
    - Windows 10
        - V-220861, V-220872, V-220954, V-220955
    - Windows 11
        - V-253425, V-253477, V-253478
    - Server 2016
        - V-225069, V-236000
    - Server 2019
        - V-205924, V-236001

# To-Do
- [ ] Complete remaining checks
- [ ] Compile results into a simple report
- [ ] Allow exporting of results to a STIG Checklist file

# Resources
Public DoD Cyber Exchange
- Public Page: https://public.cyber.mil/
- GPO Package: https://public.cyber.mil/stigs/gpo/
- STIG Library: https://public.cyber.mil/stigs/compilations/