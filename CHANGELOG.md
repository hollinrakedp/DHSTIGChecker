Change Log
======
# v0.5 (2023-05-01)
Major update to newer STIG revisions.
## Fixes

## Changes
* Updated STIG Release
    * Windows 10 v2r5
    * Server 2016 v2r5
    * Server 2019 v2r5
* Added STIG Release
    * Windows 11 v1r2
* Added blank checklist files for each STIG
* Each check now contains the STIG version and STIG ID in the comment block

## Errata

# v0.4 (2022-08-22)

## Fixes
* Invoke-STIGChecker now exits if it fails to find the environment configuration or retrieve the computer information
* Get-STIGVulnInfo - Corrected parameter set name (Was 'All', Should be 'ShowAll')
* Resolved an issue where registry checks with multiple keys to check was failing
* Resolved an issue where the tab completion was not displaying the valid values

## Changes
* Invoke-STIGChecker - Added progress bar for STIG Checks
* Server 2016
    * Completed the following checks: V-225069, V-236000
* Server 2019
    * Completed the following checks: V-205924, V-236001
    * Partially completed checks: V-205628, V-205645, V-205646, V-205647, V-205665, V-205666, V-205667, V-205668, V-205669, V-205670, V-205671, V-205672, V-205673, V-205674, V-205675, V-205695, V-205701, V-205702, V-205703, V-205704, V-205705, V-205706, V-205723, V-205726, V-205732, V-205733, V-205738, V-205739, V-205740, V-205741, V-205742, V-205743, V-205744, V-205745, V-205746, V-205747, V-205748, V-205786, V-205787, V-205788, V-205789, V-205790, V-205791, V-205792, V-205793, V-205794, V-205818, V-205875, V-205877
* Windows 10
    * Completed the following checks: V-220861, V-220872, V-220954, V-220955

## Errata
* Explicitly declared variable scope
# v0.3 (2022-05-15)
Significant progress was made towards completing the checks for both the Server 2016 and 2019 STIGs. These newly added checks may be incorrect or incomplete due to slight variations between the different OSes.

## Fixes
* Added missing Argument Completer for Get-STIGVulnInfo 'Name' parameter
* Fixed logic checks: Server 2019 V-205696, V-205715, V-205906
* Corrected the value being checked: Server 2019 V-205906, Windows 10 V-220956, Windows 10 V-220958

## Changes
* Invoke-STIGChecker - Added variables containing the evaluation results of the following: Is a DomainController, Is a MemberServer, Is a Server Core installation
* Get-STIGComputerInfo - Added 'WindowsInstallationType' for evaluating type of installation
* Server 2019 - Completed the following checks:
    * V-205625, V-205626, V-205627, V-205629, V-205630, V-205633, V-205634, V-205635, V-205636, V-205637, V-205638, V-205639, V-205643, V-205644, V-205648, V-205649, V-205651, V-205652, V-205653, V-205654, V-205655, V-205656, V-205659, V-205660, V-205662, V-205676, V-205686, V-205687, V-205688, V-205689, V-205690, V-205691, V-205692, V-205693, V-205694, V-205696, V-205708, V-205709, V-205711, V-205712, V-205713, V-205714, V-205715, V-205722, V-205724, V-205725, V-205729, V-205730, V-205749, V-205750, V-205751, V-205752, V-205753, V-205754, V-205755, V-205756, V-205757, V-205758, V-205760, V-205762, V-205763, V-205764, V-205765, V-205766, V-205767, V-205768, V-205770, V-205771, V-205772, V-205773, V-205774, V-205775, V-205776, V-205777, V-205778, V-205779, V-205780, V-205781, V-205782, V-205783, V-205784, V-205795, V-205796, V-205797, V-205798, V-205801, V-205802, V-205804, V-205805, V-205806, V-205808, V-205809, V-205810, V-205814, V-205815, V-205816, V-205817, V-205819, V-205820, V-205821, V-205822, V-205823, V-205824, V-205825, V-205826, V-205827, V-205828, V-205830, V-205832, V-205833, V-205834, V-205835, V-205836, V-205837, V-205838, V-205839, V-205840, V-205841, V-205842, V-205848, V-205852, V-205856, V-205857, V-205858, V-205859, V-205860, V-205861, V-205862, V-205863, V-205865, V-205866, V-205867, V-205868, V-205869, V-205870, V-205871, V-205872, V-205873, V-205874, V-205876, V-205906, V-205907, V-205908, V-205909, V-205910, V-205911, V-205912, V-205913, V-205914, V-205915, V-205916, V-205917, V-205918, V-205919, V-205920, V-205921, V-205922, V-205923, V-205925
* Server 2016 - Completed the following checks:
    * V-224831, V-224837, V-224841, V-224842, V-224866, V-224867, V-224868, V-224869, V-224870, V-224871, V-224872, V-224873, V-224874, V-224881, V-224882, V-224884, V-224885, V-224886, V-224887, V-224888, V-224890, V-224892, V-224893, V-224894, V-224895, V-224896, V-224897, V-224898, V-224899, V-224900, V-224902, V-224903, V-224904, V-224905, V-224907, V-224908, V-224909, V-224910, V-224911, V-224912, V-224913, V-224914, V-224915, V-224916, V-224918, V-224919, V-224920, V-224921, V-224922, V-224924, V-224925, V-224926, V-224927, V-224928, V-224931, V-224932, V-224933, V-224934, V-224935, V-224936, V-224937, V-224938, V-224939, V-224941, V-224942, V-224943, V-224944, V-224945, V-224946, V-224947, V-224948, V-224949, V-224951, V-224952, V-224953, V-224954, V-224955, V-224956, V-224957, V-224958, V-224959, V-224960, V-224961, V-224962, V-224963, V-225008, V-225009, V-225010, V-225021, V-225022, V-225023, V-225024, V-225025, V-225026, V-225027, V-225028, V-225030, V-225031, V-225032, V-225033, V-225034, V-225035, V-225038, V-225041, V-225044, V-225045, V-225046, V-225047, V-225048, V-225050, V-225051, V-225052, V-225053, V-225054, V-225055, V-225056, V-225057, V-225059, V-225060, V-225061, V-225063, V-225065, V-225066, V-225067, V-225068, V-225070, V-225071, V-225072, V-225073, V-225074, V-225076, V-225077, V-225078, V-225079, V-225080, V-225082, V-225084, V-225085, V-225086, V-225087, V-225088, V-225089, V-225091, V-225092, V-225093

## Errata

# v0.2 (2022-04-08)
The largest change for this version was adding the framework for the Server 2016 and Server 2019 STIG checks. Also added was another function for viewing information about STIG IDs.

## Fixes
* Corrected the parameter name in the Argument Completer

## Changes
* Added scripts with the framework for the remaining Windows 10 STIGs
* Added scripts with the framework for the Server 2016 STIG
* Added scripts with the framework for the Server 2019 STIG
* Added version information for the included STIGs.

## Errata
* Formatting cleanup
# v0.1.1 (2022-02-06)
## Fixes
* Invoke-STIGChecker - Fixed incorrect parameter being used to import STIG Checker configuation file

## Changes
* Added additional checks
    * V-220716, V-220723, V-220730, V-220731, V-220908, V-220909, V-220911, V-220912, V-220928, V-220956, V-220957, V-220958, V-220959, V-220960, V-220961, V-220962, V-220963, V-220964, V-220965, V-220966

## Errata
* Cleaned up some formatting
# v0.1.0 (2022-02-05)
Initial release

This is not yet production ready. Some checks may be incomplete or return incorrect results.