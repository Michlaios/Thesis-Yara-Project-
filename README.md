Update 20-04-2026
=================
I have runned the script in the final large dataset of 3119 Yara rules that have been gathered from the public repos shown at the end of this README. You can find the final dataset of the 1719 that passed the filtering in the "full_filtered_rules_dataset" folder of this repo. The output of the script was : 


RESULTS
==================================================

Total files processed: 3119

Files kept (original): 1370

Files kept (filtered): 349

Files rejected: 1400

Overall keep rate: 55.1%



This repo
=========

In this repo I have uploaded the script that filters the yara rules that I have gathered so far. There are also two directories. The directory 'rejected' includes .yar files which were rejected by the script as ephemeral (12 files). The accepted direcotry includes the ones that passed the criteria (37 files). The script checked a total of 49 files. Obviously the script was not tested at only 49 files. This is just a small subset of the files I have gathered, in which I chose to run the script, in order to present its results here. I thought it would be easier to see which files were accepted and rejected out of a total of 49 files, than 2.500. 

In a testing on a bit larger set of 874 rules, the script gave the results:

PROCESSING COMPLETE

Total files processed: 874

Files kept (original): 446

Files kept (filtered): 92

Files rejected: 523

Total rules analyzed: 12976

Rules kept: 10671

Overall keep rate: 61.6%

The metadata correction
=======================
The code has been through many changes and tests on subsets before reaching its final structure. After each test on random .yar file sets, I improved the scoring logic and the scoring criteria according on false positives or negatives (rejected a file or accepted a file when it shouldn't). At first I had forgotten to clean the rule content from the metadata section, therefore the script was matching as 'ephemeral' artifacts domains or links that existed in the metadata section. I solved that problem by introducing a funtion which removes the metadata section from the rule content.

The analyze_individual_rule() function
======================================

The most important function of the script is the analyze_individual_rule(), which accepts as parameter a rule (NOTE: not a .yar file! Just a rule! A .yar (or .yara) file might contain more than 1 yara rule) and calculates the number of code_indicators, which are desirable artifacts for a rule to have, since they indicate code reuse, similar dev env etc. It also calculates the value of infra_indicators which are mostly ephemeral or in general artifacts that we do not want our rules to have. I added many different types of possible code_indicators so that the script will add as many point as possible for any indicator that we are interested in (always with precautions in order to avoid false positives). All these different types of indicators were dded to the script after testing it on samples. At the end, we compare the values of the code_indicators and infra_indicators that a rule content has and we conclude whether it is code_centric or not. The scoring of the is_code_centric might be prone to false positives or false negatives so please I would appreciate any comments or corrections you might have. 

The keep/reject file criterion
==============================
We keep the WHOLE .yar file if every single rule in that file is useful for our purpose. In any other case we keep just the useful rules inside a .yar file and we rewrite only these useful rules in a new .yar file with the same name. So basically keep the file and discard all the useless rules inside of it


The rules I have so far
=======================
Lastly I have gathered a total of 3.119 yara files from the public repos:

https://github.com/reversinglabs/ reversinglabs-YARA-rules 

https://github.com/InQuest/awesome-YARA 

https://gist.github.com/pedramamini/c586a151a978f971b70412ca4485c491 

https://github.com/bartblaze/YARA-rules 

https://github.com/airbnb/binaryalert

https://github.com/codewatchorg/Burp-YARA-Rules 

https://github.com/kevoreilly/CAPEv2

https://github.com/CyberDefenses/CDI_YARA 

https://github.com/citizenlab/malware-signatures 

https://github.com/MalGamy/YARA_Rules 

https://github.com/kevoreilly/CAPE 

https://github.com/stvemillertime/ConventionEngine 

https://github.com/deadbits/YARA-rules 

https://github.com/elastic/protections-artifacts

https://github.com/mandiant/red_team_tool_countermeasures 

https://github.com/Neo23x0/signature-base

https://github.com/Yara-Rules/rules


