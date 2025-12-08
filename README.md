
Όλα τα directories είναι τα σωστά και έτοιμα για χρήση
======================================================

Έχω ανεβάσει το σκριπτ που κάνει το filtering στους κανόνες καθώς και δύο directories.  Το directory 'rejected' έχει αρχεία .yar που απορρίφθηκαν από τον κώδικα ως ephemeral (12) και το accepted αυτά που έγιναν δεκτά (37), όλα αυτά από ένα σύνολο συνολικά 49 αρχείων. Προφανώς το τεστάρισμα του κώδικα δεν έγινε μόνο σε αυτά τα αρχεία απλά αυτό είναι το τελευταίο σύνολο αρχείων στο οποίο επέλεξα να κάνω το τελευταίο τεστ του σκριπτ προκειμένου να παρουσιάσω εδώ τα αποτελέσματα. Τα αποτελέσματα είναι αρκετά αντιπροσωπευτικά πιστεύω. 

Γενικότερα σε ένα μεγάλο σετ από 874 κανόνες το σκριπτ αυτό είχε ως output:

PROCESSING COMPLETE

Total files processed: 874

Files kept (original): 446

Files kept (filtered): 92

Files rejected: 523

Total rules analyzed: 12976

Rules kept: 10671

Overall keep rate: 61.6%


Το σκριπτακι έχει περάσει αρκετές μορφές πριν καταλήξει σε αυτή που βρίσκεται τώρα. Μετά από κάθε test σε τυχαία samples που έχω κατεβάσει από repos με yara rules, το διόρθωνα και το προσάρμοζα, βλέποντας τι κάνει accept και reject και αν έχει κάνει κάποιο accept ή reject χωρίς να έπρεπε. Στην αρχή είχα ξεχάσει να καθαρίζω το content από τα metadata με αποτέλεσμα να αναγνωρίζει ως 'κακό' χαρακτηριστικό domains ή links που υπήρχαν στο metadata section. Στην πορεία ωστόσο το διόρθωσα προσθέτωντας την αντίστοιχη συνάρτηση που καθαρίζει το rule_content από το metadata section.


Η πιο σημαντική συνάρτηση του κώδικα είναι η analyze_individual_rules() η οποία δέχεται ως παράμετρο ένα rule (όχι ένα ολόκληρο αρχείο, μόνο έναν κανόνα) και υπολογίζει τα code_indicators, τα οποία είναι χαρακτηριστικά ενός κανόνα που θέλουμε, αφού δείχνουν code_reuse κοινό dev env κτλ. Υπολογίζει και τα infra_indicators τα οποία είναι τα ephemeral χαρακτηριστικά. Πρόσθεσα αρκετές κατηγορίες έτσι ώστε για κάθε code_indicator που γίνεται match, το score να ανεβαινει και να είναι σίγουρο οτι θα γίνει αποδεκτός ο κανόνας από το πρόγραμμα. Όσα περισσότερα code_indicators, τόσο μεγαλύτερο το συνολικό σκορ. Όλες αυτές οι κατηγορίες προστέθηκαν σταδιακά μετά από αρκετά τεστ σε sample rules. Τα infra_indicators είναι αρκετά απλά και ξεκάθαρα. Στο τέλος υπολογίζουμε πόσα code_indicators και infra_indicators έχουμε για το rule το οποίο αναλύεται, και βγάζουμε το συμπέρασμα is_code_centric. Ο τρόπος με τον οποίο υπολογίζω την τιμή αυτής της μεταβλητής είναι λίγο αμφιλεγόμενος και μπορεί να χρειάζεται να γίνει πιο αυστηρός ή καλύτερα δομημένος.

Κρατάμε ολόκληρο το αρχείο εάν ΟΛΟΙ οι κανόνες που περιέχει είναι χρήσιμοι. Σε αντίθετη περίπτωση κρατάμε μόνος αυτούς που είναι χρήσιμους και του κάνουμε write σε ένα αρχείο .yar με το ίδιο όνομα αρχείου με αυτό από το οποίο προήλθαν.

Τέλος, έχω μαζέψει συνολικά 2553 αρχεία yara από τα repos:

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


