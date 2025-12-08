import re
import yara
from pathlib import Path

def get_yara_files(input_dir):

    yara_files = []
    #Μαζεύουμε όλα τα αρχεία με .yar & .yara
    yara_files.extend(Path(input_dir).rglob('*.yar'))
    yara_files.extend(Path(input_dir).rglob('*.YAR')) 
    yara_files.extend(Path(input_dir).rglob('*.yara'))
    yara_files.extend(Path(input_dir).rglob('*.YARA'))  
    
    #Βγάζουμε τα διπλότυπα (να υπάρχουν)
    return list(set(yara_files))

def extract_individual_rules(file_content):
    #σπαμε το αρχει σε κομματια με βαση τη λέξη rule που εμφανίζεται κάθε φορα. 
    #επειδή η λέξη μπορεί να υπάρχει και σε comments κάνουμε ένα 2ο πέρασμα με 
    #λουπ να ελέγξουμε τα brackets έτσι ώστε να αποφύγουμε τέτοιες περιπτώσεις.
    rules = []
    
    # Κανε σπλιτ με βάση το 'rule ' 
    raw_rules = file_content.split('rule ')[1:]  # Skip first empty
    
    #βρες τα όρια του κανόνα μέσω των brackets
    for rule_content in raw_rules:
        brace_count = 0
        end_index = 0
        
        for i, char in enumerate(rule_content):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_index = i + 1
                    break
        
        if end_index > 0:
            full_rule = 'rule ' + rule_content[:end_index]
            rule_name = rule_content.split('{')[0].strip()
            rules.append((rule_name, full_rule))
    
    return rules

def analyze_individual_rule(rule_content, rule_name):
    #Σε αυτό το σημείο γίνεται η ανάλυση του περιεχομένου του κανόνα: Πόσα 'χρήσιμα' indicators έχουμε
    #και πόσα ephemeral

    #τα 'καλα' indicators που θέλουμε να έχουν οι κανόνες
    code_indicators = {

        # hex patterns 
        'hex_patterns': len(re.findall(
            # Look for = { ... } but allow wildcards ?, parens (), pipes |, and jumps []
            r'=\s*\{[\s0-9A-Fa-f\?\|\(\)\[\]\-]{10,}\}', 
            rule_content, 
            re.MULTILINE
        )), 
        
        'long_hex_sequences': len(re.findall(
            r'((?:[0-9A-F]{2}|\?\?*) ){6,}', # Sequences of hex bytes (code reuse)
            rule_content,
            re.IGNORECASE
        )),

        # Εδω ειχα αλλο ένα regex αλλά το έβαλα στην άκρη γιατί είδα οτι δημιουργούσε κάποια false positves
        # 'complex_regexes': len(re.findall(
        #  r'"[^"]*?(?:\\d|\\[0-9a-zA-Z-]|\(\?![^)]*\)|[?*+]{2,}|\{,\d+\}|\{\d+,\d*\}|\\u[0-9a-fA-F]{4})[^"]*?"', 
        #  rule_content
        #)),

        # PE ELF κτλ κτλ
        'binary_structure': len(re.findall(
            r'(pe\.(sections|imports|characteristics|timestamp|entry_point)|'
            r'elf\.(sections|segments|dynamic|symtab)|'
            r'macho\.|'
            r'uint16\(0\)|uint32\(0\)|' # File magic checks
            r'entrypoint|filesize|'
            r'\.rdata|\.pdata|\.text|\.CRT|\.tls|\.data|'
            r'_init|_start|_fini|DllMain|ServiceMain)',
            rule_content, re.IGNORECASE)),

        # compiler artifacts
        'compiler_artifacts': len(re.findall(
            r'\b(MSVC|Visual C\+\+|Microsoft Visual|GCC|GNU C|Clang|Borland|Delphi|'
            r'linker|compiler|'
            r'__cdecl|__stdcall|__thiscall|'
            r'\.eh_frame|\.gcc_except_table|'
            r'vtable|RTTI|typeinfo)\b',
            rule_content, re.IGNORECASE)),

        # import tables & API
        'imports_and_apis': len(re.findall(
            r'\b(kernel32|advapi32|ntdll|ws2_32|wininet|shell32|'
            r'GetProcAddress|LoadLibrary|VirtualAlloc|CreateThread|'
            r'WriteProcessMemory|CreateRemoteThread|'
            r'ptrace|fork|execve|socket|connect|bind)\b',
            rule_content, re.IGNORECASE)),

        # packers
        'obfuscation_packers': len(re.findall(
            r'\b(UPX|ASPack|Themida|VMProtect|MPRESS|PECompact|Nullsoft|NSIS)\b',
            rule_content, re.IGNORECASE)),

        # αυτό το πρόσθεσα αφού μιλήσαμε και είπαμε να κρατήσουμε και για άλλα αρχεία πέρα από binaries
        'doc_script_logic': len(re.findall(
            r'(\/JavaScript|\/JS|\/OpenAction|\/AA|\/AcroForm|' # PDF
            r'\/EmbeddedFile|\/RichMedia|' 
            r'AutoOpen|Document_Open|Shell|CreateObject|' # Office
            r'WScript\.Shell|PowerShellRunner|'
            r'eval\(|unescape|base64_decode|fromCharCode|' # JS
            r'ActiveXObject|XMLHttpRequest|'
            r'\$_\w+|function\s*\(|' 
            r'Invoke-Expression|IEX|New-Object|DownloadString|' # PS1
            r'\/bin\/sh|\/bin\/bash|chmod\s+\+x|wget|curl)', # Bash
            rule_content, re.IGNORECASE)),

        # αλλά κοινά strings 
        'behavioral_strings': len(re.findall(
            r'\b(mutex|mutant|BaseNamedObjects|'
            r'config|cfg|cipher|key|nonce|'
            r'callback|command|payload)\b',
            rule_content, re.IGNORECASE)),
            
        #άλλο ένα regex που πρόσθεσα για να μπορούν να κάνουν match και τα regex που 
        #υπάρχουν στους κανόνες
        'regex_strings' : len(re.findall(
            r'\[.*?\]|\\d\{.*?\}|\\[Ds]|RegExpr|REGEXEND|regex',
            rule_content, re.IGNORECASE)),

    }
    
    #ephemeral και generic κανόνες
    infra_indicators = {
        'ips': len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', rule_content)),
        'urls': len(re.findall(r'https?://[^\s]+', rule_content)),
        'domains': len(re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', rule_content)), #- code_indicators['compiler_artifacts'],
        'file_paths': len(re.findall(r'[a-zA-Z]:\\[^ ]+|(?:\\[a-zA-Z0-9_]+)+\.[a-zA-Z]+|\/[a-zA-Z0-9_/-]+\.[a-z]+', rule_content)),
        'ephemeral_file_extensions': len(re.findall(
            r'"[^"\\/]*\.(exe|dll|bat|cmd|ps1|vbs|txt|doc|docx|xls|xlsx|pdf|jpg|png|zip|rar|7z)"', 
            rule_content, 
            re.IGNORECASE
        )),
    }
    
    #υπολογίζομε τα σκορ
    code_score = sum(code_indicators.values())
    infra_penalty = sum(infra_indicators.values())

    #κρατάμε τον κανόνα αν ισχύουν:
    is_code_centric = ((code_score>=3 and infra_penalty<=1) or (code_score>=2 and infra_penalty==0) or (code_score >= infra_penalty*2+1))    

    
    return {
        'keep_rule': is_code_centric,
        'rule_name': rule_name,
        'code_score': code_score,
        'infra_penalty': infra_penalty, 
        'details': {
            'code_indicators': code_indicators,
            'infra_indicators': infra_indicators
        }
    }

def should_keep_entire_file(rule_analyses):
    if not rule_analyses:
        return False
    
    good_rules = sum(1 for analysis in rule_analyses if analysis['keep_rule'])
    total_rules = len(rule_analyses)
    
    # Στην αρχή είχα επιλέξει να κρατάμε όλο το αρχείο αν πάνω απο το 80% των κσνόνων ειναι χρήσιμοι, αλλά εφόσον
    # τους χρήσιμους κανόνες τελικά τους ξαναγράφουμε σε ξεχωριστά ομώνυμα αρχεία, σκέφτηκα οτι δεν υπήρχε λόγος
    # για κάτι τέτοι. Οπότε κρατάμε όλο το αρχείο μόνο αν ΟΛΟΙ οι κανόνες είναι καλοι
    return (good_rules == total_rules)

    
def remove_meta_section(rule_content):
    #Αυτό προστέθηκε μετά από κάποιες δοκιμές γιατί παρατήρησα πως πολλοί κανόνες απορρίπτονταν
    # επειδή είχαν urls στο meta section τους
    meta_pattern = r'(\s*)meta:\s*(\n\s*[^\n]*)*?(\s*(?:strings:|condition:|\}))'
    
    def replace_meta(match):
        return match.group(1) + match.group(3)
    
    # αντικατάσταση του meta section
    result = re.sub(meta_pattern, replace_meta, rule_content, flags=re.DOTALL | re.IGNORECASE)
    return result

def has_valuable_rules(rule_analyses):
    #τσεκάρουμε αν το αρχείο έχει κανόνες χρήσιμους για εξαγωγή σε εξωτερικό αρχέιο
    good_rules = sum(1 for analysis in rule_analyses if analysis['keep_rule'])
    return good_rules >= 1 




def process_yara_files(input_dir, output_dir):
    
    Path(output_dir).mkdir(exist_ok=True)
    
    stats = {
        'total_files': 0,
        'files_kept_original': 0,
        'files_kept_filtered': 0,
        'files_rejected': 0,
        'total_rules': 0,
        'rules_kept': 0
    }
    
    yara_files = get_yara_files(input_dir)
    
    print(f"Found {len(yara_files)} YARA files (.yar and .yara)")

    for yara_file in yara_files:

        stats['total_files'] += 1

        #Ξεχωρίζουμε απο τον τίτλο αν ο κανόνας αφορά APT group και
        #αν ναι, κατευθειάν τον απορρίπτουμε
        if 'APT' in yara_file.name:
            stats['files_rejected'] += 1
            print(f"---X--- REJECTED (Filename): {yara_file.name} (Contains 'APT')")
            continue
        #print(f"Processing {yara_file}...")

        
        try:
            with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            rules = extract_individual_rules(content)
            stats['total_rules'] += len(rules)
            
            #αν το αρχείο δεν έχει κανένα κανόνα (δηλαδη ελλατωματικό)
            if not rules:
                stats['files_rejected'] += 1
                print(f"---X--- REJECTED: {yara_file.name} (no rules found)")
                continue
            
            rule_analyses = []
            for rule_name, rule_content in rules:
                clear_rule = remove_meta_section(rule_content)
                analysis = analyze_individual_rule(clear_rule, rule_name)
                rule_analyses.append(analysis)
            
           
            if should_keep_entire_file(rule_analyses):
                # Κρατάμε όλο το αρχείο (δηλ. όλοι οι κανόνες μας κάνουν)
                output_path = Path(output_dir) / yara_file.name
                with open(output_path, 'w') as f:
                    f.write(content)
                stats['files_kept_original'] += 1
                stats['rules_kept'] += len(rules)
                print(f"---OK!--- KEPT ORIGINAL: {yara_file.name} (all {len(rules)} rules)")
            elif has_valuable_rules(rule_analyses):
                #Αν ΔΕΝ είναι όλοι οι κανόνες χρήσιμοι, ξαναγράφουμε σε ομώνυμα αρχεία ΜΟΝΟ τους χρήσιμους
                kept_rules = [
                    rule_content for (rule_name, rule_content), analysis 
                    in zip(rules, rule_analyses) 
                    if analysis['keep_rule']
                ]
                if kept_rules:
                    output_path = Path(output_dir) / yara_file.name
                    with open(output_path, 'w') as f:
                        f.write('\n\n'.join(kept_rules))
                    stats['files_kept_filtered'] += 1   
                    stats['rules_kept'] += len(kept_rules)
                    # πόσοι 'καλοί' κανόνες βρέθηκαν μέσα σε όλο το αρχείο 
                    print(f"---OK!--- KEPT FILTERED: {yara_file.name} ({len(kept_rules)}/{len(rules)} rules)")
            else:
                stats['files_rejected'] += 1
                actual_good_count = sum(1 for a in rule_analyses if a['keep_rule'])               
                print(f"---X--- REJECTED: {yara_file.name} ({actual_good_count}/{len(rules)} good rules)")
                reject_path = Path('path/to/reject/directory') / yara_file.name
                with open(reject_path,'w') as r:
                        r.write(content)

                    
        except Exception as e:
            print(f"Error processing {yara_file}: {e}")
            stats['files_rejected'] += 1
    
    print(f"\n{'='*50}")
    print(f"RESULTS")
    print(f"{'='*50}")
    print(f"Total files processed: {stats['total_files']}")
    print(f"Files kept (original): {stats['files_kept_original']}")
    print(f"Files kept (filtered): {stats['files_kept_filtered']}")
    print(f"Files rejected: {stats['files_rejected']}")
    print(f"Total rules analyzed: {stats['total_rules']}")
    print(f"Rules kept: {stats['rules_kept']}")
    
    if stats['total_files'] > 0:
        keep_rate = (stats['files_kept_original'] + stats['files_kept_filtered']) / stats['total_files'] * 100
        print(f"Overall keep rate: {keep_rate:.1f}%")
    
    return stats

if __name__ == "__main__":
    input_directory = 'path/to/input/directory'
    output_directory = 'path/to/output/directory'
    
    stats = process_yara_files(
        input_directory, 
        output_directory
    )









    