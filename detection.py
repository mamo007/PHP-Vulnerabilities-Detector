import os
import re
import math
from indicators import *
from functions import *

result_count = 0
result_files = 0

# Analyse the source code of a single page
def analysis(path, plain):
    global result_count
    global result_files
    result_files += 1
    with open(path, 'r', encoding='utf-8', errors='replace') as content_file:

        # Clean source for a better detection
        content = content_file.read()
        content = clean_source_and_format(content)
                 
        # Detection of RCE/SQLI/LFI/RFI/RFU/XSS/...
        for payload in payloads:
            regex = re.compile(payload[0] + regex_indicators)
            matches = regex.findall(content.replace("", "")) # (PLACEHOLDER

            for vuln_content in matches:

                # Handle "require something" vs "require(something)"
                #vuln_content = list(vuln_content)
                #for i in range(len(vuln_content)):
                #    vuln_content[i] = vuln_content[i].replace("(PLACEHOLDER", " ")
                #    vuln_content[i] = vuln_content[i].replace("PLACEHOLDER", "")

                occurence = 0

                # Security hole detected, is it protected ?
                if not check_protection(payload[2], vuln_content):
                    declaration_text, line = "", ""

                    # Managing multiple variable in a single line/function
                    sentence = "".join(vuln_content)
                    regex = re.compile(regex_indicators[2:-2])
                    for vulnerable_var in regex.findall(sentence):
                        false_positive = False
                        occurence += 1

                        # No declaration for $_GET, $_POST ...
                        if not check_exception(vulnerable_var[1]):
                            # Look for the declaration of $something = xxxxx
                            false_positive, declaration_text, line = check_declaration(
                                content,
                                vulnerable_var[1],
                                path)

                            # Set false positive if protection is in the variable's declaration
                            is_protected = check_protection(payload[2], declaration_text)
                            false_positive = is_protected if is_protected else false_positive

                        # Display all the vuln
                        line_vuln = find_line_vuln(payload, vuln_content, content)

                        # Check for not $dest="constant"; $dest='cste'; $dest=XX;
                        if "$_" not in vulnerable_var[1]:
                            if "$" not in declaration_text.replace(vulnerable_var[1], ''):
                                false_positive = True

                        if not false_positive:
                            result_count = result_count + 1
                            display(path, payload, vuln_content, line_vuln, declaration_text, line, vulnerable_var[1], occurence, plain)


# Run thru every files and subdirectories
def recursive(dir, progress, plain):
    progress += 1
    progress_indicator = '⬛'
    if plain:
        progress_indicator = "█"
    try:
        for name in os.listdir(dir):

            print('\tAnalyzing : ' + progress_indicator * progress + '\r', end="\r"),

            # Targetting only PHP Files
            if os.path.isfile(os.path.join(dir, name)):
                if ".php" in os.path.join(dir, name):
                    analysis(dir + "/" + name, plain)
            else:
                recursive(dir + "/" + name, progress, plain)

    except OSError as e:
        print("Error 404 - Not Found, maybe you need more right ?" + " " * 30)
        exit(-1)


# Display basic informations about the scan
def scanresults():
    global result_count
    global result_files
    print("Found {} vulnerabilities in {} files".format(result_count, result_files))