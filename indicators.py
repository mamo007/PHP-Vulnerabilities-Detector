# /!\ Detection Format (.*)function($vuln)(.*) matched by payload[0]+regex_indicators
regex_indicators = '\\((.*?)(\\$_GET\\[.*?\\]|\\$_FILES\\[.*?\\]|\\$_POST\\[.*?\\]|\\$_REQUEST\\[.*?\\]|\\$_COOKIES\\[.*?\\]|\\$_SESSION\\[.*?\\]|\\$(?!this|e-)[a-zA-Z0-9_]*)(.*?)\\)'

# Descriptions
cmdExc_Desc = "An attacker might execute arbitrary system commands with this vulnerability. User tainted data is used when creating the command that will be executed on the underlying operating system. This vulnerability can lead to full server compromise."
LFI_Desc = "An attacker might include local or remote PHP files or read non-PHP files with this vulnerability. User tainted data is used when creating the file name that will be included into the current file. PHP code in this file will be evaluated, non-PHP code will be embedded to the output. This vulnerability can lead to full server compromise."
SQL_Desc = "An attacker might execute arbitrary SQL commands on the database server with this vulnerability. User tainted data is used when creating the database query that will be executed on the database management system (DBMS). An attacker can inject own SQL syntax thus initiate reading, inserting or deleting database entries or attacking the underlying operating system depending on the query, DBMS and configuration."
FileU_Desc = "An attacker might write to arbitrary files or inject arbitrary code into a file with this vulnerability. User tainted data is used when creating the file name that will be opened or when creating the string that will be written to the file. An attacker can try to write arbitrary PHP code in a PHP file allowing to fully compromise the server."
XSS_Desc = "An attacker might execute arbitrary HTML/JavaScript Code in the clients browser context with this security vulnerability. User tainted data is embedded into the HTML output by the application and rendered by the users browser, thus allowing an attacker to embed and render malicious code. Preparing a malicious link will lead to an execution of this malicious code in another users browser context when clicking the link. This can lead to local website defacement, phishing or cookie stealing and session hijacking."
Header_Desc = "An attacker can inject arbitrary headers to the HTTP response header. This can be abused for a redirect when injecting a ( Location: ) header or help within a session fixation attack when the ( Set-Cookie: ) header is added. Additionally, the HTTP response can be overwritten and JavaScript can be injected leading to Cross-Site Scripting attacks. In PHP version below 4.4.2 or 5.1.2 the characters \n\r (LF CR) can be used for header line termination (cross-browser). In PHP below 5.4 the character \r (CR) can still be used for header line termination (Chrome, IE)."

# Patchs
cmdExc_Patch = "Limit the code to a very strict character subset or build a whitelist of allowed commands. Do not try to filter for evil commands. Try to avoid the usage of system command executing functions if possible."
LFI_Patch = "Build a whitelist for positive file names. Do not only limit the file name to specific paths or extensions."
SQL_Patch = "Always embed expected strings into quotes and escape the string with a PHP buildin function before embedding it to the query. Always embed expected integers without quotes and typecast the data to integer before embedding it to the query. Escaping data but embedding it without quotes is not safe."
FileU_Patch = "Build a whitelist for positive file names. Do not only limit the file name to specific paths or extensions. If you write into PHP files make sure an attacker can not write own PHP code. Use a whitelist with arrays or regular expressions (e.g. alphanumeric only)."
XSS_Patch = "Encode all user tainted data with PHP buildin functions before embedding the data into the output. Make sure to set the parameter ENT_QUOTES to avoid an eventhandler injections to existing HTML attributes and specify the correct charset."
Header_Patch = "Update PHP to prevent header injection or implement a whitelist."

# Function_Name:String, Vulnerability_Name:String, Protection_Function:Array, Vulnerabilitiy_Description: String, Vulnerability_Patch: String
payloads = [

    # Remote Command Execution
    ["eval", "Code Injection / Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["popen", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["popen_ex", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["system", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["passthru", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["exec", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["shell_exec", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["pcntl_exec", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["assert", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["proc_open", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["expect_popen", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["create_function", "Remote Command Execution", ["escapeshellarg", "escapeshellcmd"], cmdExc_Desc, cmdExc_Patch],
    ["call_user_func", "Remote Code Execution", [], cmdExc_Desc, cmdExc_Patch],
    ["call_user_func_array", "Remote Code Execution", [], cmdExc_Desc, cmdExc_Patch],
    ["preg_replace", "Remote Command Execution", ["preg_quote"], cmdExc_Desc, cmdExc_Patch],
    ["ereg_replace", "Remote Command Execution", ["preg_quote"], cmdExc_Desc, cmdExc_Patch],
    ["eregi_replace", "Remote Command Execution", ["preg_quote"], cmdExc_Desc, cmdExc_Patch],
    ["mb_ereg_replace", "Remote Command Execution", ["preg_quote"], cmdExc_Desc, cmdExc_Patch],
    ["mb_eregi_replace", "Remote Command Execution", ["preg_quote"], cmdExc_Desc, cmdExc_Patch],

    # File Inclusion / Path Traversal
    ["virtual", "File Inclusion", [], LFI_Desc, LFI_Patch],
    ["include", "File Inclusion", [], LFI_Desc, LFI_Patch],
    ["require", "File Inclusion", [], LFI_Desc, LFI_Patch],
    ["include_once", "File Inclusion", [], LFI_Desc, LFI_Patch],
    ["require_once", "File Inclusion", [], LFI_Desc, LFI_Patch],

    ["readfile", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["file_get_contents", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["file_put_contents", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["show_source", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["fopen", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["file", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["fpassthru", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["gzopen", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["gzfile", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["gzpassthru", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["readgzfile", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    
    ["DirectoryIterator", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["stream_get_contents", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],
    ["copy", "File Inclusion / Path Traversal", [], LFI_Desc, LFI_Patch],

    # MySQL(i) SQL Injection
    ["mysql_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_multi_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_send_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_master_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_master_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysql_unbuffered_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysql_db_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli::real_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_real_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli::query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],
    ["mysqli_query", "SQL Injection", ["mysql_real_escape_string"], SQL_Desc, SQL_Patch],

    # PostgreSQL Injection
    ["pg_query", "SQL Injection", ["pg_escape_string", "pg_pconnect", "pg_connect"], SQL_Desc, SQL_Patch],
    ["pg_send_query", "SQL Injection", ["pg_escape_string", "pg_pconnect", "pg_connect"], SQL_Desc, SQL_Patch],

    # SQLite SQL Injection
    ["sqlite_array_query", "SQL Injection", ["sqlite_escape_string"], SQL_Desc, SQL_Patch],
    ["sqlite_exec", "SQL Injection", ["sqlite_escape_string"], SQL_Desc, SQL_Patch],
    ["sqlite_query", "SQL Injection", ["sqlite_escape_string"], SQL_Desc, SQL_Patch],
    ["sqlite_single_query", "SQL Injection", ["sqlite_escape_string"], SQL_Desc, SQL_Patch],
    ["sqlite_unbuffered_query", "SQL Injection", ["sqlite_escape_string"], SQL_Desc, SQL_Patch],

    # PDO SQL Injection
    ["->arrayQuery", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->query", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->queryExec", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->singleQuery", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->querySingle", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->exec", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->execute", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->unbufferedQuery", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->real_query", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->multi_query", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],
    ["->send_query", "SQL Injection", ["->prepare"], SQL_Desc, SQL_Patch],

    # Cubrid SQL Injection
    ["cubrid_unbuffered_query", "SQL Injection", ["cubrid_real_escape_string"], SQL_Desc, SQL_Patch],
    ["cubrid_query", "SQL Injection", ["cubrid_real_escape_string"], SQL_Desc, SQL_Patch],

    # MSSQL SQL Injection : Warning there is not any real_escape_string
    ["mssql_query", "SQL Injection", ["mssql_escape"], SQL_Desc, SQL_Patch],

    # File Upload
    ["move_uploaded_file", "File Upload", [], FileU_Desc, FileU_Patch],

    # Cross Site Scripting
    ["print", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["printf", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["vprintf", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["trigger_error", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["user_error", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["odbc_result_all", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["ifx_htmltbl_result", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["die", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["exit", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],
    ["var_dump", "Cross Site Scripting", ["htmlentities", "htmlspecialchars"], XSS_Desc, XSS_Patch],

    # Header Injection
    ["header", "Header Injection", [], Header_Desc, Header_Patch],
    ["HttpMessage::setHeaders", "Header Injection", [], Header_Desc, Header_Patch],
    ["HttpRequest::setHeaders", "Header Injection", [], Header_Desc, Header_Patch],

    # URL Redirection
    ["http_redirect", "URL Redirection", [], "Not Found", "Not Found"],
    ["HttpMessage::setResponseCode", "URL Redirection", [], "Not Found", "Not Found"],
]
