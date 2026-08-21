#!/usr/bin/env python3
import os
import sys
import re
import json
import subprocess
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

# Constants for Rule IDs
RULE_COMPILATION = "Rule-1.1-Compilation-Failure"
RULE_SQL_INJECTION = "Rule-1.2-SonarQube-SQL-Injection"
RULE_UNUSED_DEPENDENCY = "Rule-1.4-Unused-Dependency"
RULE_SNAPSHOT_VERSION = "Rule-1.5-Snapshot-Version"
RULE_VERSION_BUMP = "Rule-1.6-Version-Bump"

RULE_LOMBOK_DI = "Rule-3.1-Lombok-Dependency-Injection"
RULE_CIRCULAR_DEP = "Rule-3.2-Circular-Spring-Dependency"
RULE_TRANSACTIONAL = "Rule-3.3-Transactional-Visibility"
RULE_CTOR_LOGIC = "Rule-3.4-Constructor-Business-Logic"

RULE_SECRETS = "Rule-4.1-No-Secrets"
RULE_WRAPPER_EQ = "Rule-4.4-Wrapper-Comparison"
RULE_LAZY_EQUALS = "Rule-4.5-Equals-HashCode-Lazy"
RULE_TRY_WITH_RESOURCES = "Rule-4.6-Try-With-Resources"
RULE_FINALLY_RETURN = "Rule-4.7-Finally-Return"

RULE_CHANGED_BEHAVIOR_TESTS = "Rule-1.3-Changed-Behavior-Tests"
RULE_SONAR_MAJOR_JUSTIFICATION = "Rule-1.7-Sonar-Major-Justification"
RULE_PIN_DEPENDENCY_VERSIONS = "Rule-1.8-Pin-Dependency-Versions"
RULE_DOCUMENT_NEW_PROPERTIES = "Rule-1.9-Document-New-Properties"
RULE_UNCOMMON_ABBREVIATIONS = "Rule-2.7-Uncommon-Abbreviations"
RULE_SERVICE_DAO_INTERFACE_IMPL = "Rule-2.8-Service-DAO-Interface-Impl"
RULE_MAGIC_VALUES = "Rule-2.9-No-Magic-Values"
RULE_ENUM_FIXED_VALUES = "Rule-2.10-Prefer-Enum-Fixed-Values"
RULE_LONG_LITERAL_SUFFIX = "Rule-2.11-Long-Literal-Suffix"
RULE_CLASS_SUFFIXES = "Rule-2.12-Class-Suffixes"
RULE_BOOLEAN_NAMING = "Rule-2.13-Boolean-Lombok-Jackson-Naming"
RULE_PREFER_SLF4J = "Rule-3.5-Prefer-Slf4j"
RULE_LOMBOK_DTOS = "Rule-3.6-Lombok-DTOs"
RULE_BEAN_ALL_ARGS_CTOR = "Rule-3.7-Bean-All-Args-Constructor"
RULE_ASYNC_SCHEDULED_FAILURE = "Rule-3.8-Async-Scheduled-Failure"
RULE_ACCESS_STATIC_VIA_CLASS = "Rule-4.9-Access-Static-Via-Class"
RULE_DEPRECATED_APIS = "Rule-4.10-Deprecated-APIs"
RULE_NULL_SAFE_EQUALITY = "Rule-4.11-Null-Safe-Equality"
RULE_DTO_WRAPPERS = "Rule-4.12-DTO-Wrappers"
RULE_STRINGBUILDER_IN_LOOPS = "Rule-4.13-StringBuilder-In-Loops"
RULE_TIGHTEST_VISIBILITY = "Rule-4.14-Tightest-Visibility"
RULE_BREAK_METHOD_SIGNATURE = "Rule-4.15-Break-Method-Signature"
RULE_COLLECTION_CAPACITY = "Rule-5.8-Collection-Capacity"
RULE_ITERATE_MAP_ENTRYSET = "Rule-5.9-Iterate-Map-EntrySet"
RULE_SPRING_SINGLETON_VS_DCL = "Rule-5.10-Spring-Singleton-Bean"
RULE_THREADLOCAL_RANDOM = "Rule-5.11-ThreadLocalRandom"
RULE_NESTING_LEVEL = "Rule-6.3-Limit-Nesting"
RULE_COMPLEX_BOOLEAN = "Rule-6.4-Complex-Boolean"
RULE_HTTP_VERB_SEMANTICS = "Rule-7.9-HTTP-Verb-Semantics"
RULE_PROPER_STATUS_CODES = "Rule-7.10-Proper-Status-Codes"
RULE_THIN_CONTROLLERS = "Rule-7.11-Thin-Controllers"
RULE_ERROR_ENVELOPE_STACK_TRACE = "Rule-7.12-Error-Envelope-No-Stack-Trace"
RULE_PAGINATE_LISTS = "Rule-7.13-Paginate-List-Endpoints"
RULE_AVOID_N_PLUS_ONE = "Rule-8.6-Avoid-N-Plus-One"
RULE_NAMED_PARAMS_IN_QUERY = "Rule-8.7-Named-Params-In-Query"
RULE_PROJECTIONS_FOR_SEARCH = "Rule-8.8-Projections-For-Search"
RULE_PREFER_JPQL_CRITERIA = "Rule-8.9-Prefer-JPQL-Criteria"
RULE_NATIVE_SQL_EXPLICIT_COLUMNS = "Rule-8.10-Native-SQL-Explicit-Columns"
RULE_TRANSACTIONAL_READONLY = "Rule-8.11-Transactional-ReadOnly"
RULE_NO_TRANSACTION_REMOTE_IO = "Rule-8.12-No-Transaction-Remote-IO"
RULE_AVOID_SELF_INVOCATION = "Rule-8.13-Avoid-Self-Invocation"
RULE_AVOID_GENERIC_UPDATE = "Rule-8.14-Avoid-Generic-Update"
RULE_MAP_IS_COLUMNS = "Rule-8.15-Map-Is-Columns"
RULE_SWALLOW_EXCEPTION = "Rule-9.2-Swallow-Exception"
RULE_LOG_EXC_GET_MESSAGE = "Rule-9.3-Log-Exception-Get-Message"
RULE_CATCH_NPE_INDEX = "Rule-9.4-Catch-NPE-Index"
RULE_TRY_CATCH_SCOPE = "Rule-9.5-Try-Catch-Scope"
RULE_PREFER_APPLICATION_EXCEPTION = "Rule-9.6-Prefer-Application-Exception"
RULE_NO_PRINT_STACK_TRACE = "Rule-9.7-No-Print-Stack-Trace"
RULE_BRACE_SPACING = "Rule-11.1-Brace-Spacing"
RULE_MAX_LINE_LENGTH = "Rule-11.2-Max-Line-Length"
RULE_UTF8_ENCODING = "Rule-11.3-UTF8-Encoding"
RULE_MANUAL_ALIGNMENT = "Rule-11.4-Manual-Variable-Alignment"
RULE_HYGIENE_WHITESPACE = "Rule-11.5-Hygiene-Whitespace"
RULE_COMMENTED_CODE = "Rule-12.3-Commented-Code-Jira"
RULE_TODO_JIRA = "Rule-12.4-Todo-Fixme-Jira"
RULE_LAYER_PACKAGE = "Rule-13.1-Layer-Package"
RULE_TYPE_SUFFIXES = "Rule-13.2-Type-Suffixes"
RULE_LOOP_DB_CALLS = "Rule-14.1-Loop-DB-Calls"
RULE_CACHING_KEYS = "Rule-14.2-Caching-Keys"
RULE_COMMIT_HYGIENE = "Rule-15.1-Commit-Hygiene"
RULE_PR_TITLE_HYGIENE = "Rule-15.2-PR-Title-Hygiene"
RULE_PR_DESC_HYGIENE = "Rule-15.3-PR-Desc-Hygiene"
RULE_TESTS_DETERMINISTIC = "Rule-16.3-Tests-Deterministic"
RULE_DOMAIN_FIXTURES = "Rule-16.4-Domain-Fixtures"
RULE_SPRING_BOOT_TEST_RESERVE = "Rule-16.5-SpringBootTest-Reserve"
RULE_PREFER_TYPED_DTO = "Rule-17.16-Pojo-Vo-Dto-Roles"
RULE_CORE_AUTHENTICATED_USER = "Rule-17.17-AuthenticatedUser-Fork"
RULE_MESSAGE_Q_ROUTER = "Rule-17.19-RabbitTemplate-Direct"
RULE_NO_DAO_IN_CONTROLLER = "Rule-17.21-No-DAO-In-Controller"
RULE_MUTABLE_STATIC_MAPS = "Rule-17.22-Mutable-Static-Maps"
RULE_JAVA_11_COMPAT = "Rule-17.23-Java11-Language-APIs"
RULE_YES_NO_FLAGS = "Rule-17.24-Yes-No-Constants"
RULE_CONSTANT_FIRST_EQUAL = "Rule-17.25-Constant-First-Equals"
RULE_MULTIPART_FORMAT_CHECK = "Rule-17.28-Multipart-Format-Check"
RULE_JPA_GETTER_SETTER_ONLY = "Rule-17.30-Jpa-Getter-Setter-Only"
RULE_DTO_BOOLEAN_WRAPPER = "Rule-17.31-Dto-Boolean-Wrapper"
RULE_LOG_CONTEXT_IDS = "Rule-17.32-Log-Context-Ids"
RULE_DB_SQL_SAFE_UPDATES = "Rule-DB-1-SQL-Safe-Updates"
RULE_DB_UPDATE_USER_TIMESTAMP = "Rule-DB-2-Update-User-Timestamp"
RULE_DB_CHANGESET_UNIQUE_ID = "Rule-DB-3-Changeset-Unique-Id"
RULE_DB_NO_DELIMITER = "Rule-DB-4-No-Delimiter"
RULE_DB_CHANGESET_PATH_MATCH = "Rule-DB-5-Changeset-Path-Match"
RULE_DB_NO_SECRETS = "Rule-DB-6-No-Secrets"
RULE_DB_DROP_PAIRED = "Rule-DB-7-Drop-Paired"
RULE_DB_CREATE_OR_REPLACE = "Rule-DB-2.1-Create-Or-Replace"
RULE_DB_SELECT_INTO_EXCEPTION = "Rule-DB-3.1-Select-Into-Exception"
RULE_DB_DROP_PK_INDEX = "Rule-DB-4.4-Drop-PK-Index"
RULE_DB_NO_SELF_JOIN = "Rule-DB-4.11-No-Self-Join"
RULE_DB_NULL_INEQUALITY = "Rule-DB-5.1-Null-Inequality"
RULE_DB_TERMINATE_SLASH = "Rule-DB-6.3-Terminate-Slash"
RULE_DB_TABLE_NAME = "Rule-DB-1.1-Table-Name"
RULE_DB_VIEW_NAME = "Rule-DB-1.2-View-Name"
RULE_DB_FK_ALIGN = "Rule-DB-1.3-FK-Align"
RULE_DB_PROC_PREFIX = "Rule-DB-1.4-Proc-Prefix"
RULE_DB_FUNC_PREFIX = "Rule-DB-1.5-Func-Prefix"
RULE_DB_PKG_PREFIX = "Rule-DB-1.6-Pkg-Prefix"
RULE_DB_TRG_PREFIX = "Rule-DB-1.7-Trg-Prefix"
RULE_DB_SEQ_PREFIX = "Rule-DB-1.8-Seq-Prefix"
RULE_DB_PARAM_PREFIX = "Rule-DB-1.9-Param-Prefix"
RULE_DB_VAR_PREFIX = "Rule-DB-1.10-Var-Prefix"
RULE_DB_PURPOSE_COMMENT = "Rule-DB-2.2-Purpose-Comment"
RULE_DB_CASE_NUMBER = "Rule-DB-2.3-Case-Number"
RULE_DB_KEYWORDS_UPPER = "Rule-DB-4.1-Keywords-Upper"
RULE_DB_IDENTIFIERS_LOWER = "Rule-DB-4.2-Identifiers-Lower"
RULE_DB_ALIAS_CONSISTENT = "Rule-DB-4.3-Alias-Consistent"
RULE_DB_NO_SCHEMA_PREFIX = "Rule-DB-4.5-No-Schema-Prefix"
RULE_DB_BOOLEAN_INT = "Rule-DB-4.6-Boolean-Int"
RULE_DB_COMPLEX_LOGIC_COMMENT = "Rule-DB-4.7-Complex-Logic-Comment"
RULE_DB_MAGIC_VALUE_COMMENT = "Rule-DB-4.8-Magic-Value-Comment"
RULE_DB_USE_TYPE_DECLARATION = "Rule-DB-4.9-Use-Type-Declaration"
RULE_DB_WHERE_ORDER = "Rule-DB-4.10-Where-Order"
RULE_DB_SET_WHERE_COLUMN = "Rule-DB-5.2-Set-Where-Column"
RULE_DB_NO_FUNCTION_WHERE = "Rule-DB-5.3-No-Function-Where"
RULE_DB_PREFER_OUTER_JOIN = "Rule-DB-5.4-Prefer-Outer-Join"
RULE_DB_NO_LIKE_EQUAL = "Rule-DB-5.5-No-Like-Equal"
RULE_DB_COUNT_COLUMN = "Rule-DB-5.6-Count-Column"
RULE_DB_USE_BIND_VARIABLES = "Rule-DB-5.7-Use-Bind-Variables"
RULE_DB_EXISTS_DISTINCT = "Rule-DB-5.8-Exists-Distinct"
RULE_DB_DRIVING_TABLE_ORDER = "Rule-DB-5.9-Driving-Table-Order"
RULE_DB_FILENAME_LOWERCASE = "Rule-DB-6.1-Filename-Lowercase"
RULE_DB_PACKAGE_ONE_FILE = "Rule-DB-6.2-Package-One-File"
RULE_DB_COMBINE_SCHEMA_CHANGES = "Rule-DB-6.4-Combine-Schema-Changes"
RULE_DB_SEPARATE_DATA_SCRIPTS = "Rule-DB-6.5-Separate-Data-Scripts"

_PR_ADDED_LINES_CACHE = None

def log(msg):
    print(f"[ReviewRules] {msg}", flush=True)

def find_java_files():
    java_files = []
    for root, dirs, files in os.walk('.'):
        # Skip common directories
        if any(p in root for p in ['.git', '.github', 'target', '.idea', '.vscode', 'node_modules']):
            continue
        for file in files:
            if file.endswith('.java'):
                java_files.append(os.path.join(root, file))
    return java_files

def find_pom_files():
    pom_files = []
    for root, dirs, files in os.walk('.'):
        if any(p in root for p in ['.git', '.github', 'target', '.idea', '.vscode', 'node_modules']):
            continue
        for file in files:
            if file == 'pom.xml':
                pom_files.append(os.path.join(root, file))
    return pom_files

def find_sql_files():
    """Find all .sql files in the repo, excluding build/IDE dirs."""
    sql_files = []
    for root, dirs, files in os.walk('.'):
        if any(p in root for p in ['.git', '.github', 'target', '.idea', '.vscode', 'node_modules']):
            continue
        for file in files:
            if file.endswith('.sql'):
                sql_files.append(os.path.join(root, file).replace('\\', '/'))
    return sql_files

def find_xml_changelog_files():
    """Find Liquibase XML changelog files."""
    xml_files = []
    for root, dirs, files in os.walk('.'):
        if any(p in root for p in ['.git', '.github', 'target', '.idea', '.vscode', 'node_modules']):
            continue
        for file in files:
            if file.endswith('.xml'):
                filepath = os.path.join(root, file).replace('\\', '/')
                content = _read_file(filepath)
                if content and ('changeSet' in content or 'databaseChangeLog' in content):
                    xml_files.append(filepath)
    return xml_files

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=cwd
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def parse_classes_in_file(filepath, content_no_comments):
    # Returns a list of dicts: [{'class_name': name, 'interface_name': interface, 'class_chunk': chunk, 'annotation_chunk': ann_chunk, 'start_pos': pos}]
    class_pattern = re.compile(r'\bclass\s+(?P<class>[a-zA-Z0-9_]+)(?:\s+implements\s+(?P<interface>[a-zA-Z0-9_]+))?')
    matches = list(class_pattern.finditer(content_no_comments))
    classes = []
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx+1].start() if idx+1 < len(matches) else len(content_no_comments)
        class_chunk = content_no_comments[start:end]
        
        annotation_chunk_start = matches[idx-1].end() if idx > 0 else 0
        annotation_chunk = content_no_comments[annotation_chunk_start:start]
        
        classes.append({
            'class_name': m.group('class'),
            'interface_name': m.group('interface'),
            'class_chunk': class_chunk,
            'annotation_chunk': annotation_chunk,
            'start_pos': start
        })
    return classes

def check_compilation():
    errors = []
    if not os.path.exists('pom.xml'):
        return errors

    log("Running Maven compilation check...")
    code, stdout, stderr = run_command("mvn clean test-compile")
    if code != 0:
        log("Maven compilation failed! Parsing errors...")
        full_output = stdout + "\n" + stderr
        patterns = [
            r'(?P<file>[^:\n\r]+):\[(?P<line>\d+),(?P<col>\d+)\] (?P<msg>.*)',
            r'(?P<file>[^:\n\r]+):(?P<line>\d+):(?P<col>\d+)?:?\s*error:\s*(?P<msg>.*)',
            r'(?P<file>[^:\n\r]+):(?P<line>\d+):\s*error:\s*(?P<msg>.*)'
        ]
        
        found_error = False
        for line_str in full_output.splitlines():
            if "[ERROR]" in line_str or "error:" in line_str:
                for pattern in patterns:
                    match = re.search(pattern, line_str)
                    if match:
                        file_path = match.group('file').strip()
                        if os.path.isabs(file_path):
                            file_path = os.path.relpath(file_path)
                        
                        if os.path.exists(file_path):
                            line_num = int(match.group('line'))
                            col_num = int(match.group('col')) if 'col' in match.groupdict() and match.group('col') else 1
                            msg = match.group('msg').strip()
                            errors.append({
                                'file': file_path,
                                'line': line_num,
                                'col': col_num,
                                'message': f"Rule 1.1: Compilation failed: {msg}",
                                'source': RULE_COMPILATION
                            })
                            found_error = True
                            break
                if found_error:
                    continue

        if not errors:
            target_file = 'pom.xml'
            if not os.path.exists(target_file):
                java_files = find_java_files()
                target_file = java_files[0] if java_files else 'README.md'
            errors.append({
                'file': target_file,
                'line': 1,
                'col': 1,
                'message': "Rule 1.1: Production / CI build must compile successfully. Maven clean test-compile failed.",
                'source': RULE_COMPILATION
            })
    else:
        log("Maven compilation completed successfully.")
    return errors

def check_sql_injection():
    errors = []
    java_files = find_java_files()
    sql_keywords = re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|INTO|MERGE)\b', re.IGNORECASE)
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            log(f"Error reading {filepath}: {e}")
            continue

        def replacer_multiline(match):
            return re.sub(r'[^\n]', ' ', match.group(0))
        content_no_comments = re.sub(r'/\*.*?\*/', replacer_multiline, content, flags=re.DOTALL)

        def replacer_singleline(match):
            return re.sub(r'[^\n]', ' ', match.group(0))
        content_no_comments = re.sub(r'//.*', replacer_singleline, content_no_comments)

        statement_boundaries = [0]
        for match in re.finditer(r'[;{}]', content_no_comments):
            statement_boundaries.append(match.end())
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        
        def get_line_num(char_idx):
            import bisect
            return bisect.bisect_right(line_starts, char_idx)

        for i in range(len(statement_boundaries) - 1):
            start = statement_boundaries[i]
            end = statement_boundaries[i+1]
            statement_text = content_no_comments[start:end]
            
            literal_matches = list(re.finditer(r'"([^"\\]|\\.)*"', statement_text))
            if not literal_matches:
                continue
                
            has_sql_literal = False
            sql_literal_line = None
            for m in literal_matches:
                lit_val = m.group(0)
                if sql_keywords.search(lit_val):
                    has_sql_literal = True
                    sql_literal_line = get_line_num(start + m.start())
                    break
                    
            if not has_sql_literal:
                continue
                
            template = ""
            last_idx = 0
            for idx, m in enumerate(literal_matches):
                template += statement_text[last_idx:m.start()]
                template += f"__STR_LITERAL_{idx}__"
                last_idx = m.end()
            template += statement_text[last_idx:]
            
            if '+' not in template:
                continue
                
            parts = template.split('+')
            for idx, part in enumerate(parts):
                part_stripped = part.strip()
                if not part_stripped:
                    continue
                
                tokens = re.findall(r'\b[a-zA-Z0-9_]+\b', part_stripped)
                if not tokens:
                    continue
                
                operand_tokens = []
                if idx == 0:
                    operand_tokens = [tokens[-1]]
                elif idx == len(parts) - 1:
                    operand_tokens = [tokens[0]]
                else:
                    operand_tokens = tokens
                
                is_unsafe = False
                for token in operand_tokens:
                    if token.startswith('__STR_LITERAL_'):
                        continue
                    if token in ('true', 'false', 'null', 'new', 'String', 'int', 'double', 'float', 'long', 'boolean'):
                        continue
                    if re.match(r'^[A-Z0-9_]+$', token):
                        continue
                    if re.match(r'^\d+$', token):
                        continue
                    is_unsafe = True
                    break
                
                if is_unsafe:
                    errors.append({
                        'file': filepath,
                        'line': sql_literal_line if sql_literal_line else get_line_num(start),
                        'col': 1,
                        'message': "Rule 1.2: No new SonarQube Blocker or Critical issues (SQL Injection risk in concatenated query)",
                        'source': RULE_SQL_INJECTION
                    })
                    break
    return errors

def check_unused_dependencies():
    errors = []
    if not os.path.exists('pom.xml'):
        return errors

    log("Running Maven dependency:analyze-only check...")
    code, stdout, stderr = run_command("mvn dependency:analyze-only")
    full_output = stdout + "\n" + stderr
    
    if "Unused declared dependencies found:" in full_output:
        log("Unused dependencies found! Parsing...")
        lines = full_output.splitlines()
        started = False
        unused_deps = []
        for line in lines:
            if "Unused declared dependencies found:" in line:
                started = True
                continue
            if started:
                if "Used undeclared dependencies found:" in line or "Build success" in line or "BUILD SUCCESS" in line or not line.strip().startswith("[WARNING]"):
                    if not line.strip().startswith("[WARNING]    "):
                        started = False
                if started and line.strip().startswith("[WARNING]    "):
                    dep_str = line.strip().replace("[WARNING]    ", "").strip()
                    parts = dep_str.split(':')
                    if len(parts) >= 2:
                        unused_deps.append((parts[0], parts[1]))
        
        pom_files = find_pom_files()
        for pom_file in pom_files:
            try:
                with open(pom_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for group_id, artifact_id in unused_deps:
                    in_dependency = False
                    start_line = -1
                    has_group = False
                    has_artifact = False
                    
                    for line_idx, line in enumerate(lines):
                        if "<dependency>" in line:
                            in_dependency = True
                            start_line = line_idx + 1
                            has_group = False
                            has_artifact = False
                        if in_dependency:
                            if f"<groupId>{group_id}</groupId>" in line:
                                has_group = True
                            if f"<artifactId>{artifact_id}</artifactId>" in line:
                                has_artifact = True
                            if "</dependency>" in line:
                                if has_group and has_artifact:
                                    errors.append({
                                        'file': pom_file,
                                        'line': start_line,
                                        'col': 1,
                                        'message': f"Rule 1.4: Unused dependency in pom.xml: {group_id}:{artifact_id}",
                                        'source': RULE_UNUSED_DEPENDENCY
                                    })
                                in_dependency = False
            except Exception as e:
                log(f"Error reading pom file {pom_file}: {e}")
                
    return errors

def check_snapshot_versions():
    errors = []
    pom_files = find_pom_files()
    snapshot_pattern = re.compile(r'<version>[^<]*-SNAPSHOT[^<]*</version>')
    
    for pom_file in pom_files:
        try:
            with open(pom_file, 'r', encoding='utf-8') as f:
                for line_idx, line in enumerate(f):
                    if snapshot_pattern.search(line):
                        errors.append({
                            'file': pom_file,
                            'line': line_idx + 1,
                            'col': 1,
                            'message': f"Rule 1.5: No SNAPSHOT versions in production-bound builds",
                            'source': RULE_SNAPSHOT_VERSION
                        })
        except Exception as e:
            log(f"Error reading pom file {pom_file}: {e}")
    return errors

def get_pom_version_and_properties(pom_content):
    pom_content_clean = pom_content.replace('xmlns="http://maven.apache.org/POM/4.0.0"', '')
    pom_content_clean = re.sub(r'\sxmlns="[^"]+"', '', pom_content_clean)
    try:
        root = ET.fromstring(pom_content_clean)
        version_elem = root.find('./version')
        version = version_elem.text.strip() if version_elem is not None else None
        
        properties = {}
        properties_elem = root.find('./properties')
        if properties_elem is not None:
            for prop in properties_elem:
                properties[prop.tag] = prop.text.strip() if prop.text else ""
        return version, properties
    except Exception as e:
        log(f"Error parsing POM XML: {e}")
        return None, {}

def check_version_bumps():
    errors = []
    base_branch = os.environ.get('GITHUB_BASE_REF')
    if not base_branch:
        code, stdout, stderr = run_command("git symbolic-ref --short refs/remotes/origin/HEAD")
        if code == 0 and stdout.strip():
            base_branch = stdout.strip().replace("origin/", "")
        else:
            base_branch = "main"

    log(f"Comparing changes against base branch: origin/{base_branch}")
    run_command(f"git fetch origin {base_branch}:{base_branch}")
    
    code, stdout, stderr = run_command(f"git diff --name-only origin/{base_branch}...HEAD")
    if code != 0 or not stdout.strip():
        code, stdout, stderr = run_command(f"git diff --name-only origin/{base_branch}")
        if code != 0:
            log("Failed to get git diff. Skipping version bump checks.")
            return errors
            
    changed_files = [line.strip() for line in stdout.splitlines() if line.strip()]

    pom_files = find_pom_files()
    modules = []
    for pom in pom_files:
        module_dir = os.path.dirname(pom)
        if module_dir != '.' and module_dir != '':
            modules.append(module_dir)

    root_pom_properties_base = {}
    if os.path.exists('pom.xml'):
        code, stdout, stderr = run_command(f"git show origin/{base_branch}:pom.xml")
        if code == 0:
            _, root_pom_properties_base = get_pom_version_and_properties(stdout)
            
    root_pom_properties_current = {}
    if os.path.exists('pom.xml'):
        try:
            with open('pom.xml', 'r', encoding='utf-8') as f:
                _, root_pom_properties_current = get_pom_version_and_properties(f.read())
        except Exception:
            pass

    for module in modules:
        module_changed = False
        changed_module_files = []
        for file in changed_files:
            if file.startswith(module + '/') and not file.endswith('pom.xml'):
                module_changed = True
                changed_module_files.append(file)
                
        if not module_changed:
            continue
            
        version_bumped = False
        module_pom_path = os.path.join(module, 'pom.xml')
        base_version = None
        current_version = None
        
        code, stdout, stderr = run_command(f"git show origin/{base_branch}:{module_pom_path}")
        if code == 0:
            base_version, _ = get_pom_version_and_properties(stdout)
            
        if os.path.exists(module_pom_path):
            try:
                with open(module_pom_path, 'r', encoding='utf-8') as f:
                    current_version, _ = get_pom_version_and_properties(f.read())
            except Exception:
                pass
                
        if base_version and current_version and base_version != current_version:
            version_bumped = True
            
        module_name = os.path.basename(module)
        possible_props = [
            f"{module_name}.version",
            f"{module_name}-version",
            f"{module_name}_version",
            f"{module_name}Version"
        ]
        
        for prop in possible_props:
            base_val = root_pom_properties_base.get(prop)
            current_val = root_pom_properties_current.get(prop)
            if base_val and current_val and base_val != current_val:
                version_bumped = True
                break
                
        if not version_bumped:
            target_file = module_pom_path if os.path.exists(module_pom_path) else changed_module_files[0]
            errors.append({
                'file': target_file,
                'line': 1,
                'col': 1,
                'message': f"Rule 1.6: Bump shared module versions when they change. Shared module '{module_name}' was changed but its version was not bumped.",
                'source': RULE_VERSION_BUMP
            })
            
    return errors

def check_lombok_di():
    errors = []
    java_files = find_java_files()
    
    spring_bean_pattern = re.compile(r'@(Component|Service|RestController|Repository|Controller)\b')
    value_types = {'String', 'int', 'long', 'boolean', 'double', 'float', 'Integer', 'Long', 'Boolean', 'Double', 'Float', 
                   'Map', 'List', 'Set', 'Collection', 'Date', 'LocalDate', 'LocalDateTime', 'Properties'}

    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            if not spring_bean_pattern.search(cls['annotation_chunk']):
                continue
                
            has_req_args_ctor = '@RequiredArgsConstructor' in cls['annotation_chunk']
            
            for m in re.finditer(r'@Autowired\b', cls['class_chunk']):
                start_pos = cls['start_pos'] + m.start()
                line_num = get_line_num(start_pos)
                
                look_ahead = cls['class_chunk'][m.start():m.start()+200]
                if '(' in look_ahead and '{' in look_ahead and look_ahead.index('(') < look_ahead.index('{'):
                    continue
                
                errors.append({
                    'file': filepath,
                    'line': line_num,
                    'col': 1,
                    'message': "Rule 3.1: Constructor injection via @RequiredArgsConstructor. Do not use field @Autowired.",
                    'source': RULE_LOMBOK_DI
                })
                
            field_matches = re.finditer(r'\bprivate\s+(?P<modifier>final\s+)?(?P<type>[a-zA-Z0-9_<>]+)\s+(?P<name>[a-zA-Z0-9_]+)\s*;', cls['class_chunk'])
            has_collaborators = False
            for m in field_matches:
                dep_type = m.group('type')
                is_final = m.group('modifier') is not None
                
                generic_match = re.search(r'<([a-zA-Z0-9_]+)>', dep_type)
                if generic_match:
                    dep_type = generic_match.group(1)
                    
                if dep_type[0].isupper() and dep_type not in value_types:
                    has_collaborators = True
                    if not is_final:
                        line_num = get_line_num(cls['start_pos'] + m.start())
                        errors.append({
                            'file': filepath,
                            'line': line_num,
                            'col': 1,
                            'message': f"Rule 3.1: Declare collaborators as private final: private final {dep_type} {m.group('name')};",
                            'source': RULE_LOMBOK_DI
                        })
                        
            if has_collaborators and not has_req_args_ctor:
                line_num = get_line_num(cls['start_pos'])
                errors.append({
                    'file': filepath,
                    'line': line_num,
                    'col': 1,
                    'message': "Rule 3.1: Spring components must use Lombok @RequiredArgsConstructor for constructor injection.",
                    'source': RULE_LOMBOK_DI
                })
                
    return errors

def check_circular_dependencies():
    errors = []
    java_files = find_java_files()
    
    dependencies = {}
    file_of_type = {}
    line_of_type = {}
    implements_map = {}
    
    spring_bean_pattern = re.compile(r'@(Component|Service|RestController|Repository|Controller)\b')
    field_pattern = re.compile(r'\bprivate\s+final\s+(?P<type>[a-zA-Z0-9_<>]+)\s+(?P<name>[a-zA-Z0-9_]+);')
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            if not spring_bean_pattern.search(cls['annotation_chunk']):
                continue
                
            class_name = cls['class_name']
            interface_name = cls['interface_name']
            class_line = bisect.bisect_right(line_starts, cls['start_pos'])
            
            file_of_type[class_name] = filepath
            line_of_type[class_name] = class_line
            if interface_name:
                file_of_type[interface_name] = filepath
                line_of_type[interface_name] = class_line
                implements_map[interface_name] = class_name
                
            deps = set()
            for field_match in field_pattern.finditer(cls['class_chunk']):
                dep_type = field_match.group('type')
                generic_match = re.search(r'<([a-zA-Z0-9_]+)>', dep_type)
                if generic_match:
                    dep_type = generic_match.group(1)
                deps.add(dep_type)
                
            dependencies[class_name] = deps
            if interface_name:
                dependencies[interface_name] = deps
                
    resolved_dependencies = {}
    for bean, deps in dependencies.items():
        resolved_deps = set()
        for dep in deps:
            impl = implements_map.get(dep, dep)
            resolved_deps.add(impl)
        resolved_dependencies[bean] = resolved_deps
        
    visited = {}
    cycle_path = []
    
    def dfs(node):
        visited[node] = 1
        cycle_path.append(node)
        
        for neighbor in resolved_dependencies.get(node, []):
            if neighbor not in resolved_dependencies:
                continue
            if visited.get(neighbor, 0) == 1:
                cycle_start_idx = cycle_path.index(neighbor)
                cycle = cycle_path[cycle_start_idx:]
                return cycle
            elif visited.get(neighbor, 0) == 0:
                cycle = dfs(neighbor)
                if cycle:
                    return cycle
                    
        cycle_path.pop()
        visited[node] = 2
        return None

    for bean in resolved_dependencies:
        if visited.get(bean, 0) == 0:
            cycle = dfs(bean)
            if cycle:
                cycle_str = " -> ".join(cycle + [cycle[0]])
                msg = f"Rule 3.2: Circular Spring dependency detected: {cycle_str}"
                reported_files = set()
                for b in cycle:
                    filepath = file_of_type.get(b)
                    line_num = line_of_type.get(b, 1)
                    if filepath and filepath not in reported_files:
                        reported_files.add(filepath)
                        errors.append({
                            'file': filepath,
                            'line': line_num,
                            'col': 1,
                            'message': msg,
                            'source': RULE_CIRCULAR_DEP
                        })
                break
                
    return errors

def check_transactional_visibility():
    errors = []
    java_files = find_java_files()
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
            
        for line_idx, line in enumerate(lines):
            if '@Transactional' in line:
                for lookahead_idx in range(line_idx + 1, min(line_idx + 10, len(lines))):
                    next_line = lines[lookahead_idx].strip()
                    if not next_line:
                        continue
                    if next_line.startswith('@') or next_line.startswith('//') or next_line.startswith('/*') or next_line.startswith('*'):
                        continue
                    
                    if '(' in next_line:
                        is_public = 'public' in next_line
                        is_private = 'private' in next_line
                        is_protected = 'protected' in next_line
                        
                        if is_private or is_protected or (not is_public and ('void' in next_line or re.search(r'\b[A-Z][a-zA-Z0-9_<>]*\s+[a-z][a-zA-Z0-9_]*\s*\(', next_line))):
                            errors.append({
                                'file': filepath,
                                'line': line_idx + 1,
                                'col': 1,
                                'message': "Rule 3.3: @Transactional must only be placed on public (proxy-visible) methods.",
                                'source': RULE_TRANSACTIONAL
                            })
                        break
    return errors

def check_constructor_logic():
    errors = []
    java_files = find_java_files()
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_name = cls['class_name']
            
            ctor_pattern = re.compile(rf'\b(public|protected|private)\s+{class_name}\s*\([^)]*\)\s*\{{(?P<body>.*?)\}}', re.DOTALL)
            for ctor_match in ctor_pattern.finditer(cls['class_chunk']):
                body = ctor_match.group('body')
                statements = body.split(';')
                has_business_logic = False
                for stmt in statements:
                    stmt_stripped = stmt.strip()
                    if not stmt_stripped:
                        continue
                    if stmt_stripped.startswith('super(') or stmt_stripped.startswith('this('):
                        continue
                    if stmt_stripped.startswith('this.') and '=' in stmt_stripped and '(' not in stmt_stripped.split('=')[1]:
                        continue
                    if '=' in stmt_stripped and '(' not in stmt_stripped:
                        continue
                    if '(' in stmt_stripped:
                        if 'Objects.requireNonNull' in stmt_stripped:
                            continue
                        has_business_logic = True
                        break
                
                if has_business_logic:
                    line_num = get_line_num(cls['start_pos'] + ctor_match.start())
                    errors.append({
                        'file': filepath,
                        'line': line_num,
                        'col': 1,
                        'message': "Rule 3.4: No business logic in constructors. Constructors must only assign dependencies/state.",
                        'source': RULE_CTOR_LOGIC
                    })
    return errors

def check_secrets():
    errors = []
    java_files = find_java_files()
    secret_var_pattern = re.compile(r'(?i)(password|secret|apikey|token|privatekey|passwd)\b.*=\s*"(?P<val>[^"]+)"')
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_idx, line in enumerate(f):
                    match = secret_var_pattern.search(line)
                    if match:
                        val = match.group('val')
                        if val.startswith('${') or val.startswith('{') or '%' in val or val == 'placeholder' or len(val) < 4:
                            continue
                        errors.append({
                            'file': filepath,
                            'line': line_idx + 1,
                            'col': 1,
                            'message': "Rule 4.1: No secrets in the repository. Avoid hardcoding credentials/passwords/API keys.",
                            'source': RULE_SECRETS
                        })
        except Exception:
            continue
    return errors

def check_wrapper_equality():
    errors = []
    java_files = find_java_files()
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        wrapper_vars = set()
        decl_pattern = re.compile(r'\b(Integer|Long|Boolean|Double|Float|Short|Byte|Character)\s+(?P<var>[a-zA-Z0-9_]+)\b')
        for m in decl_pattern.finditer(content_no_comments):
            wrapper_vars.add(m.group('var'))
            
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        comp_pattern = re.compile(r'\b(?P<left>[a-zA-Z0-9_]+)\s*(==|!=)\s*(?P<right>[a-zA-Z0-9_]+)\b')
        for m in comp_pattern.finditer(content_no_comments):
            left = m.group('left')
            right = m.group('right')
            if left in wrapper_vars or right in wrapper_vars:
                if left == 'null' or right == 'null':
                    continue
                line_num = get_line_num(m.start())
                errors.append({
                    'file': filepath,
                    'line': line_num,
                    'col': 1,
                    'message': "Rule 4.4: Compare wrapper objects using equals() or Objects.equals(), not == or !=.",
                    'source': RULE_WRAPPER_EQ
                })
    return errors

def check_lazy_equals():
    errors = []
    java_files = find_java_files()
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        pattern = re.compile(r'@(?:[a-zA-Z0-9_.]+\.)?EqualsAndHashCode\([^)]*\bof\s*=\s*(?P<fields>\{[^}]*\}|"[^"]+")\)')
        for m in pattern.finditer(content):
            fields_str = m.group('fields')
            fields = re.findall(r'"([^"]+)"', fields_str)
            has_lazy = False
            for f in fields:
                if f.endswith('s') and not f.endswith('status') and not f.endswith('address') and not f.endswith('class'):
                    has_lazy = True
                    break
                if 'List' in f or 'Set' in f or 'Collection' in f:
                    has_lazy = True
                    break
            
            if has_lazy or len(fields) > 2:
                line_starts = [0]
                for match in re.finditer(r'\n', content):
                    line_starts.append(match.end())
                import bisect
                line_num = bisect.bisect_right(line_starts, m.start())
                errors.append({
                    'file': filepath,
                    'line': line_num,
                    'col': 1,
                    'message': "Rule 4.5: Override equals and hashCode on stable business keys only; never include collections or lazy associations.",
                    'source': RULE_LAZY_EQUALS
                })
    return errors

def check_try_with_resources():
    errors = []
    java_files = find_java_files()
    closeable_types = {
        'InputStream', 'OutputStream', 'Reader', 'Writer',
        'FileInputStream', 'FileOutputStream', 'FileReader', 'FileWriter',
        'BufferedReader', 'BufferedWriter', 'ZipFile', 'ZipInputStream', 'ZipOutputStream',
        'Connection', 'Statement', 'PreparedStatement', 'ResultSet'
    }
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
            
        for line_idx, line in enumerate(lines):
            line_strip = line.strip()
            if any(t in line for t in closeable_types) and '=' in line and ';' in line:
                if 'try' not in line_strip and not line_strip.startswith('return') and not line_strip.startswith('public') and not line_strip.startswith('private'):
                    match = re.search(r'\b(?P<type>' + '|'.join(closeable_types) + r')\s+[a-zA-Z0-9_]+\s*=', line_strip)
                    if match:
                        errors.append({
                            'file': filepath,
                            'line': line_idx + 1,
                            'col': 1,
                            'message': "Rule 4.6: Close resources using try-with-resources to prevent resource leaks.",
                            'source': RULE_TRY_WITH_RESOURCES
                        })
    return errors

def check_finally_return():
    errors = []
    java_files = find_java_files()
    
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
            
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        for m in re.finditer(r'\bfinally\s*\{', content_no_comments):
            start_pos = m.end() - 1
            brace_count = 0
            block_content = ""
            for idx in range(start_pos, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        block_content = content_no_comments[start_pos+1:idx]
                        break
                        
            if 'return' in block_content:
                line_starts = [0]
                for match in re.finditer(r'\n', content):
                    line_starts.append(match.end())
                import bisect
                line_num = bisect.bisect_right(line_starts, m.start())
                errors.append({
                    'file': filepath,
                    'line': line_num,
                    'col': 1,
                    'message': "Rule 4.7: Never return from a finally block, as it discards uncaught exceptions and overrides previous return values.",
                    'source': RULE_FINALLY_RETURN
                })
    return errors

def check_immutable_mutation():
    errors = []
    java_files = find_java_files()
    immutable_sources = re.compile(
        r'(Arrays\.asList|List\.of|Collections\.empty(?:List|Map|Set)|Collections\.unmodifiable\w+)\s*\([^)]*\)\.'
        r'(?:add|remove|put|set|clear)\s*\('
    )
    keyset_pattern = re.compile(
        r'\b[a-zA-Z0-9_]+\.(keySet|values|entrySet)\s*\(\s*\)\s*\.\s*(?:add|remove)\s*\('
    )
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
        for line_idx, line in enumerate(lines):
            if immutable_sources.search(line) or keyset_pattern.search(line):
                errors.append({
                    'file': filepath,
                    'line': line_idx + 1,
                    'col': 1,
                    'message': 'Rule 5.1: Do not mutate immutable/fixed-size list views (Arrays.asList, List.of, emptyList, keySet, etc.).',
                    'source': 'Rule-5.1-Immutable-Collection-Mutation'
                })
    return errors

def check_foreach_modify():
    errors = []
    java_files = find_java_files()
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        content_nc = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_nc = re.sub(r'//.*', '', content_nc)
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_ln(idx):
            return bisect.bisect_right(line_starts, idx)
        foreach_pat = re.compile(
            r'for\s*\(\s*[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*:\s*(?P<col>[a-zA-Z0-9_]+)\s*\)'
        )
        for m in foreach_pat.finditer(content_nc):
            col = m.group('col')
            start = content_nc.find('{', m.end())
            if start == -1:
                continue
            brace = 0
            body = ""
            for i in range(start, len(content_nc)):
                c = content_nc[i]
                if c == '{':
                    brace += 1
                elif c == '}':
                    brace -= 1
                    if brace == 0:
                        body = content_nc[start+1:i]
                        break
            if re.search(rf'\b{re.escape(col)}\s*\.\s*(add|remove|clear)\s*\(', body):
                errors.append({
                    'file': filepath,
                    'line': get_ln(m.start()),
                    'col': 1,
                    'message': f"Rule 5.2: Do not add/remove from '{col}' while iterating over it. Use removeIf() or Iterator.remove().",
                    'source': 'Rule-5.2-Foreach-Modify-Same-Collection'
                })
    return errors

def check_comparator_consistency():
    errors = []
    java_files = find_java_files()
    pat = re.compile(
        r'\([a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\)\s*->[^;\n{]*\?\s*(?P<pos>-?\d+)\s*:\s*(?P<neg>-?\d+)'
    )
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            continue
        for line_idx, line in enumerate(lines):
            m = pat.search(line)
            if m:
                pos = m.group('pos')
                neg = m.group('neg')
                # Only flag if neither value is 0 (missing equality case)
                if pos != '0' and neg != '0':
                    errors.append({
                        'file': filepath,
                        'line': line_idx + 1,
                        'col': 1,
                        'message': 'Rule 5.3: Comparator lambda is not consistent — missing equality case (return 0). Use Comparator.comparing() instead.',
                        'source': 'Rule-5.3-Comparator-Consistency'
                    })
    return errors

def check_threadlocal_leak():
    errors = []
    java_files = find_java_files()
    for filepath in java_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            continue
        content_nc = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_nc = re.sub(r'//.*', '', content_nc)
        # Find ThreadLocal variable names declared in the file
        tl_decl = re.findall(r'\bThreadLocal\b[^;=\n]*?(?:=|(?:static\s+)?[a-zA-Z0-9_]+\s+([a-zA-Z0-9_]+)\s*[=;])', content_nc)
        tl_vars = set(v for v in tl_decl if v)
        tl_vars.update(re.findall(r'ThreadLocal\s*[<][^>]*[>]\s+([a-zA-Z0-9_]+)', content_nc))
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_ln(idx):
            return bisect.bisect_right(line_starts, idx)
        for var in tl_vars:
            if not var:
                continue
            for m in re.finditer(rf'\b{re.escape(var)}\.set\s*\(', content_nc):
                scope = content_nc[m.start():m.start() + 2000]
                has_remove = bool(re.search(
                    rf'finally\s*\{{[^}}]*\b{re.escape(var)}\.remove\s*\(',
                    scope, re.DOTALL
                ))
                if not has_remove:
                    errors.append({
                        'file': filepath,
                        'line': get_ln(m.start()),
                        'col': 1,
                        'message': f"Rule 5.7: ThreadLocal '{var}' is set but not removed in a finally block — causes thread pool leaks.",
                        'source': 'Rule-5.7-ThreadLocal-Leak'
                    })
    return errors

# ─── Section 7: REST API & Security ─────────────────────────────────────────

MAPPING_ANNOTATIONS = {'@GetMapping', '@PostMapping', '@PutMapping', '@DeleteMapping', '@PatchMapping', '@RequestMapping'}
WRITE_ANNOTATIONS   = {'@PostMapping', '@PutMapping', '@DeleteMapping', '@PatchMapping'}
AUTH_ANNOTATIONS    = {'@PreAuthorize', '@Secured', '@RolesAllowed', '@PermitAll', '@DenyAll'}

def _get_line_starts(content):
    import bisect
    ls = [0]
    for m in re.finditer(r'\n', content):
        ls.append(m.end())
    return ls

def _line_of(line_starts, pos):
    import bisect
    return bisect.bisect_right(line_starts, pos)

def _read_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return None

def _strip_comments(content):
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    content = re.sub(r'//.*', '', content)
    return content

def _strip_comments_preserve_length(content):
    def replacer_multiline(match):
        return re.sub(r'[^\n]', ' ', match.group(0))
    content_no_comments = re.sub(r'/\*.*?\*/', replacer_multiline, content, flags=re.DOTALL)
    def replacer_singleline(match):
        return re.sub(r'[^\n]', ' ', match.group(0))
    content_no_comments = re.sub(r'//.*', replacer_singleline, content_no_comments)
    return content_no_comments

def check_rest_auth():
    """Rule 7.1 — every mapped endpoint must carry a security annotation."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        ls = _get_line_starts(content)
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not any(stripped.startswith(a) for a in MAPPING_ANNOTATIONS):
                continue
            # scan backwards up to 10 lines for a security annotation
            window_start = max(0, i - 10)
            window = '\n'.join(lines[window_start:i+1])
            if not any(a in window for a in AUTH_ANNOTATIONS):
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': 'Rule 7.1: Authenticated endpoints must carry a security annotation '
                               '(@PreAuthorize, @Secured, @RolesAllowed).',
                    'source': 'Rule-7.1-Endpoint-Auth'
                })
    return errors

def check_request_body_validation():
    """Rule 7.2 — @RequestBody must be accompanied by @Valid."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if '@RequestBody' in line and '@Valid' not in line:
                # check previous / same line for @Valid
                window = '\n'.join(lines[max(0, i-2):i+1])
                if '@Valid' not in window:
                    errors.append({
                        'file': filepath,
                        'line': i + 1,
                        'col': 1,
                        'message': 'Rule 7.2: @RequestBody must be annotated with @Valid to enforce bean validation.',
                        'source': 'Rule-7.2-Request-Body-Validation'
                    })
    return errors

def check_entity_request_body():
    """Rule 7.3 / 7.8 — write APIs must not bind directly to JPA @Entity classes."""
    errors = []
    entity_names = set()
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        # collect entity class names
        for m in re.finditer(r'@Entity\b.*?class\s+(\w+)', content, re.DOTALL):
            entity_names.add(m.group(1))
        # also single-line @Entity then class on next line
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if '@Entity' in line and i + 1 < len(lines):
                cm = re.search(r'\bclass\s+(\w+)', lines[i+1])
                if cm:
                    entity_names.add(cm.group(1))

    if not entity_names:
        return errors

    entity_pattern = re.compile(r'\b(' + '|'.join(re.escape(e) for e in entity_names) + r')\b')

    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(stripped.startswith(a) for a in WRITE_ANNOTATIONS):
                # scan next 5 lines for @RequestBody with an entity type
                for j in range(i+1, min(i+6, len(lines))):
                    if '@RequestBody' in lines[j] and entity_pattern.search(lines[j]):
                        errors.append({
                            'file': filepath,
                            'line': j + 1,
                            'col': 1,
                            'message': f'Rule 7.3/7.8: Write APIs must not bind directly to JPA @Entity classes. '
                                       f'Use a dedicated DTO/request object instead.',
                            'source': 'Rule-7.3-No-Entity-RequestBody'
                        })
    return errors

def check_jpql_injection():
    """Rule 7.4 — no concatenated JPQL/HQL with user input (extends Rule 1.2)."""
    errors = []
    jpql_keywords = re.compile(
        r'\b(FROM|SELECT|WHERE|UPDATE|DELETE|JOIN|FETCH|NAMED|QUERY)\b', re.IGNORECASE
    )
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        # find string literals containing JPQL keywords concatenated with variables
        for m in re.finditer(r'"([^"\\]|\\.)*"', nc):
            lit = m.group(0)
            if not jpql_keywords.search(lit):
                continue
            # check if there is a + variable after / before the literal nearby
            ctx_start = max(0, m.start() - 5)
            ctx_end   = min(len(nc), m.end() + 100)
            ctx = nc[ctx_start:ctx_end]
            if '+' in ctx:
                parts = ctx.split('+')
                for part in parts:
                    tokens = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_]*\b', part.strip())
                    for tok in tokens:
                        if re.match(r'^[A-Z0-9_]+$', tok):
                            continue
                        if tok in ('String', 'true', 'false', 'null', 'new'):
                            continue
                        errors.append({
                            'file': filepath,
                            'line': _line_of(ls, m.start()),
                            'col': 1,
                            'message': 'Rule 7.4: No concatenated JPQL/SQL with user input. Use named/positional parameters instead.',
                            'source': 'Rule-7.4-No-JPQL-Injection'
                        })
                        break
    return errors

def check_missing_authorization():
    """Rule 7.5 — controller methods should call an authorization service."""
    errors = []
    auth_call_pattern = re.compile(
        r'\b(assert|check|verify|authorize|canView|canEdit|canDelete|hasPermission|isAuthorized)\b',
        re.IGNORECASE
    )
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        lines = content.splitlines()
        # only look at files with Spring controller annotations
        if not re.search(r'@(RestController|Controller)\b', nc):
            continue
        # find each mapping method
        mapping_pat = re.compile(
            r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b[^\n]*\n'
            r'(?:\s*@\w[^\n]*\n)*'               # optional further annotations
            r'\s*(?:public|protected)\s+\w[\w<>\[\]]*\s+(\w+)\s*\([^)]*\)\s*\{'
        )
        for m in mapping_pat.finditer(nc):
            method_start = nc.find('{', m.end() - 1)
            if method_start == -1:
                continue
            brace = 0
            body = ''
            for idx in range(method_start, len(nc)):
                if nc[idx] == '{':
                    brace += 1
                elif nc[idx] == '}':
                    brace -= 1
                    if brace == 0:
                        body = nc[method_start+1:idx]
                        break
            if not auth_call_pattern.search(body):
                errors.append({
                    'file': filepath,
                    'line': _line_of(ls, m.start()),
                    'col': 1,
                    'message': f'Rule 7.5: Controller method appears to be missing an authorization check '
                               f'(assertCanView / assertCanEdit / hasPermission, etc.).',
                    'source': 'Rule-7.5-Missing-Authorization'
                })
    return errors

def check_log_secrets():
    """Rule 7.6 — never log or return values of secret/password variables."""
    errors = []
    secret_pat = re.compile(
        r'\b(?:password|passwd|secret|apiKey|token|privateKey|credential)\b',
        re.IGNORECASE
    )
    log_return_pat = re.compile(
        r'\b(?:log\.|logger\.|System\.out\.|return)\b'
    )
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if log_return_pat.search(line) and secret_pat.search(line):
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': 'Rule 7.6: Do not log or return secrets/passwords/tokens. '
                               'Redact or omit sensitive values.',
                    'source': 'Rule-7.6-Log-Secret'
                })
    return errors

def check_file_upload_security():
    """Rule 7.7 — MultipartFile uploads must validate type and size."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        if 'MultipartFile' not in content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        # Find method signatures that take a MultipartFile parameter
        method_pat = re.compile(
            r'(?:public|private|protected)\s+\w[\w<>\[\]]*\s+\w+\s*\([^)]*MultipartFile[^)]*\)\s*\{'
        )
        for m in method_pat.finditer(nc):
            body_start = nc.find('{', m.end() - 1)
            if body_start == -1:
                continue
            brace = 0
            body = ''
            for idx in range(body_start, len(nc)):
                if nc[idx] == '{':
                    brace += 1
                elif nc[idx] == '}':
                    brace -= 1
                    if brace == 0:
                        body = nc[body_start+1:idx]
                        break
            has_type_check = bool(re.search(
                r'\b(getContentType|getOriginalFilename|getSize|transferTo|allowedTypes|validateFile)\b',
                body
            ))
            if not has_type_check:
                errors.append({
                    'file': filepath,
                    'line': _line_of(ls, m.start()),
                    'col': 1,
                    'message': 'Rule 7.7: File upload handler must validate file type, size, and path '
                               '(check getContentType(), getSize(), etc.).',
                    'source': 'Rule-7.7-File-Upload-Security'
                })
    return errors

# ─── Section 8: Persistence & Transactions ──────────────────────────────────

def check_multi_step_transaction():
    """Rule 8.1 — service methods with multiple writes must be @Transactional."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        if not re.search(r'@(Service|Component|RestController|Controller)\b', nc):
            continue
        ls = _get_line_starts(content)
        classes = parse_classes_in_file(filepath, nc)
        for cls in classes:
            if '@Transactional' in cls['annotation_chunk']:
                continue
            # match methods
            method_pat = re.compile(
                r'(?:public|protected)\s+\w[\w<>\[\]]*\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
            )
            for m in method_pat.finditer(cls['class_chunk']):
                mname = m.group('name')
                start = cls['class_chunk'].find('{', m.end() - 1)
                if start == -1:
                    continue
                brace = 0
                body = ''
                for i in range(start, len(cls['class_chunk'])):
                    c = cls['class_chunk'][i]
                    if c == '{':
                        brace += 1
                    elif c == '}':
                        brace -= 1
                        if brace == 0:
                            body = cls['class_chunk'][start+1:i]
                            break
                writes = re.findall(r'\b[a-zA-Z0-9_]+\.(save|delete|update|persist|remove|saveAndFlush)\s*\(', body)
                if len(writes) > 1:
                    offset = cls['start_pos'] + m.start()
                    # check if method annotation has @Transactional
                    window = cls['class_chunk'][max(0, m.start()-300):m.start()]
                    if '@Transactional' not in window:
                        errors.append({
                            'file': filepath,
                            'line': _line_of(ls, offset),
                            'col': 1,
                            'message': f"Rule 8.1: Method '{mname}' performs multiple write operations ({', '.join(writes)}) "
                                       f"but lacks a transaction declaration (@Transactional).",
                            'source': 'Rule-8.1-Multi-Step-Transaction'
                        })
    return errors

def check_lazy_initialization_dto():
    """Rule 8.2 — mapped endpoints should not return database Entities directly."""
    errors = []
    entities = set()
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for m in re.finditer(r'@Entity\b.*?class\s+(\w+)', content, re.DOTALL):
            entities.add(m.group(1))
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if '@Entity' in line and i + 1 < len(lines):
                cm = re.search(r'\bclass\s+(\w+)', lines[i+1])
                if cm:
                    entities.add(cm.group(1))
    if not entities:
        return errors

    pattern = re.compile(r'\b(' + '|'.join(re.escape(e) for e in entities) + r')\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        if not re.search(r'@(RestController|Controller)\b', nc):
            continue
        ls = _get_line_starts(content)
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if any(stripped.startswith(a) for a in MAPPING_ANNOTATIONS):
                for j in range(i+1, min(i+6, len(lines))):
                    next_line = lines[j].strip()
                    if not next_line or next_line.startswith('@') or next_line.startswith('//'):
                        continue
                    m = re.search(r'\b(?:public|protected|private)?\s+(?P<ret>(?:[a-zA-Z0-9_.]|<|>|\[|\])+)\s+\w+\s*\(', next_line)
                    if m:
                        ret = m.group('ret')
                        if pattern.search(ret):
                            errors.append({
                                'file': filepath,
                                'line': j + 1,
                                'col': 1,
                                'message': f"Rule 8.2: Endpoint returns database Entity '{ret}' directly. "
                                           f"Map to DTOs first to avoid LazyInitializationException.",
                                'source': 'Rule-8.2-No-Entity-Serialization'
                            })
                        break
    return errors

def check_cascade_safety():
    """Rule 8.3 — @ManyToMany must not carry unsafe CascadeType.REMOVE / CascadeType.ALL."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if '@ManyToMany' in line:
                window = '\n'.join(lines[max(0, i-1):min(len(lines), i+3)])
                if 'CascadeType.REMOVE' in window or 'CascadeType.ALL' in window:
                    errors.append({
                        'file': filepath,
                        'line': i + 1,
                        'col': 1,
                        'message': "Rule 8.3: @ManyToMany must not cascade REMOVE or ALL to prevent unintended deletions of shared resources.",
                        'source': 'Rule-8.3-Unsafe-Cascade-ManyToMany'
                    })
    return errors

def check_modifying_query():
    """Rule 8.4 — UPDATE or DELETE queries in repositories require the @Modifying annotation."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        query_pattern = re.compile(r'@Query\s*\((?P<val>.*?)\)', re.DOTALL)
        for m in query_pattern.finditer(nc):
            val = m.group('val').upper()
            if 'UPDATE' in val or 'DELETE' in val:
                preceding = nc[max(0, m.start()-150):m.start()]
                if '@Modifying' not in preceding:
                    errors.append({
                        'file': filepath,
                        'line': _line_of(ls, m.start()),
                        'col': 1,
                        'message': "Rule 8.4: UPDATE or DELETE JPQL queries must be annotated with @Modifying.",
                        'source': 'Rule-8.4-Missing-Modifying-Annotation'
                    })
    return errors

def check_money_bigdecimal():
    """Rule 8.5 — monetary/cost fields must use BigDecimal in Java."""
    errors = []
    words = {'cost', 'price', 'amount', 'money', 'salary', 'tax', 'budget', 'balance', 'rate', 'fee'}
    pattern = re.compile(r'\b(double|Double|float|Float)\s+(?P<name>[a-zA-Z0-9_]+)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            m = pattern.search(line)
            if m:
                name = m.group('name')
                if any(w in name.lower() for w in words):
                    errors.append({
                        'file': filepath,
                        'line': i + 1,
                        'col': 1,
                        'message': f"Rule 8.5: Monetary field '{name}' must use BigDecimal instead of Double/Float.",
                        'source': 'Rule-8.5-BigDecimal-For-Money'
                    })
    return errors

# ─── Section 9 & 10: Exceptions, Logging, Resource & Scale ──────────────────

def check_parameterized_logs():
    """Rule 9.1 — debug and trace logs must use parameterized placeholders instead of concatenation."""
    errors = []
    log_pattern = re.compile(r'\blog\.(debug|trace)\s*\((?P<args>[^;]*)\)\s*;')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        for m in log_pattern.finditer(nc):
            args = m.group('args')
            if '+' in args:
                stripped_args = re.sub(r'"([^"\\]|\\.)*"', '', args)
                cleaned = re.sub(r'[\s\+\,\(\)]', '', stripped_args)
                if cleaned:
                    errors.append({
                        'file': filepath,
                        'line': _line_of(ls, m.start()),
                        'col': 1,
                        'message': f"Rule 9.1: Do not use string concatenation in log.{m.group(1)}(). Use parameterized placeholders (e.g. log.{m.group(1)}(\"proposal id: {{}}\", id)).",
                        'source': f"Rule-9.1-Parameterized-{m.group(1).upper()}-Log"
                    })
    return errors

def check_unbounded_loads():
    """Rule 10.1 — no unbounded full-table loads on request threads."""
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        if not re.search(r'@(RestController|Controller)\b', nc):
            continue
        ls = _get_line_starts(content)
        classes = parse_classes_in_file(filepath, nc)
        for cls in classes:
            if '@RestController' not in cls['annotation_chunk'] and '@Controller' not in cls['annotation_chunk']:
                continue
            method_pat = re.compile(
                r'(?:public|protected)\s+(?:[a-zA-Z0-9_.]|<|>|\[|\])+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
            )
            for m in method_pat.finditer(cls['class_chunk']):
                mname = m.group('name')
                start = cls['class_chunk'].find('{', m.end() - 1)
                if start == -1:
                    continue
                brace = 0
                body = ''
                for i in range(start, len(cls['class_chunk'])):
                    c = cls['class_chunk'][i]
                    if c == '{':
                        brace += 1
                    elif c == '}':
                        brace -= 1
                        if brace == 0:
                            body = cls['class_chunk'][start+1:i]
                            break
                # match repository calls that indicate unbounded loads
                calls = re.finditer(
                    r'\b(?P<repo>[a-zA-Z0-9_]+Repository)\.(?P<method>findAll|search|list|getAll)\s*\((?P<args>[^)]*)\)',
                    body
                )
                for call in calls:
                    args = call.group('args').lower()
                    if 'pageable' not in args and 'page' not in args:
                        offset = cls['start_pos'] + m.start()
                        errors.append({
                            'file': filepath,
                            'line': _line_of(ls, offset),
                            'col': 1,
                            'message': f"Rule 10.1: Repository call '{call.group(0)}' inside controller method '{mname}' "
                                       f"must be paginated (pass Pageable/Limit) to prevent unbounded full-table loads.",
                            'source': 'Rule-10.1-Unbounded-Full-Table-Load'
                        })
    return errors

    return errors

# ─── Section 17: Project-Specific Rules — fibi40 ────────────────────────────

def check_rule_17_1_person_identity():
    errors = []
    pat = re.compile(
        r'\bisAuthorized\s*\(\s*[^,]+,\s*[^,]+,\s*'
        r'(?!(?:AuthenticatedUser|UserContext|UserUtils)\b)(?P<expr>[a-zA-Z0-9_]+\.get(?:PersonId|UpdateUser|UserName|UserId)\s*\(\s*\))\s*\)'
    )
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        for m in pat.finditer(nc):
            errors.append({
                'file': filepath,
                'line': _line_of(ls, m.start()),
                'col': 1,
                'message': f"Rule 17.1: Never trust request-body identifiers for identity. Replace '{m.group('expr')}' with AuthenticatedUser or UserContext.",
                'source': 'Rule-17.1-Untrusted-Identity'
            })
    return errors

def check_rule_17_2_module_codes():
    errors = []
    pat = re.compile(r'\bisAuthorized\s*\(\s*(?P<num>\d+)\s*,')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        for m in pat.finditer(nc):
            errors.append({
                'file': filepath,
                'line': _line_of(ls, m.start()),
                'col': 1,
                'message': f"Rule 17.2: UserDocumentAuthorization.isAuthorized called with raw integer '{m.group('num')}' as module code. Use CoreConstants module constants instead.",
                'source': 'Rule-17.2-Invalid-Module-Code'
            })
    return errors

def check_rule_17_3_file_upload_routing():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if 'new FileData(' in line or 'commonDao.saveFileData' in line:
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.3: Use FileManagementService to save attachments; do not instantiate FileData or call commonDao.saveFileData directly.",
                    'source': 'Rule-17.3-Direct-FileData-Usage'
                })
    return errors

def check_rule_17_4_dual_path_stored_procedures():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        if 'prepareCall' in content:
            if 'oracledb' not in content.lower():
                ls = _get_line_starts(content)
                idx = content.find('prepareCall')
                errors.append({
                    'file': filepath,
                    'line': _line_of(ls, idx),
                    'col': 1,
                    'message': "Rule 17.4: PrepareCall call site must branch on '${oracledb}' (Oracle / MySQL dual-path) to support both dialects.",
                    'source': 'Rule-17.4-Oracle-MySQL-Dual-Path'
                })
    return errors

def check_rule_17_5_award_mutation_bypass():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if 'setAwardSequenceStatus' in line and 'ACTIVE' in line:
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.5: Do not directly set Award status to ACTIVE. Use AwardVersionService copy / PENDING / workflow activation paths.",
                    'source': 'Rule-17.5-Direct-Award-Activation'
                })
    return errors

def check_rule_17_6_elastic_sync():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        if not re.search(r'@(Service|Component)\b', content):
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        classes = parse_classes_in_file(filepath, nc)
        for cls in classes:
            method_pat = re.compile(
                r'(?:public|protected)\s+(?:[a-zA-Z0-9_.]|<|>|\[|\])+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
            )
            for m in method_pat.finditer(cls['class_chunk']):
                start = cls['class_chunk'].find('{', m.end() - 1)
                if start == -1:
                    continue
                brace = 0
                body = ''
                for i in range(start, len(cls['class_chunk'])):
                    c = cls['class_chunk'][i]
                    if c == '{':
                        brace += 1
                    elif c == '}':
                        brace -= 1
                        if brace == 0:
                            body = cls['class_chunk'][start+1:i]
                            break
                if re.search(r'\b(saveOrUpdate)(Proposal|Award|Agreement|ServiceRequest)\b', body):
                    if 'elasticSyncOperation' not in body and 'initiateSyncForElasticQueueRequest' not in body:
                        offset = cls['start_pos'] + m.start()
                        errors.append({
                            'file': filepath,
                            'line': _line_of(ls, offset),
                            'col': 1,
                            'message': f"Rule 17.6: Method mutates searchable module but appears to be missing Elastic sync call (elasticSyncOperation.initiateSyncForElasticQueueRequest).",
                            'source': 'Rule-17.6-Missing-Elastic-Sync'
                        })
    return errors

def check_rule_17_7_async_user_context():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        nc = _strip_comments(content)
        ls = _get_line_starts(content)
        classes = parse_classes_in_file(filepath, nc)
        for cls in classes:
            method_pat = re.compile(
                r'(?:public|protected)\s+(?:[a-zA-Z0-9_.]|<|>|\[|\])+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
            )
            for m in method_pat.finditer(cls['class_chunk']):
                preceding = cls['class_chunk'][max(0, m.start()-300):m.start()]
                if any(ann in preceding for ann in ('@RabbitListener', '@Scheduled', '@Quartz')):
                    start = cls['class_chunk'].find('{', m.end() - 1)
                    if start == -1:
                        continue
                    brace = 0
                    body = ''
                    for i in range(start, len(cls['class_chunk'])):
                        c = cls['class_chunk'][i]
                        if c == '{':
                            brace += 1
                        elif c == '}':
                            brace -= 1
                            if brace == 0:
                                body = cls['class_chunk'][start+1:i]
                                break
                    if 'UserContext.set' not in body:
                        offset = cls['start_pos'] + m.start()
                        errors.append({
                            'file': filepath,
                            'line': _line_of(ls, offset),
                            'col': 1,
                            'message': f"Rule 17.7: Async/Scheduler method '{m.group('name')}' must set UserContext first.",
                            'source': 'Rule-17.7-Async-User-Context'
                        })
    return errors

def check_rule_17_8_hardcoded_client_logic():
    errors = []
    pat = re.compile(r'\.(?:startsWith|equals|equalsIgnoreCase)\s*\(\s*"(SMU|WUSTL|MIT|NUS|NTU|UPENN)"\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if pat.search(line):
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.8: Do not hardcode client-specific logic (e.g. 'SMU'). Use parameter-driven configuration via PARAMETER table.",
                    'source': 'Rule-17.8-Hardcoded-Client-Fork'
                })
    return errors

def check_rule_17_9_log_tokens():
    errors = []
    pat = re.compile(r'\blog\.[a-z]+\([^)]*\b(jwt|token|cookie|cookie_token|access_token|accessToken)\b', re.IGNORECASE)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if pat.search(line):
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.9: Do not log raw JWT tokens, cookies, or access tokens.",
                    'source': 'Rule-17.9-Log-Token'
                })
    return errors

def check_rule_17_10_core_dependency():
    errors = []
    for filepath in find_java_files():
        filepath_norm = filepath.replace('\\', '/')
        if '/fibi-core/' in filepath_norm or '/core/' in filepath_norm:
            content = _read_file(filepath)
            if not content:
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if line.strip().startswith('import com.polus.fibicomp.'):
                    if 'import com.polus.fibicomp.core.' not in line:
                        errors.append({
                            'file': filepath,
                            'line': i + 1,
                            'col': 1,
                            'message': "Rule 17.10: fibi-core must not depend on domain/feature modules. Clean up domain module import.",
                            'source': 'Rule-17.10-Core-Dependency-Violation'
                        })
    return errors

def check_rule_17_11_char_boolean_conversion():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if '@Column' in line and ('IS_' in line.upper() or 'HAS_' in line.upper() or '_FLAG' in line.upper() or '_YN' in line.upper()):
                for j in range(i+1, min(i+5, len(lines))):
                    next_line = lines[j].strip()
                    if next_line.startswith('@') or not next_line:
                        continue
                    m = re.search(r'\bString\s+[a-zA-Z0-9_]+\s*;', next_line)
                    if m:
                        errors.append({
                            'file': filepath,
                            'line': i + 1,
                            'col': 1,
                            'message': "Rule 17.11: Y/N CHAR columns must map to Boolean type and carry @Convert(converter = JpaCharBooleanConversion.class).",
                            'source': 'Rule-17.11-Char-Boolean-Mapping'
                        })
                        break
                    elif 'Boolean' in next_line:
                        window = '\n'.join(lines[i:j])
                        if 'JpaCharBooleanConversion' not in window:
                            errors.append({
                                'file': filepath,
                                'line': i + 1,
                                'col': 1,
                                'message': "Rule 17.11: Boolean column mapped to Y/N CHAR database column must specify @Convert(converter = JpaCharBooleanConversion.class).",
                                'source': 'Rule-17.11-Char-Boolean-Mapping'
                            })
                        break
    return errors

def check_rule_17_12_timezone_timestamps():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if 'new Timestamp(System.currentTimeMillis())' in line or 'new Timestamp(new Date().getTime())' in line:
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.12: Use commonDao.getCurrentTimestamp() to retrieve timezone-aware database timestamps.",
                    'source': 'Rule-17.12-Timezone-Timestamp'
                })
    return errors

def check_rule_17_13_permitAll_justification():
    errors = []
    for filepath in find_java_files():
        if 'Security' in filepath or 'WebSecurity' in filepath:
            content = _read_file(filepath)
            if not content:
                continue
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if 'permitAll()' in line:
                    window = '\n'.join(lines[max(0, i-5):i])
                    if not any(w in window.lower() for w in ('justification', 'reason', 'because', 'why', 'ticket')):
                        errors.append({
                            'file': filepath,
                            'line': i + 1,
                            'col': 1,
                            'message': "Rule 17.13: Widening security paths (permitAll()) requires a comment providing justification.",
                            'source': 'Rule-17.13-PermitAll-Justification'
                        })
    return errors

def check_rule_17_14_native_sql_concat():
    errors = []
    pat = re.compile(r'\+\s*AuthenticatedUser\.')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if pat.search(line) and any(w in line.upper() for w in ('SELECT', 'UPDATE', 'AND', 'WHERE', 'INSERT')):
                errors.append({
                    'file': filepath,
                    'line': i + 1,
                    'col': 1,
                    'message': "Rule 17.14: Do not concatenate AuthenticatedUser fields into SQL strings. Use query.setParameter() instead.",
                    'source': 'Rule-17.14-SQL-Concatenation'
                })
    return errors

def warning(file_path, line, message, source, col=1):
    return {
        'file': file_path,
        'line': line,
        'col': col,
        'message': message,
        'source': source,
        'severity': 'warning'
    }

def error(file_path, line, message, source, col=1):
    return {
        'file': file_path,
        'line': line,
        'col': col,
        'message': message,
        'source': source,
        'severity': 'error'
    }

def _first_added_line(filepath, added_lines_by_file):
    lines = added_lines_by_file.get(normalize_path(filepath), set())
    return min(lines) if lines else 1

def _read_pr_body():
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if not event_path or not os.path.exists(event_path):
        return ''
    try:
        with open(event_path, 'r', encoding='utf-8', errors='ignore') as f:
            event = json.load(f)
        return ((event.get('pull_request') or {}).get('body') or '')
    except Exception as e:
        log(f"Unable to read PR body from event payload: {e}")
        return ''

def check_changed_behavior_tests_warning():
    added_lines_by_file = get_pr_added_lines()
    changed_files = set(added_lines_by_file.keys())
    if not changed_files:
        return []

    changed_production_java = [
        f for f in changed_files
        if f.endswith('.java') and '/src/test/' not in f and not re.search(r'Test\.java$', f)
    ]
    if not changed_production_java:
        return []

    has_test_change = any('/src/test/' in f or re.search(r'Test\.java$', f) for f in changed_files)
    pr_body = _read_pr_body().lower()
    has_testing_note = 'testing' in pr_body or 'manual verification' in pr_body or 'tests deferred' in pr_body
    if has_test_change or has_testing_note:
        return []

    target = sorted(changed_production_java)[0]
    return [warning(
        target,
        _first_added_line(target, added_lines_by_file),
        "Rule 1.3 [WARN]: Behavior changed without a test update or PR testing note. Prefer adding/updating tests, or document manual verification / deferral.",
        RULE_CHANGED_BEHAVIOR_TESTS
    )]

def check_sonar_major_justification_warning():
    sonar_files = [f for f in ['sonar-report.json', 'sonar-issues.json', '.scannerwork/report-task.txt'] if os.path.exists(f)]
    if not sonar_files:
        return []

    pr_body = _read_pr_body().lower()
    if 'sonar' in pr_body and ('major' in pr_body or 'justification' in pr_body):
        return []

    return [warning(
        sonar_files[0],
        1,
        "Rule 1.7 [WARN]: New Sonar Major issues should be justified in the PR or fixed before merge.",
        RULE_SONAR_MAJOR_JUSTIFICATION
    )]

def _parse_pom_dependencies(pom_file):
    content = _read_file(pom_file)
    if not content:
        return []
    deps = []
    line_starts = _get_line_starts(content)
    for dep_match in re.finditer(r'<dependency>(.*?)</dependency>', content, re.DOTALL):
        block = dep_match.group(1)
        group_match = re.search(r'<groupId>\s*([^<]+?)\s*</groupId>', block)
        artifact_match = re.search(r'<artifactId>\s*([^<]+?)\s*</artifactId>', block)
        version_match = re.search(r'<version>\s*([^<]+?)\s*</version>', block)
        if not artifact_match or not version_match:
            continue
        deps.append({
            'group': group_match.group(1).strip() if group_match else '',
            'artifact': artifact_match.group(1).strip(),
            'version': version_match.group(1).strip(),
            'line': _line_of(line_starts, dep_match.start() + version_match.start())
        })
    return deps

def check_pin_versions_warning():
    errors = []
    for pom_file in find_pom_files():
        family_versions = {}
        for dep in _parse_pom_dependencies(pom_file):
            version = dep['version']
            family = dep['group'] or dep['artifact'].split('-')[0]
            if version and not version.startswith('${'):
                errors.append(warning(
                    pom_file,
                    dep['line'],
                    "Rule 1.8 [WARN]: Prefer pinning dependency versions through one property per library family.",
                    RULE_PIN_DEPENDENCY_VERSIONS
                ))
            family_versions.setdefault(family, set()).add(version)

        for family, versions in family_versions.items():
            literal_versions = {v for v in versions if v and not v.startswith('${')}
            if len(literal_versions) > 1:
                errors.append(warning(
                    pom_file,
                    1,
                    f"Rule 1.8 [WARN]: Dependency family '{family}' uses multiple literal versions. Use one shared property.",
                    RULE_PIN_DEPENDENCY_VERSIONS
                ))
    return errors

def check_document_new_properties_warning():
    errors = []
    property_file_pat = re.compile(r'(^|/)(application|bootstrap).*\.(properties|ya?ml)$|(^|/)config/.*\.(properties|ya?ml)$')
    added_lines_by_file = get_pr_added_lines()
    for filepath in added_lines_by_file:
        if not property_file_pat.search(filepath):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for line_no in added_lines_by_file.get(filepath, set()):
            if line_no > len(lines):
                continue
            stripped = lines[line_no - 1].strip()
            if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                continue
            if '=' in stripped or re.match(r'^[A-Za-z0-9_.-]+\s*:', stripped):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 1.9 [WARN]: New configuration properties should be externalized and documented.",
                    RULE_DOCUMENT_NEW_PROPERTIES
                ))
    return errors

def check_uncommon_abbreviations_warning():
    errors = []
    bad_abbrev = re.compile(r'\b[A-Za-z0-9_]*(condtn|svc|abs|cfg|mgr|num|txt|addr|usr)[A-Za-z0-9_]*\b', re.IGNORECASE)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if bad_abbrev.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.7 [WARN]: Avoid uncommon abbreviations; prefer clear domain names.",
                    RULE_UNCOMMON_ABBREVIATIONS
                ))
    return errors

def check_service_dao_interface_impl_warning():
    errors = []
    java_files = find_java_files()
    known_types = {os.path.splitext(os.path.basename(f))[0] for f in java_files}
    for filepath in java_files:
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            if not re.search(r'\bclass\s+\w+(Service|Dao|DAO)\b', line):
                continue
            window = '\n'.join(lines[max(0, idx - 5):idx + 2])
            class_match = re.search(r'\bclass\s+(\w+)', line)
            if not class_match or ('@Service' not in window and '@Repository' not in window):
                continue
            class_name = class_match.group(1)
            base_name = re.sub(r'Impl$', '', class_name)
            if ' implements ' in line or class_name.endswith('Impl') or base_name in known_types:
                continue
            errors.append(warning(
                filepath,
                idx + 1,
                "Rule 2.8 [WARN]: Where this module uses Service/DAO interfaces, keep the Interface + Impl pattern.",
                RULE_SERVICE_DAO_INTERFACE_IMPL
            ))
    return errors

def check_magic_values_warning():
    errors = []
    magic_pat = re.compile(r'(==|!=|<=|>=|<|>)\s*("[^"]+"|\d+(?:\.\d+)?[dDfFlL]?)')
    allowed = {'0', '1', '-1', '0L', '1L'}
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(_strip_comments(content).splitlines(), 1):
            if 'static final' in line or 'case ' in line:
                continue
            match = magic_pat.search(line)
            if match and match.group(2) not in allowed:
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.9 [WARN]: Avoid magic values; name them with constants or domain types.",
                    RULE_MAGIC_VALUES
                ))
    return errors

def check_enum_fixed_values_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        constants = []
        for line_no, line in enumerate(content.splitlines(), 1):
            if re.search(r'\bstatic\s+final\s+String\s+[A-Z0-9_]+\s*=\s*"[^"]+"', line):
                constants.append(line_no)
        if len(constants) >= 2:
            errors.append(warning(
                filepath,
                constants[0],
                "Rule 2.10 [WARN]: Prefer an enum for fixed related values instead of parallel string constants.",
                RULE_ENUM_FIXED_VALUES
            ))
    return errors

def check_long_literal_suffix_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if re.search(r'\b\d+l\b', line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.11 [WARN]: Use uppercase L, not lowercase l, for long literals.",
                    RULE_LONG_LITERAL_SUFFIX
                ))
    return errors

def check_class_suffixes_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        line_starts = _get_line_starts(content)
        for match in re.finditer(r'\b(abstract\s+)?class\s+(\w+)(?:\s+extends\s+([\w.]+))?', content):
            class_name = match.group(2)
            parent_name = match.group(3) or ''
            line_no = _line_of(line_starts, match.start())
            if match.group(1) and not class_name.startswith('Abstract'):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.12 [WARN]: Abstract classes should use the Abstract prefix.",
                    RULE_CLASS_SUFFIXES
                ))
            if parent_name.endswith('Exception') and not class_name.endswith('Exception'):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.12 [WARN]: Exception classes should use the Exception suffix.",
                    RULE_CLASS_SUFFIXES
                ))
            if ('/src/test/' in normalize_path(filepath) or filepath.endswith('Test.java')) and not class_name.endswith('Test'):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.12 [WARN]: Test classes should use the Test suffix.",
                    RULE_CLASS_SUFFIXES
                ))
    return errors

def check_boolean_naming_warning():
    errors = []
    boolean_pat = re.compile(r'\bprivate\s+Boolean\s+is[A-Z]\w*\s*[;=]')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if boolean_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 2.13 [WARN]: Prefer Boolean field names like 'active' over 'isActive' unless explicitly mapped for Lombok/Jackson.",
                    RULE_BOOLEAN_NAMING
                ))
    return errors

def _is_new_file(filepath):
    base_branch = os.environ.get('GITHUB_BASE_REF')
    if not base_branch:
        code, stdout, stderr = run_command("git symbolic-ref --short refs/remotes/origin/HEAD")
        base_branch = stdout.strip().replace("origin/", "") if code == 0 and stdout.strip() else "main"
    norm_path = normalize_path(filepath)
    code, stdout, stderr = run_command(f"git cat-file -e origin/{base_branch}:{norm_path}")
    return code != 0

def check_prefer_slf4j_warning():
    errors = []
    for filepath in find_java_files():
        if not _is_new_file(filepath):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if re.search(r'\b(Logger|LogManager|LoggerFactory)\.getLogger\b', line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 3.5 [WARN]: Prefer Lombok @Slf4j on new classes instead of manual Logger instantiation.",
                    RULE_PREFER_SLF4J
                ))
    return errors

def check_lombok_dto_warning():
    errors = []
    getter_pat = re.compile(r'\bpublic\s+(?!class\b)[a-zA-Z0-9_<>]+\s+get[A-Z]\w*\s*\(\s*\)\s*(?:\{|throws\b)')
    is_getter_pat = re.compile(r'\bpublic\s+boolean\s+is[A-Z]\w*\s*\(\s*\)\s*(?:\{|throws\b)')
    setter_pat = re.compile(r'\bpublic\s+void\s+set[A-Z]\w*\s*\(\s*[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*\)\s*(?:\{|throws\b)')
    
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_name = cls['class_name']
            is_dto_or_vo = class_name.endswith(('DTO', 'VO', 'Request', 'Response')) or '/dto/' in normalize_path(filepath) or '/vo/' in normalize_path(filepath)
            if not is_dto_or_vo:
                continue
                
            class_chunk = cls['class_chunk']
            start_pos = cls['start_pos']
            
            for pat, desc in [(getter_pat, "getter"), (is_getter_pat, "boolean getter"), (setter_pat, "setter")]:
                for m in pat.finditer(class_chunk):
                    line_num = get_line_num(start_pos + m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 3.6 [WARN]: Use Lombok @Getter/@Setter annotations on DTOs/VOs/request-response types instead of manual {desc}s.",
                        RULE_LOMBOK_DTOS
                    ))
    return errors

def check_spring_all_args_ctor_warning():
    errors = []
    spring_bean_pattern = re.compile(r'@(Component|Service|RestController|Repository|Controller)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            ann_chunk = cls['annotation_chunk']
            if not spring_bean_pattern.search(ann_chunk):
                continue
            if '@AllArgsConstructor' in ann_chunk:
                line_num = get_line_num(cls['start_pos'])
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 3.7 [WARN]: @AllArgsConstructor is for data types — not Spring beans. Use @RequiredArgsConstructor with private final fields instead.",
                    RULE_BEAN_ALL_ARGS_CTOR
                ))
    return errors

def check_async_scheduled_failure_handling_warning():
    errors = []
    async_scheduled_pat = re.compile(r'@(Async|Scheduled)\b')
    
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content_no_comments = re.sub(r'//.*', '', content_no_comments)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in async_scheduled_pat.finditer(content_no_comments):
            start_pos = m.end()
            method_match = re.search(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*(?:throws\s+[a-zA-Z0-9_, ]+)?\s*\{', content_no_comments[start_pos:])
            if not method_match:
                continue
                
            brace_start = start_pos + method_match.end() - 1
            brace_count = 1
            method_body = ""
            for idx in range(brace_start + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        method_body = content_no_comments[brace_start+1:idx]
                        break
            
            if not re.search(r'\btry\b', method_body) or not re.search(r'\bcatch\b', method_body):
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 3.8 [WARN]: @Async/@Scheduled method must handle exceptions using a try-catch block to log or surface failures.",
                    RULE_ASYNC_SCHEDULED_FAILURE
                ))
    return errors

def check_access_static_via_class_warning():
    errors = []
    static_access_pat = re.compile(r'\b(?P<instance>[a-z][a-zA-Z0-9_]*)\.(?P<member>[A-Z][A-Z0-9_]*)\b')
    allowed_instances = {'log', 'logger', 'out', 'err'}
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            for m in static_access_pat.finditer(line):
                if m.group('instance') in allowed_instances:
                    continue
                errors.append(warning(
                    filepath,
                    line_no,
                    f"Rule 4.9 [WARN]: Access static member '{m.group('member')}' via the class name, not the instance variable '{m.group('instance')}'.",
                    RULE_ACCESS_STATIC_VIA_CLASS
                ))
    return errors

def check_deprecated_apis_warning():
    errors = []
    deprecated_methods = [
        (re.compile(r'\.newInstance\('), "Class.newInstance() is deprecated. Use clazz.getDeclaredConstructor().newInstance() instead."),
        (re.compile(r'\bSystem\.runFinalizersOnExit\b'), "System.runFinalizersOnExit() is deprecated and unsafe."),
        (re.compile(r'\bRuntime\.runFinalizersOnExit\b'), "Runtime.runFinalizersOnExit() is deprecated and unsafe."),
        (re.compile(r'\.destroy\('), "Thread.destroy() is deprecated and not implemented."),
        (re.compile(r'\.stop\('), "Thread.stop() is deprecated and unsafe."),
        (re.compile(r'\.suspend\('), "Thread.suspend() is deprecated and unsafe."),
        (re.compile(r'\.resume\('), "Thread.resume() is deprecated and unsafe.")
    ]
    for filepath in find_java_files():
        if not _is_new_file(filepath):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if '@SuppressWarnings' in line and 'deprecation' in line:
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 4.10 [WARN]: Do not suppress deprecation warnings in new code. Avoid using deprecated APIs.",
                    RULE_DEPRECATED_APIS
                ))
            for pat, msg in deprecated_methods:
                if pat.search(line):
                    errors.append(warning(
                        filepath,
                        line_no,
                        f"Rule 4.10 [WARN]: Do not use deprecated APIs in new code: {msg}",
                        RULE_DEPRECATED_APIS
                    ))
    return errors

def check_null_safe_equality_warning():
    errors = []
    eq_pat = re.compile(r'\b(?P<var>[a-z][a-zA-Z0-9_]*)\.equals\(')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            for m in eq_pat.finditer(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    f"Rule 4.11 [WARN]: Prefer null-safe equality check Objects.equals({m.group('var')}, ...) or constant-first equality instead of {m.group('var')}.equals(...).",
                    RULE_NULL_SAFE_EQUALITY
                ))
    return errors

def check_dto_wrappers_warning():
    errors = []
    primitive_pat = re.compile(r'\bprivate\s+(int|long|boolean|double|float|char|byte|short)\s+[a-zA-Z0-9_]+\s*;')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_name = cls['class_name']
            is_dto_or_vo = class_name.endswith(('DTO', 'VO', 'Request', 'Response')) or '/dto/' in normalize_path(filepath) or '/vo/' in normalize_path(filepath)
            if not is_dto_or_vo:
                continue
            class_chunk = cls['class_chunk']
            start_pos = cls['start_pos']
            for m in primitive_pat.finditer(class_chunk):
                line_num = get_line_num(start_pos + m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 4.12 [WARN]: DTO/VO field should use wrapper classes (e.g. Integer, Boolean) instead of primitives to allow representing unset/null values.",
                    RULE_DTO_WRAPPERS
                ))
    return errors

def check_stringbuilder_in_loops_warning():
    errors = []
    loop_pat = re.compile(r'\b(for|while)\s*\(', re.DOTALL)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in loop_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_search = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_search:
                continue
            brace_start = start_pos + brace_search.start()
            brace_count = 1
            loop_body = ""
            for idx in range(brace_start + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        loop_body = content_no_comments[brace_start+1:idx]
                        break
            
            if '+=' in loop_body or 'new StringBuilder' in loop_body:
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 4.13 [WARN]: Avoid using StringBuilder instantiation or String concatenation (+=) inside loops. Use a single StringBuilder outside the loop.",
                    RULE_STRINGBUILDER_IN_LOOPS
                ))
    return errors

def check_tightest_visibility_warning():
    errors = []
    public_field_pat = re.compile(r'\bpublic\s+(?!static\b|class\b|interface\b|enum\b)[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*[;=]')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if public_field_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 4.14 [WARN]: Keep member fields private or protected to enforce encapsulation and tightest practical visibility.",
                    RULE_TIGHTEST_VISIBILITY
                ))
    return errors

def check_break_method_signature_warning():
    errors = []
    base_branch = os.environ.get('GITHUB_BASE_REF')
    if not base_branch:
        code, stdout, stderr = run_command("git symbolic-ref --short refs/remotes/origin/HEAD")
        base_branch = stdout.strip().replace("origin/", "") if code == 0 and stdout.strip() else "main"
        
    code, stdout, stderr = run_command(f"git diff --unified=0 origin/{base_branch}...HEAD -- .")
    if code != 0:
        return errors
        
    current_file = None
    deleted_methods = []
    
    for line in stdout.splitlines():
        if line.startswith('--- a/'):
            current_file = normalize_path(line[6:])
            continue
        if line.startswith('-') and not line.startswith('---'):
            stripped = line[1:].strip()
            if re.match(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*\(', stripped):
                method_name_match = re.search(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+(?P<name>[a-zA-Z0-9_]+)\s*\(', stripped)
                if method_name_match:
                    deleted_methods.append((current_file, method_name_match.group('name'), stripped))
                    
    added_lines_by_file = get_pr_added_lines()
    for filepath, method_name, old_sig in deleted_methods:
        if not os.path.exists(filepath):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_num = _first_added_line(filepath, added_lines_by_file)
        if method_name not in content_no_comments:
            errors.append(warning(
                filepath,
                line_num,
                f"Rule 4.15 [WARN]: Do not break published method signature '{old_sig}' in place. Deprecate and add a replacement method instead.",
                RULE_BREAK_METHOD_SIGNATURE
            ))
        else:
            if '@Deprecated' not in content:
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 4.15 [WARN]: Do not break published method signature '{old_sig}' in place. Deprecate and add a replacement method instead.",
                    RULE_BREAK_METHOD_SIGNATURE
                ))
    return errors

def check_collection_capacity_warning():
    errors = []
    empty_constructor_pat = re.compile(r'\bnew\s+(?:[a-zA-Z0-9_]+\.)*(ArrayList|HashMap)\s*(<[^>]*>)?\s*\(\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if empty_constructor_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 5.8 [WARN]: Specify initial capacity for ArrayList/HashMap if the size is known to avoid resizing overhead.",
                    RULE_COLLECTION_CAPACITY
                ))
    return errors

def check_iterate_map_entryset_warning():
    errors = []
    keyset_loop_pat = re.compile(r'\bfor\s*\(\s*[a-zA-Z0-9_<>]+ \s*(?P<key>[a-zA-Z0-9_]+)\s*:\s*(?P<map>[a-zA-Z0-9_]+)\.keySet\(\)\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in keyset_loop_pat.finditer(content_no_comments):
            start_pos = m.end()
            key_var = m.group('key')
            map_var = m.group('map')
            
            brace_search = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_search:
                continue
            brace_start = start_pos + brace_search.start()
            brace_count = 1
            loop_body = ""
            for idx in range(brace_start + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        loop_body = content_no_comments[brace_start+1:idx]
                        break
            
            get_pat = re.compile(r'\b' + re.escape(map_var) + r'\.get\(\s*' + re.escape(key_var) + r'\s*\)')
            if get_pat.search(loop_body):
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 5.9 [WARN]: Iterate map '{map_var}' via entrySet() or forEach instead of keySet() and calling map.get({key_var}) inside the loop.",
                    RULE_ITERATE_MAP_ENTRYSET
                ))
    return errors

def check_spring_singleton_vs_dcl_warning():
    errors = []
    dcl_pat = re.compile(r'\bsynchronized\s*\([^)]*\)\s*\{[\s\n]*if\s*\(\s*[a-zA-Z0-9_]+\s*==\s*null\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in dcl_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            errors.append(warning(
                filepath,
                line_num,
                "Rule 5.10 [WARN]: Prefer Spring singleton beans over manual double-checked locking singletons.",
                RULE_SPRING_SINGLETON_VS_DCL
            ))
    return errors

def check_threadlocal_random_warning():
    errors = []
    random_pat = re.compile(r'\bnew\s+(?:[a-zA-Z0-9_]+\.)*Random\s*\(\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if random_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 5.11 [WARN]: Prefer ThreadLocalRandom.current() over new Random() under contention.",
                    RULE_THREADLOCAL_RANDOM
                ))
    return errors

def check_nesting_level_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_chunk = cls['class_chunk']
            start_pos = cls['start_pos']
            
            method_pat = re.compile(r'\b(?:public|protected|private|static|\s)+\s+[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*(?:throws\s+[a-zA-Z0-9_, ]+)?\s*\{')
            for m in method_pat.finditer(class_chunk):
                method_start = m.end() - 1
                brace_count = 1
                method_body = ""
                for idx in range(method_start + 1, len(class_chunk)):
                    char = class_chunk[idx]
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            method_body = class_chunk[method_start+1:idx]
                            break
                
                curr_depth = 0
                for body_idx, char in enumerate(method_body):
                    if char == '{':
                        curr_depth += 1
                        if curr_depth > 3:
                            char_pos = start_pos + method_start + 1 + body_idx
                            line_num = get_line_num(char_pos)
                            errors.append(warning(
                                filepath,
                                line_num,
                                "Rule 6.3 [WARN]: Nesting level exceeds 3. Simplify control flow using guard clauses or break blocks into helper methods.",
                                RULE_NESTING_LEVEL
                            ))
                            break
                    elif char == '}':
                        curr_depth -= 1
    return errors

def check_complex_boolean_warning():
    errors = []
    if_pat = re.compile(r'\bif\s*\((?P<cond>[^)]+)\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            for m in if_pat.finditer(line):
                cond = m.group('cond')
                ops_count = len(re.findall(r'&&|\|\|', cond))
                if ops_count >= 3:
                    errors.append(warning(
                        filepath,
                        line_no,
                        "Rule 6.4 [WARN]: Name complex boolean expressions by extracting them into descriptive local boolean variables.",
                        RULE_COMPLEX_BOOLEAN
                    ))
    return errors

def check_http_verb_semantics_warning():
    errors = []
    get_mapping_pat = re.compile(r'@GetMapping\b')
    post_mapping_pat = re.compile(r'@PostMapping\b')
    
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in get_mapping_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            sig_chunk = content_no_comments[start_pos : start_pos + brace_match.start() + 1]
            method_match = re.search(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+(?P<name>[a-zA-Z0-9_]+)\s*\(', sig_chunk)
            if method_match:
                name = method_match.group('name').lower()
                if any(x in name for x in ['save', 'create', 'update', 'delete', 'insert', 'modify']):
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 7.9 [WARN]: HTTP GET mapping used on data-modifying method '{method_match.group('name')}'. Prefer Post/Put/DeleteMapping.",
                        RULE_HTTP_VERB_SEMANTICS
                    ))
                    
        for m in post_mapping_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            start_pos = m.end()
            mapping_str_match = re.match(r'\s*\(\s*(?:value\s*=\s*)?"([^"]+)"', content_no_comments[start_pos:])
            if mapping_str_match:
                path = mapping_str_match.group(1)
                if any(x in path for x in ['/save', '/delete', '/update']):
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 7.9 [WARN]: Avoid using action verbs in POST path '{path}'. Prefer RESTful noun-based resources (e.g. POST to /resources instead of /saveResource).",
                        RULE_HTTP_VERB_SEMANTICS
                    ))
            
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            sig_chunk = content_no_comments[start_pos : start_pos + brace_match.start() + 1]
            method_match = re.search(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+(?P<name>[a-zA-Z0-9_]+)\s*\(', sig_chunk)
            if method_match:
                name = method_match.group('name').lower()
                if any(name.startswith(x) for x in ['get', 'fetch', 'find', 'query']):
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 7.9 [WARN]: HTTP POST mapping used on retrieval-like method '{method_match.group('name')}'. Prefer GetMapping.",
                        RULE_HTTP_VERB_SEMANTICS
                    ))
    return errors

def check_proper_status_codes_warning():
    errors = []
    fail_ok_pat = re.compile(r'\bif\s*\(.*(?:error|fail|invalid).*\)\s*\{[^}]*return\s+ResponseEntity\.ok\(')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for m in fail_ok_pat.finditer(content_no_comments):
            line_starts = [0]
            for match in re.finditer(r'\n', content):
                line_starts.append(match.end())
            import bisect
            line_num = bisect.bisect_right(line_starts, m.start())
            errors.append(warning(
                filepath,
                line_num,
                "Rule 7.10 [WARN]: Do not return HTTP 200 (ResponseEntity.ok) for validation/business failures. Use appropriate 4xx/5xx status codes.",
                RULE_PROPER_STATUS_CODES
            ))
    return errors

def check_thin_controllers_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        is_controller = '@RestController' in content_no_comments or '@Controller' in content_no_comments
        if not is_controller:
            continue
            
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        repo_dao_pat = re.compile(r'@Autowired\s+(?:private\s+)?[a-zA-Z0-9_<>@]+\s+[a-zA-Z0-9_]+(Repository|DAO)\b')
        for m in repo_dao_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            errors.append(warning(
                filepath,
                line_num,
                "Rule 7.11 [WARN]: Thin controllers: Do not autowire Repositories or DAOs directly in controllers. Delegate to service layer.",
                RULE_THIN_CONTROLLERS
            ))
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_chunk = cls['class_chunk']
            start_pos = cls['start_pos']
            
            method_pat = re.compile(r'\b(?:public|protected|private|static|\s)+\s+[a-zA-Z0-9_<>]+\s+[a-zA-Z0-9_]+\s*\([^)]*\)\s*(?:throws\s+[a-zA-Z0-9_, ]+)?\s*\{')
            for m in method_pat.finditer(class_chunk):
                method_start = m.end() - 1
                brace_count = 1
                method_body = ""
                for idx in range(method_start + 1, len(class_chunk)):
                    char = class_chunk[idx]
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            method_body = class_chunk[method_start+1:idx]
                            break
                
                lines = [l for l in method_body.splitlines() if l.strip()]
                if len(lines) > 20:
                    line_num = get_line_num(start_pos + m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 7.11 [WARN]: Thin controllers: Controller method body is too long ({len(lines)} lines, max allowed is 20). Move business logic to service layer.",
                        RULE_THIN_CONTROLLERS
                    ))
    return errors

def check_error_envelope_stack_trace_warning():
    errors = []
    stack_trace_pat = re.compile(r'\.printStackTrace\(|\.getStackTrace\(')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if stack_trace_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 7.12 [WARN]: Do not expose stack traces to clients. Use logger to log stack trace and return a standard error envelope.",
                    RULE_ERROR_ENVELOPE_STACK_TRACE
                ))
    return errors

def check_paginate_lists_warning():
    errors = []
    get_mapping_pat = re.compile(r'@GetMapping\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in get_mapping_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            sig_chunk = content_no_comments[start_pos : start_pos + brace_match.start() + 1]
            method_match = re.search(r'\bpublic\s+(?:ResponseEntity\s*<\s*)?(?:List|Collection)\s*<\s*[a-zA-Z0-9_<> ]+\s*>\s*>?\s+(?P<name>[a-zA-Z0-9_]+)\s*\((?P<args>[^)]*)\)', sig_chunk)
            if method_match:
                args = method_match.group('args')
                if 'Pageable' not in args and not ('page' in args.lower() and 'size' in args.lower()):
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 7.13 [WARN]: Paginate list endpoints consistently. Method '{method_match.group('name')}' returns a List but does not accept Pageable or page/size request parameters.",
                        RULE_PAGINATE_LISTS
                    ))
    return errors

def check_avoid_n_plus_one_warning():
    errors = []
    assoc_pat = re.compile(r'@(OneToMany|ManyToMany)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in assoc_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            lines = content_no_comments.splitlines()
            start_idx = max(0, line_num - 3)
            end_idx = min(len(lines), line_num + 3)
            surrounding_code = "\n".join(lines[start_idx:end_idx])
            
            if '@BatchSize' not in surrounding_code and '@Fetch' not in surrounding_code:
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 8.6 [WARN]: Avoid N+1 select issues. Use @BatchSize or @Fetch(FetchMode.SUBSELECT) on OneToMany/ManyToMany collections.",
                    RULE_AVOID_N_PLUS_ONE
                ))
    return errors

def check_named_params_in_query_warning():
    errors = []
    query_pat = re.compile(r'@Query\s*\((?P<val>[^)]+)\)', re.DOTALL)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in query_pat.finditer(content_no_comments):
            val = m.group('val')
            if re.search(r'\?\d+', val):
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 8.7 [WARN]: Use named parameters (e.g. :paramName) in @Query instead of positional parameters (?1).",
                    RULE_NAMED_PARAMS_IN_QUERY
                ))
    return errors

def check_projections_for_search_warning():
    errors = []
    entity_names = set()
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for m in re.finditer(r'@Entity\s*(?:@[a-zA-Z0-9_]+(?:\([^)]*\))?\s*)*\bclass\s+(?P<name>[a-zA-Z0-9_]+)', content_no_comments):
            entity_names.add(m.group('name'))
                
    for filepath in find_java_files():
        if not filepath.endswith('Repository.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if 'List<' in line or 'Page<' in line:
                for entity in entity_names:
                    if f'List<{entity}>' in line or f'Page<{entity}>' in line:
                        if 'find' in line or 'search' in line or 'query' in line:
                            errors.append(warning(
                                filepath,
                                line_no,
                                f"Rule 8.8 [WARN]: Use Projections or DTOs instead of full Entity class '{entity}' for search/list query methods to improve performance.",
                                RULE_PROJECTIONS_FOR_SEARCH
                            ))
    return errors

def check_prefer_jpql_criteria_warning():
    errors = []
    query_pat = re.compile(r'@Query\s*\((?P<val>[^)]+)\)', re.DOTALL)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in query_pat.finditer(content_no_comments):
            val = m.group('val')
            if 'nativeQuery' in val and 'true' in val:
                line_num = get_line_num(m.start())
                lines = content.splitlines()
                has_justification = False
                for idx in range(max(0, line_num - 4), line_num - 1):
                    line = lines[idx].strip()
                    if (line.startswith('//') or line.startswith('/*') or line.startswith('*')) and any(w in line.lower() for w in ['justification', 'reason', 'explain', 'why', 'native']):
                        has_justification = True
                        break
                
                if not has_justification:
                    errors.append(warning(
                        filepath,
                        line_num,
                        "Rule 8.9 [WARN]: Prefer JPQL/Criteria over native SQL. Native SQL should only be used when required and justified in comments.",
                        RULE_PREFER_JPQL_CRITERIA
                    ))
    return errors

def check_native_sql_explicit_columns_warning():
    errors = []
    query_pat = re.compile(r'@Query\s*\((?P<val>[^)]+)\)', re.DOTALL)
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in query_pat.finditer(content_no_comments):
            val = m.group('val')
            if 'nativeQuery' in val and 'true' in val:
                if re.search(r'\bSELECT\s+\*\s+FROM\b', val, re.IGNORECASE):
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        "Rule 8.10 [WARN]: Native SQL must list explicit columns. Do not use 'SELECT *'.",
                        RULE_NATIVE_SQL_EXPLICIT_COLUMNS
                    ))
    return errors

def check_transactional_readonly_warning():
    errors = []
    tx_pat = re.compile(r'@Transactional\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in tx_pat.finditer(content_no_comments):
            start_pos = m.end()
            tx_args_match = re.match(r'\s*\([^)]*\)', content_no_comments[start_pos:])
            has_readonly = False
            if tx_args_match:
                if 'readOnly' in tx_args_match.group(0):
                    has_readonly = True
            
            if not has_readonly:
                method_match = re.search(r'\bpublic\s+[a-zA-Z0-9_<>]+\s+(?P<name>[a-zA-Z0-9_]+)\s*\(', content_no_comments[start_pos:])
                if method_match:
                    name = method_match.group('name')
                    if name.startswith(('get', 'fetch', 'find', 'read', 'load')):
                        line_num = get_line_num(m.start())
                        errors.append(warning(
                            filepath,
                            line_num,
                            f"Rule 8.11 [WARN]: Use @Transactional(readOnly = true) for read-only method '{name}' to optimize performance.",
                            RULE_TRANSACTIONAL_READONLY
                        ))
    return errors

def check_no_transaction_remote_io_warning():
    errors = []
    tx_pat = re.compile(r'@Transactional\b')
    remote_io_indicators = ['RestTemplate', 'WebClient', 'HttpClient', 'FeignClient', 'Client.']
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in tx_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            method_start = start_pos + brace_match.start()
            brace_count = 1
            method_body = ""
            for idx in range(method_start + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        method_body = content_no_comments[method_start+1:idx]
                        break
            
            for indicator in remote_io_indicators:
                if indicator in method_body:
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 8.12 [WARN]: Do not hold DB transactions across remote I/O (found '{indicator}' usage inside @Transactional method).",
                        RULE_NO_TRANSACTION_REMOTE_IO
                    ))
                    break
    return errors

def check_avoid_self_invocation_warning():
    errors = []
    annotated_method_pat = re.compile(r'@(Transactional|Async|Scheduled)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        classes = parse_classes_in_file(filepath, content_no_comments)
        for cls in classes:
            class_chunk = cls['class_chunk']
            start_pos = cls['start_pos']
            
            special_methods = set()
            method_pat = re.compile(r'\b(?:public|protected|private|static|\s)+\s+[a-zA-Z0-9_<>]+\s+(?P<name>[a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[a-zA-Z0-9_, ]+)?\s*\{')
            for m in annotated_method_pat.finditer(class_chunk):
                method_match = method_pat.search(class_chunk[m.end():])
                if method_match:
                    special_methods.add(method_match.group('name'))
            
            for method_name in special_methods:
                self_call_pat = re.compile(r'\b(this\.)?' + re.escape(method_name) + r'\s*\(')
                for call_match in self_call_pat.finditer(class_chunk):
                    call_idx = call_match.start()
                    surrounding = class_chunk[max(0, call_idx - 50):call_idx]
                    if '@' in surrounding and any(x in surrounding for x in ['Transactional', 'Async', 'Scheduled']):
                        continue
                    
                    line_num = get_line_num(start_pos + call_idx)
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 8.13 [WARN]: Avoid self-invocation bypassing the Spring proxy when calling special method '{method_name}()'.",
                        RULE_AVOID_SELF_INVOCATION
                    ))
    return errors

def check_avoid_generic_update_warning():
    errors = []
    modifying_pat = re.compile(r'@Modifying\b')
    for filepath in find_java_files():
        if not filepath.endswith('Repository.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in modifying_pat.finditer(content_no_comments):
            start_pos = m.end()
            method_match = re.search(r'\b(?:public|void|int|long|\s)+\s+(?P<name>[a-zA-Z0-9_]+)\s*\(', content_no_comments[start_pos:])
            if method_match:
                name = method_match.group('name').lower()
                if any(x == name or 'everything' in name or 'updateall' in name or name.startswith('update') and len(name) < 8 for x in ['update', 'save']):
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        f"Rule 8.14 [WARN]: Avoid generic 'update everything' Repository methods like '{method_match.group('name')}'. Update only columns that changed.",
                        RULE_AVOID_GENERIC_UPDATE
                    ))
    return errors

def check_map_is_columns_warning():
    errors = []
    boolean_field_pat = re.compile(r'\bprivate\s+(Boolean|boolean)\s+(?P<name>active|enabled|deleted|locked)\s*;')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in boolean_field_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            name = m.group('name')
            lines = content_no_comments.splitlines()
            start_idx = max(0, line_num - 3)
            end_idx = min(len(lines), line_num + 3)
            surrounding_code = "\n".join(lines[start_idx:end_idx])
            
            expected_db_col = f"IS_{name.upper()}"
            if expected_db_col not in surrounding_code:
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 8.15 [WARN]: Map DB 'IS_' columns explicitly when POJO field '{name}' drops the prefix (e.g., @Column(name = \"{expected_db_col}\")).",
                    RULE_MAP_IS_COLUMNS
                ))
    return errors

def check_swallow_exception_warning():
    errors = []
    catch_pat = re.compile(r'\bcatch\s*\(\s*[a-zA-Z0-9_]+\s+[a-zA-Z0-9_]+\s*\)\s*\{')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in catch_pat.finditer(content_no_comments):
            start_pos = m.end() - 1
            brace_count = 1
            catch_body = ""
            for idx in range(start_pos + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        catch_body = content_no_comments[start_pos+1:idx]
                        break
            
            stripped_body = catch_body.strip().replace(';', '')
            has_logging = any(x in stripped_body for x in ['log.', 'logger.', 'LogManager'])
            has_throw = 'throw ' in stripped_body
            if not has_logging and not has_throw:
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 9.2 [WARN]: Swallow exception: Do not swallow exceptions in catch blocks. Wrap in ApplicationException and throw, or log with full stack trace.",
                    RULE_SWALLOW_EXCEPTION
                ))
    return errors

def check_log_exc_get_message_warning():
    errors = []
    catch_pat = re.compile(r'\bcatch\s*\(\s*(?P<exc_type>[a-zA-Z0-9_]+)\s+(?P<exc_var>[a-zA-Z0-9_]+)\s*\)\s*\{')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in catch_pat.finditer(content_no_comments):
            start_pos = m.end() - 1
            exc_var = m.group('exc_var')
            brace_count = 1
            catch_body = ""
            for idx in range(start_pos + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        catch_body = content_no_comments[start_pos+1:idx]
                        break
            
            log_getMessage_pat = re.compile(r'\b(log|logger)\.(error|warn|info|debug)\s*\([^)]*' + re.escape(exc_var) + r'\.getMessage\(\)[^)]*\)')
            if log_getMessage_pat.search(catch_body):
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 9.3 [WARN]: If you log at the catch site, pass the full exception object '{exc_var}' instead of just '{exc_var}.getMessage()' to preserve the stack trace.",
                    RULE_LOG_EXC_GET_MESSAGE
                ))
    return errors

def check_catch_npe_index_warning():
    errors = []
    bad_catch_pat = re.compile(r'\bcatch\s*\(\s*(NullPointerException|IndexOutOfBoundsException|ArrayIndexOutOfBoundsException)\s+[a-zA-Z0-9_]+\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in bad_catch_pat.finditer(content_no_comments):
            line_num = get_line_num(m.start())
            errors.append(warning(
                filepath,
                line_num,
                "Rule 9.4 [WARN]: Do not catch NullPointerException or IndexOutOfBoundsException. Pre-check for null or list boundary instead.",
                RULE_CATCH_NPE_INDEX
            ))
    return errors

def check_try_catch_scope_warning():
    errors = []
    try_pat = re.compile(r'\btry\s*\{')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in try_pat.finditer(content_no_comments):
            start_pos = m.end() - 1
            brace_count = 1
            try_body = ""
            for idx in range(start_pos + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        try_body = content_no_comments[start_pos+1:idx]
                        break
            
            lines = [l for l in try_body.splitlines() if l.strip()]
            if len(lines) > 15:
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 9.5 [WARN]: Keep try-catch tightly scoped ({len(lines)} lines inside try, max recommended is 15). Move unrelated code outside the try block.",
                    RULE_TRY_CATCH_SCOPE
                ))
    return errors

def check_prefer_application_exception_warning():
    errors = []
    raw_throw_pat = re.compile(r'\bthrow\s+new\s+(RuntimeException|Exception)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if raw_throw_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 9.6 [WARN]: Prefer throwing ApplicationException (or custom module exceptions) over raw RuntimeException or Exception.",
                    RULE_PREFER_APPLICATION_EXCEPTION
                ))
    return errors

def check_no_print_stack_trace_warning():
    errors = []
    print_trace_pat = re.compile(r'\.printStackTrace\(|\bSystem\.(out|err)\.print')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if print_trace_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 9.7 [WARN]: Do not use printStackTrace() or System.out/err. Use logger (e.g. @Slf4j or LogManager) instead.",
                    RULE_NO_PRINT_STACK_TRACE
                ))
    return errors

def check_brace_spacing_warning():
    errors = []
    no_space_keyword_pat = re.compile(r'\b(if|for|while)\(')
    no_space_op_pat = re.compile(r'\b[a-zA-Z0-9_]+(?:==|!=|<=|>=|&&|\|\|)[a-zA-Z0-9_]+\b')
    brace_next_line_pat = re.compile(r'\b(if|for|while|try|catch)\s*\([^)]*\)\s*\n\s*\{')
    
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        for m in no_space_keyword_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                f"Rule 11.1 [WARN]: Missing space after control flow keyword '{m.group(1)}' (e.g. use 'if (flag)' instead of 'if(flag)').",
                RULE_BRACE_SPACING
            ))
            
        for m in no_space_op_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                f"Rule 11.1 [WARN]: Missing spaces around binary operator in '{m.group(0)}' (e.g. use 'a == b' instead of 'a==b').",
                RULE_BRACE_SPACING
            ))
            
        for m in brace_next_line_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                f"Rule 11.1 [WARN]: Opening brace '{{' for control structure '{m.group(1)}' must be on the same line, not on the next line.",
                RULE_BRACE_SPACING
            ))
            
    return errors

def check_max_line_length_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if len(line) > 120:
                if line.strip().startswith('import '):
                    continue
                errors.append(warning(
                    filepath,
                    line_no,
                    f"Rule 11.2 [WARN]: Line exceeds maximum length of 120 characters (current length: {len(line)}).",
                    RULE_MAX_LINE_LENGTH
                ))
    return errors

def check_utf8_encoding_warning():
    errors = []
    for filepath in find_java_files():
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
            raw.decode('utf-8')
        except UnicodeDecodeError:
            errors.append(warning(
                filepath,
                1,
                "Rule 11.3 [WARN]: Source file encoding must be UTF-8.",
                RULE_UTF8_ENCODING
            ))
    return errors

def check_manual_variable_alignment_warning():
    errors = []
    align_pat = re.compile(r'\b[a-zA-Z0-9_<>]+\s{2,}=\s*[^=]')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if align_pat.search(line):
                if line.strip().startswith('@') or '==' in line:
                    continue
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 11.4 [WARN]: Do not manually align variables with extra spaces before the '=' assignment operator.",
                    RULE_MANUAL_ALIGNMENT
                ))
    return errors

def check_hygiene_whitespace_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        for line_no, line in enumerate(lines, 1):
            if re.search(r'[ \t]+$', line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 11.5 [WARN]: Trailing whitespace detected. Remove any trailing spaces or tabs.",
                    RULE_HYGIENE_WHITESPACE
                ))
        
        if content and not content.endswith('\n') and not content.endswith('\r'):
            errors.append(warning(
                filepath,
                len(lines),
                "Rule 11.5 [WARN]: File must end with a newline character.",
                RULE_HYGIENE_WHITESPACE
            ))
    return errors

def check_commented_code_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                comment_text = stripped[2:].strip()
                if ';' in comment_text and not re.search(r'\bFIBI-\d+\b', comment_text):
                    if any(x in comment_text for x in ['=', '(', ')', 'new ', 'public', 'private', 'void', 'int', 'String']):
                        errors.append(warning(
                            filepath,
                            line_no,
                            "Rule 12.3 [WARN]: Commented-out code must reference a Jira ticket (e.g. FIBI-1234) or be deleted.",
                            RULE_COMMENTED_CODE
                        ))
    return errors

def check_todo_jira_warning():
    errors = []
    todo_pat = re.compile(r'\b(TODO|FIXME)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if todo_pat.search(line):
                if not re.search(r'\bFIBI-\d+\b', line):
                    errors.append(warning(
                        filepath,
                        line_no,
                        "Rule 12.4 [WARN]: TODO / FIXME comments must reference a Jira ticket (e.g. // TODO [FIBI-1234]: ...).",
                        RULE_TODO_JIRA
                    ))
    return errors

def check_layer_package_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        pkg_match = re.search(r'\bpackage\s+(?P<pkg>[a-zA-Z0-9_.]+);', content_no_comments)
        if not pkg_match:
            continue
        pkg = pkg_match.group('pkg')
        
        class_match = re.search(r'\b(?:class|interface|enum)\s+(?P<name>[a-zA-Z0-9_]+)', content_no_comments)
        if not class_match:
            continue
        name = class_match.group('name')
        
        if name.endswith('Controller') and '.controller' not in pkg:
            errors.append(warning(filepath, 1, f"Rule 13.1 [WARN]: Controller class '{name}' must be placed in a package containing '.controller'. Current: '{pkg}'.", RULE_LAYER_PACKAGE))
        elif (name.endswith('Service') or name.endswith('ServiceImpl')) and '.service' not in pkg:
            errors.append(warning(filepath, 1, f"Rule 13.1 [WARN]: Service class '{name}' must be placed in a package containing '.service'. Current: '{pkg}'.", RULE_LAYER_PACKAGE))
        elif (name.endswith('Repository') or name.endswith('Dao') or name.endswith('RepositoryImpl')) and not ('.repository' in pkg or '.dao' in pkg):
            errors.append(warning(filepath, 1, f"Rule 13.1 [WARN]: Repository/DAO class '{name}' must be placed in a package containing '.repository' or '.dao'. Current: '{pkg}'.", RULE_LAYER_PACKAGE))
        elif (name.endswith('DTO') or name.endswith('VO')) and not ('.dto' in pkg or '.vo' in pkg):
            errors.append(warning(filepath, 1, f"Rule 13.1 [WARN]: DTO/VO class '{name}' must be placed in a package containing '.dto' or '.vo'. Current: '{pkg}'.", RULE_LAYER_PACKAGE))
            
    return errors

def check_type_suffixes_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        for m in re.finditer(r'\b(?:class|interface|enum)\s+(?P<name>[a-zA-Z0-9_]+)', content_no_comments):
            name = m.group('name')
            start_idx = m.start()
            preceding_chunk = content_no_comments[max(0, start_idx - 150):start_idx]
            line_num = content_no_comments[:start_idx].count('\n') + 1
            
            if '@RestController' in preceding_chunk or '@Controller' in preceding_chunk:
                if not name.endswith('Controller'):
                    errors.append(warning(filepath, line_num, f"Rule 13.2 [WARN]: Class '{name}' carrying Controller annotation must end with 'Controller' suffix.", RULE_TYPE_SUFFIXES))
            elif '@Service' in preceding_chunk:
                if not (name.endswith('Service') or name.endswith('ServiceImpl')):
                    errors.append(warning(filepath, line_num, f"Rule 13.2 [WARN]: Class '{name}' carrying @Service annotation must end with 'Service' or 'ServiceImpl' suffix.", RULE_TYPE_SUFFIXES))
            elif '@Repository' in preceding_chunk:
                if not (name.endswith('Repository') or name.endswith('Dao') or name.endswith('RepositoryImpl')):
                    errors.append(warning(filepath, line_num, f"Rule 13.2 [WARN]: Class '{name}' carrying @Repository annotation must end with 'Repository', 'Dao', or 'RepositoryImpl' suffix.", RULE_TYPE_SUFFIXES))
                    
    return errors

def check_loop_db_calls_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        loop_pat = re.compile(r'\b(for|while)\s*\([^)]*\)\s*\{|\.forEach\s*\([^)]*\)\s*->\s*\{|\.forEach\s*\([^)]*\)\s*\{')
        for m in loop_pat.finditer(content_no_comments):
            start_pos = m.end() - 1
            brace_count = 1
            loop_body = ""
            for idx in range(start_pos + 1, len(content_no_comments)):
                char = content_no_comments[idx]
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        loop_body = content_no_comments[start_pos+1:idx]
                        break
            
            db_call_pat = re.compile(r'\b[a-zA-Z0-9_]*(?:repository|dao|client|restTemplate|webClient)\b\.[a-zA-Z0-9_]+\s*\(', re.IGNORECASE)
            db_match = db_call_pat.search(loop_body)
            if db_match:
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 14.1 [WARN]: Avoid database/remote calls inside tight loops (found call '{db_match.group(0)}' inside loop body).",
                    RULE_LOOP_DB_CALLS
                ))
    return errors

def check_caching_keys_warning():
    errors = []
    cache_pat = re.compile(r'@(?:[a-zA-Z0-9_.]+\.)?Cacheable\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in cache_pat.finditer(content_no_comments):
            start_pos = m.end()
            args_match = re.match(r'\s*\([^)]*\)', content_no_comments[start_pos:])
            has_key = False
            if args_match:
                if 'key' in args_match.group(0):
                    has_key = True
            if not has_key:
                line_num = get_line_num(m.start())
                errors.append(warning(
                    filepath,
                    line_num,
                    "Rule 14.2 [WARN]: Spring @Cacheable caching should specify explicit cache keys (e.g. key = \"...\").",
                    RULE_CACHING_KEYS
                ))
    return errors

def check_commit_hygiene_warning():
    errors = []
    base_ref = os.getenv('GITHUB_BASE_REF')
    if not base_ref:
        return errors
        
    added_lines_by_file = get_pr_added_lines()
    if not added_lines_by_file:
        return errors
    first_file = next(iter(added_lines_by_file.keys()))
    first_line = _first_added_line(first_file, added_lines_by_file)
    
    import subprocess
    try:
        cmd = "git log -n 1 --format=%s HEAD"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        commit_msgs = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        for msg in commit_msgs:
            if not re.match(r'^FIBI-\d+:', msg, re.IGNORECASE) and not msg.startswith('Merge branch'):
                errors.append(warning(
                    first_file,
                    first_line,
                    f"Rule 15.1 [WARN]: Commit message must start with 'FIBI-XXXX:' Jira ticket ID. Found: '{msg}'.",
                    RULE_COMMIT_HYGIENE
                ))
    except Exception as e:
        log(f"Error checking commit message hygiene: {e}")
        
    return errors

def check_pr_hygiene_warning():
    errors = []
    event_path = os.getenv('GITHUB_EVENT_PATH')
    if not event_path or not os.path.exists(event_path):
        return errors
        
    added_lines_by_file = get_pr_added_lines()
    if not added_lines_by_file:
        return errors
    first_file = next(iter(added_lines_by_file.keys()))
    first_line = _first_added_line(first_file, added_lines_by_file)
    
    try:
        import json
        with open(event_path, 'r', encoding='utf-8') as f:
            event_data = json.load(f)
            
        pr_data = event_data.get('pull_request', {})
        pr_title = pr_data.get('title', '')
        pr_body = pr_data.get('body', '')
        
        if pr_title and not re.match(r'^FIBI-\d+:', pr_title, re.IGNORECASE):
            errors.append(warning(
                first_file,
                first_line,
                f"Rule 15.2 [WARN]: PR title must start with 'FIBI-XXXX:' Jira ticket ID. Current title: '{pr_title}'.",
                RULE_PR_TITLE_HYGIENE
            ))
            
        if pr_body:
            if not re.search(r'\b(jira|fibi-\d+|issues/\d+)\b', pr_body.lower()):
                errors.append(warning(
                    first_file,
                    first_line,
                    "Rule 15.3 [WARN]: PR description must include a Jira ticket link or reference.",
                    RULE_PR_DESC_HYGIENE
                ))
    except Exception as e:
        log(f"Error checking PR title/body hygiene: {e}")
        
    return errors

def check_tests_deterministic_warning():
    errors = []
    thread_sleep_pat = re.compile(r'\bThread\.sleep\s*\(')
    order_pat = re.compile(r'@(FixMethodOrder|TestMethodOrder)\b')
    for filepath in find_java_files():
        if not ('src/test/' in filepath or filepath.endswith('Test.java') or filepath.endswith('Tests.java')):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        for m in thread_sleep_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                "Rule 16.3 [WARN]: Tests must be deterministic. Do not use 'Thread.sleep()' in tests. Use Awaitility or mock clocks instead.",
                RULE_TESTS_DETERMINISTIC
            ))
            
        for m in order_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                f"Rule 16.3 [WARN]: Tests must be deterministic. Do not use order dependence annotations like '@{m.group(1)}'.",
                RULE_TESTS_DETERMINISTIC
            ))
            
    return errors

def check_domain_fixtures_warning():
    errors = []
    new_entity_pat = re.compile(r'\bnew\s+(Proposal|Award|BudgetHeader|BudgetPeriod|Sponsor)\s*\(')
    for filepath in find_java_files():
        if not ('src/test/' in filepath or filepath.endswith('Test.java') or filepath.endswith('Tests.java')):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            m = new_entity_pat.search(line)
            if m:
                errors.append(warning(
                    filepath,
                    line_no,
                    f"Rule 16.4 [WARN]: Use realistic domain fixtures (e.g. {m.group(1)}Fixtures) instead of manually instantiating 'new {m.group(1)}()' in tests.",
                    RULE_DOMAIN_FIXTURES
                ))
    return errors

def check_spring_boot_test_reserve_warning():
    errors = []
    springboot_test_pat = re.compile(r'@SpringBootTest\b')
    for filepath in find_java_files():
        if not ('src/test/' in filepath or filepath.endswith('Test.java') or filepath.endswith('Tests.java')):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for m in springboot_test_pat.finditer(content_no_comments):
            line_no = content_no_comments[:m.start()].count('\n') + 1
            errors.append(warning(
                filepath,
                line_no,
                "Rule 16.5 [WARN]: Reserve @SpringBootTest for integration tests that require the full application context. Use unit tests for pure logic.",
                RULE_SPRING_BOOT_TEST_RESERVE
            ))
    return errors

    return errors

def check_prefer_typed_dto_warning():
    errors = []
    hashmap_pat = re.compile(r'\bnew\s+HashMap\s*<\s*String\s*,\s*Object\s*>\s*\(')
    for filepath in find_java_files():
        if not (filepath.endswith('Controller.java') or filepath.endswith('Service.java') or filepath.endswith('ServiceImpl.java')):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if hashmap_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.16 [WARN]: Prefer typed VO/DTO over new HashMap / Map<String, Object> APIs in controllers and services.",
                    RULE_PREFER_TYPED_DTO
                ))
    return errors

def check_core_authenticated_user_warning():
    errors = []
    class_auth_pat = re.compile(r'\bclass\s+AuthenticatedUser\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if class_auth_pat.search(line):
                pkg_match = re.search(r'\bpackage\s+(?P<pkg>[a-zA-Z0-9_.]+);', content_no_comments)
                if pkg_match and '.core' not in pkg_match.group('pkg'):
                    errors.append(warning(
                        filepath,
                        line_no,
                        "Rule 17.17 [WARN]: Use core AuthenticatedUser instead of defining a new duplicate AuthenticatedUser class.",
                        RULE_CORE_AUTHENTICATED_USER
                    ))
    return errors

def check_message_q_router_warning():
    errors = []
    rabbit_template_pat = re.compile(r'\bRabbitTemplate\b')
    for filepath in find_java_files():
        if filepath.endswith('Router.java') or filepath.endswith('MessageQServiceRouter.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if rabbit_template_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.19 [WARN]: Do not publish messages directly with raw RabbitTemplate from domain services. Use MessageQServiceRouter/MessageQVO instead.",
                    RULE_MESSAGE_Q_ROUTER
                ))
    return errors

def check_no_dao_in_controller_warning():
    errors = []
    dao_field_pat = re.compile(r'\bprivate\s+[a-zA-Z0-9_]*Dao\b')
    for filepath in find_java_files():
        if not filepath.endswith('Controller.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if dao_field_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.21 [WARN]: Do not newly inject DAOs into controllers. Prefer injecting a service.",
                    RULE_NO_DAO_IN_CONTROLLER
                ))
    return errors

def check_mutable_static_maps_warning():
    errors = []
    mutable_static_pat = re.compile(r'\bpublic\s+static\s+(?:final\s+)?(Map|HashMap|ConcurrentHashMap|List|ArrayList)\b')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if mutable_static_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.22 [WARN]: No new mutable public static maps/caches. Use Spring beans with proper eviction policies instead.",
                    RULE_MUTABLE_STATIC_MAPS
                ))
    return errors

def check_java_11_compat_warning():
    errors = []
    record_pat = re.compile(r'\bpublic\s+record\s+[a-zA-Z0-9_]+\s*\(')
    text_block_pat = re.compile(r'"""')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if record_pat.search(line) or text_block_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.23 [WARN]: Stay on Java 11 language APIs. Do not use Java 17 features (such as records or text blocks).",
                    RULE_JAVA_11_COMPAT
                ))
    return errors

def check_yes_no_flags_warning():
    errors = []
    yn_literal_pat = re.compile(r'\.equals(?:IgnoreCase)?\(\s*"[YN]"\s*\)|"[YN]"\.equals(?:IgnoreCase)?\(')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if yn_literal_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.24 [WARN]: Use CoreConstants.YES / named constants for Y/N flags instead of literal \"Y\"/\"N\".",
                    RULE_YES_NO_FLAGS
                ))
    return errors

def check_constant_first_equals_warning():
    errors = []
    equals_const_pat = re.compile(r'\b[a-z][a-zA-Z0-9_]*\.equals\(\s*(?:String\.valueOf\()?(?P<const>CoreConstants\.[A-Z0-9_]+|"[A-Z0-9_]+")\s*\)?\s*\)')
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            if equals_const_pat.search(line):
                errors.append(warning(
                    filepath,
                    line_no,
                    "Rule 17.25 [WARN]: Constant-first / null-safe equals. Place constant or CoreConstants.CONSTANT first in .equals() checks.",
                    RULE_CONSTANT_FIRST_EQUAL
                ))
    return errors

def check_multipart_format_check_warning():
    errors = []
    multipart_method_pat = re.compile(r'@(?:Post|Put|Request)Mapping\b')
    for filepath in find_java_files():
        if not filepath.endswith('Controller.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in multipart_method_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            sig_chunk = content_no_comments[start_pos : start_pos + brace_match.start() + 1]
            if 'MultipartFile' in sig_chunk:
                method_start = start_pos + brace_match.start()
                brace_count = 1
                method_body = ""
                for idx in range(method_start + 1, len(content_no_comments)):
                    char = content_no_comments[idx]
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            method_body = content_no_comments[method_start+1:idx]
                            break
                
                if 'checkFileFormat' not in method_body:
                    line_num = get_line_num(m.start())
                    errors.append(warning(
                        filepath,
                        line_num,
                        "Rule 17.28 [WARN]: Call commonService.checkFileFormat on new multipart uploads before processing attachments.",
                        RULE_MULTIPART_FORMAT_CHECK
                    ))
    return errors

def check_jpa_getter_setter_only_warning():
    errors = []
    for filepath in find_java_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        if '@Entity' in content_no_comments:
            bad_annotations = []
            if '@Data' in content_no_comments:
                bad_annotations.append('@Data')
            if '@Builder' in content_no_comments:
                bad_annotations.append('@Builder')
            if '@AllArgsConstructor' in content_no_comments:
                bad_annotations.append('@AllArgsConstructor')
                
            if bad_annotations:
                entity_match = re.search(r'@Entity\b', content_no_comments)
                line_num = content_no_comments[:entity_match.start()].count('\n') + 1
                errors.append(warning(
                    filepath,
                    line_num,
                    f"Rule 17.30 [WARN]: On JPA entities prefer @Getter / @Setter / @NoArgsConstructor instead of {' / '.join(bad_annotations)}.",
                    RULE_JPA_GETTER_SETTER_ONLY
                ))
    return errors

def check_dto_boolean_wrapper_warning():
    errors = []
    boolean_field_pat = re.compile(r'\bprivate\s+boolean\s+(?P<name>[a-zA-Z0-9_]+)\s*;')
    for filepath in find_java_files():
        if not (filepath.endswith('DTO.java') or filepath.endswith('VO.java')):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        for line_no, line in enumerate(content_no_comments.splitlines(), 1):
            m = boolean_field_pat.search(line)
            if m:
                errors.append(warning(
                    filepath,
                    line_no,
                    f"Rule 17.31 [WARN]: Use wrapper 'Boolean' instead of primitive 'boolean' for field '{m.group('name')}' in DTO/VO classes.",
                    RULE_DTO_BOOLEAN_WRAPPER
                ))
    return errors

def check_log_context_ids_warning():
    errors = []
    mapping_pat = re.compile(r'@(?:Get|Post|Put|Delete)Mapping\b')
    for filepath in find_java_files():
        if not filepath.endswith('Controller.java'):
            continue
        content = _read_file(filepath)
        if not content:
            continue
        content_no_comments = _strip_comments_preserve_length(content)
        
        line_starts = [0]
        for match in re.finditer(r'\n', content):
            line_starts.append(match.end())
        import bisect
        def get_line_num(char_idx):
            return bisect.bisect_right(line_starts, char_idx)
            
        for m in mapping_pat.finditer(content_no_comments):
            start_pos = m.end()
            brace_match = re.search(r'\{', content_no_comments[start_pos:])
            if not brace_match:
                continue
            body_start = start_pos + brace_match.start() + 1
            first_stmt_match = re.match(r'\s*(?P<stmt>[^;]+);', content_no_comments[body_start:])
            if first_stmt_match:
                stmt = first_stmt_match.group('stmt').strip()
                if stmt.startswith('return '):
                    sig_chunk = content_no_comments[start_pos : start_pos + brace_match.start()]
                    if any(x in sig_chunk for x in ['inboxId', 'quickLinkId', 'proposalId', 'awardId', 'id']):
                        line_num = get_line_num(m.start())
                        errors.append(warning(
                            filepath,
                            line_num,
                            "Rule 17.32 [WARN]: Log useful context IDs (e.g. inboxId, proposalId) on controller entry before returning.",
                            RULE_LOG_CONTEXT_IDS
                        ))
    return errors

# ─── DB Rules ───────────────────────────────────────────────────────────────

def _strip_sql_comments(content):
    if not content:
        return ''
    # Strip multi-line comments /* ... */
    content = re.sub(r'/\*.*?\*/', lambda m: ' ' * len(m.group(0)), content, flags=re.DOTALL)
    # Strip single-line comments -- ...
    content = re.sub(r'--.*$', lambda m: ' ' * len(m.group(0)), content, flags=re.MULTILINE)
    # Strip single-line hash comments # ...
    content = re.sub(r'#.*$', lambda m: ' ' * len(m.group(0)), content, flags=re.MULTILINE)
    return content

def _strip_xml_comments(content):
    if not content:
        return ''
    # Strip XML comments <!-- ... --> preserving length to keep line numbers intact
    return re.sub(r'<!--.*?-->', lambda m: ' ' * len(m.group(0)), content, flags=re.DOTALL)

def _sql_is_update_script(content_clean):
    """Return True if the SQL file contains at least one UPDATE or INSERT statement."""
    return bool(re.search(r'\b(UPDATE|INSERT)\b', content_clean, re.IGNORECASE))

def check_db_sql_safe_updates():
    """
    Rule DB-1 [BLOCK]: UPDATE scripts must wrap DML with:
        SET SQL_SAFE_UPDATES = 0; ... SET SQL_SAFE_UPDATES = 1;
    """
    errors = []
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        if not re.search(r'\bUPDATE\b', content_clean, re.IGNORECASE):
            continue  # only check files that contain UPDATE statements
        has_disable = bool(re.search(r'SET\s+SQL_SAFE_UPDATES\s*=\s*0', content_clean, re.IGNORECASE))
        has_enable  = bool(re.search(r'SET\s+SQL_SAFE_UPDATES\s*=\s*1', content_clean, re.IGNORECASE))
        if not has_disable or not has_enable:
            missing = []
            if not has_disable:
                missing.append("SET SQL_SAFE_UPDATES = 0 (before UPDATE)")
            if not has_enable:
                missing.append("SET SQL_SAFE_UPDATES = 1 (after UPDATE)")
            errors.append(error(
                filepath, 1,
                f"Rule DB-1 [BLOCK]: UPDATE script must include SQL_SAFE_UPDATES guards. Missing: {', '.join(missing)}.",
                RULE_DB_SQL_SAFE_UPDATES
            ))
    return errors

def check_db_update_user_timestamp():
    """
    Rule DB-2 [BLOCK]: INSERT/UPDATE scripts must set UPDATE_USER and UPDATE_TIMESTAMP columns.
    """
    errors = []
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        if not _sql_is_update_script(content_clean):
            continue
        has_update_user      = bool(re.search(r'\bUPDATE_USER\b', content_clean, re.IGNORECASE))
        has_update_timestamp = bool(re.search(r'\bUPDATE_TIMESTAMP\b', content_clean, re.IGNORECASE))
        if not has_update_user or not has_update_timestamp:
            missing = []
            if not has_update_user:
                missing.append("UPDATE_USER")
            if not has_update_timestamp:
                missing.append("UPDATE_TIMESTAMP")
            errors.append(error(
                filepath, 1,
                f"Rule DB-2 [BLOCK]: INSERT/UPDATE script must set {' and '.join(missing)} column(s).",
                RULE_DB_UPDATE_USER_TIMESTAMP
            ))
    return errors

def check_db_changeset_unique_id():
    """
    Rule DB-3 [BLOCK]: Changeset IDs must be globally unique across all Liquibase XML files.
    """
    errors = []
    seen = {}   # id -> first filepath
    changeset_id_pat = re.compile(r'<changeSet[^>]+\bid\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    for filepath in find_xml_changelog_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_xml_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = changeset_id_pat.search(line)
            if m:
                cs_id = m.group(1).strip()
                if cs_id in seen:
                    errors.append(error(
                        filepath, line_no,
                        f"Rule DB-3 [BLOCK]: Changeset ID '{cs_id}' is already defined in '{seen[cs_id]}'. Changeset IDs must be unique across all folders.",
                        RULE_DB_CHANGESET_UNIQUE_ID
                    ))
                else:
                    seen[cs_id] = filepath
    return errors

def check_db_no_delimiter():
    """
    Rule DB-4 [BLOCK]: No DELIMITER statements inside Liquibase-formatted SQL routines.
    """
    errors = []
    delimiter_pat = re.compile(r'^\s*DELIMITER\s+', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if delimiter_pat.match(line):
                errors.append(error(
                    filepath, line_no,
                    "Rule DB-4 [BLOCK]: Do not use DELIMITER statements in Liquibase-formatted SQL routines. Liquibase handles statement splitting automatically.",
                    RULE_DB_NO_DELIMITER
                ))
    return errors

def check_db_changeset_path_match():
    """
    Rule DB-5 [BLOCK]: The path referenced inside a <sqlFile> / <include> tag must match
    an existing file relative to the repo root.
    """
    errors = []
    path_pat = re.compile(
        r'<(?:sqlFile|include)\s[^>]*\bpath\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    for filepath in find_xml_changelog_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_xml_comments(content)
        changelog_dir = os.path.dirname(filepath)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = path_pat.search(line)
            if m:
                ref_path = m.group(1).strip()
                # Try relative to changelog dir, then repo root
                candidates = [
                    os.path.join(changelog_dir, ref_path),
                    ref_path,
                    os.path.join('.', ref_path),
                ]
                if not any(os.path.exists(c) for c in candidates):
                    errors.append(error(
                        filepath, line_no,
                        f"Rule DB-5 [BLOCK]: Referenced path '{ref_path}' does not exist. Changeset path must match the actual script/procedure path.",
                        RULE_DB_CHANGESET_PATH_MATCH
                    ))
    return errors

def check_db_no_secrets():
    """
    Rule DB-6 [BLOCK]: No DB names, credentials, connection strings, API keys or secrets
    inside SQL scripts or Liquibase XML files.
    """
    errors = []
    secret_pat = re.compile(
        r'(?:'
        r'password\s*=\s*["\'][^"\']{3,}["\']'           # password = "..."
        r'|jdbc:[a-zA-Z]+://[^\s;>"\']+'                  # JDBC URLs
        r'|(?:api|secret|token|key)\s*[=:]\s*["\'][^"\']{8,}["\']'  # api/secret/token/key = "..."
        r'|(?:USE|DATABASE)\s+`?[a-zA-Z0-9_]{3,}`?\s*;'  # USE dbname; or DATABASE dbname;
        r')',
        re.IGNORECASE
    )
    all_files = find_sql_files() + find_xml_changelog_files()
    for filepath in all_files:
        content = _read_file(filepath)
        if not content:
            continue
        if filepath.endswith('.sql'):
            content_clean = _strip_sql_comments(content)
        else:
            content_clean = _strip_xml_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if secret_pat.search(line):
                errors.append(error(
                    filepath, line_no,
                    "Rule DB-6 [BLOCK]: Do not embed DB names, credentials, API keys or secrets in SQL scripts or Liquibase files.",
                    RULE_DB_NO_SECRETS
                ))
    return errors

def check_db_drop_paired():
    """
    Rule DB-7 [BLOCK]: DROP operations must appear in the same changeset as their
    related DML/DDL — not as a standalone changeset with only DROP statements.
    """
    errors = []
    changeset_pat  = re.compile(r'<changeSet\b[^>]*>', re.IGNORECASE)
    end_changeset  = re.compile(r'</changeSet\s*>', re.IGNORECASE)
    sql_tag_pat    = re.compile(r'<sql\b[^>]*>(.*?)</sql>', re.IGNORECASE | re.DOTALL)
    sqlfile_pat    = re.compile(r'<sqlFile\b', re.IGNORECASE)

    for filepath in find_xml_changelog_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_xml_comments(content)
        # Split into per-changeset blocks
        lines = content_clean.splitlines(keepends=True)
        block_lines = []
        in_block = False
        block_start_line = 0
        for line_no, line in enumerate(lines, 1):
            if changeset_pat.search(line):
                in_block = True
                block_start_line = line_no
                block_lines = [line]
            elif in_block:
                block_lines.append(line)
                if end_changeset.search(line):
                    block = ''.join(block_lines)
                    # Extract inline SQL from <sql> tags
                    inline_sql = ' '.join(m.group(1) for m in sql_tag_pat.finditer(block))
                    has_sqlfile = bool(sqlfile_pat.search(block))
                    has_drop    = bool(re.search(r'\bDROP\b', inline_sql, re.IGNORECASE)) or \
                                  bool(re.search(r'\bDROP\b', block, re.IGNORECASE) and has_sqlfile)
                    has_other   = bool(re.search(r'\b(CREATE|ALTER|INSERT|UPDATE|DELETE|RENAME)\b', inline_sql, re.IGNORECASE))

                    if has_drop and not has_other and not has_sqlfile:
                        errors.append(error(
                            filepath, block_start_line,
                            "Rule DB-7 [BLOCK]: DROP operation is standalone. Pair it with the related DML/DDL in the same changeset, or include a rollback section.",
                            RULE_DB_DROP_PAIRED
                        ))
                    in_block = False
                    block_lines = []
    return errors

def check_db_create_or_replace():
    errors = []
    obj_pat = re.compile(r'\b(?:PROCEDURE|FUNCTION|PACKAGE)\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        if re.search(r'\bPACKAGE\s+BODY\b', content_clean, re.IGNORECASE):
            continue
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            line_stripped = line.strip()
            if obj_pat.search(line_stripped):
                if re.search(r'\b(?:CALL|DROP|ALTER|EXECUTE|END)\b', line_stripped, re.IGNORECASE):
                    continue
                if not re.search(r'\bCREATE\s+OR\s+REPLACE\s+', line_stripped, re.IGNORECASE):
                    errors.append(error(
                        filepath, line_no,
                        "Rule DB-2.1 [BLOCK]: Object header must start with CREATE OR REPLACE (every function, procedure, or package).",
                        RULE_DB_CREATE_OR_REPLACE
                    ))
    return errors

def check_db_select_into_exception():
    errors = []
    select_into_pat = re.compile(r'\bSELECT\s+((?!COUNT\().)*?\bINTO\b', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        statements = content_clean.split(';')
        for stmt in statements:
            if select_into_pat.search(stmt):
                if not re.search(r'\b(?:EXCEPTION|NO_DATA_FOUND|OTHERS|TOO_MANY_ROWS)\b', content_clean, re.IGNORECASE):
                    errors.append(error(
                        filepath, 1,
                        "Rule DB-3.1 [BLOCK]: SELECT ... INTO must handle NO_DATA_FOUND / TOO_MANY_ROWS with an EXCEPTION block.",
                        RULE_DB_SELECT_INTO_EXCEPTION
                    ))
                    break
    return errors

def check_db_drop_pk_index():
    errors = []
    drop_pk_pat = re.compile(r'\bDROP\s+PRIMARY\s+KEY\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if drop_pk_pat.search(line):
                if not re.search(r'\bDROP\s+INDEX\b', line, re.IGNORECASE):
                    errors.append(error(
                        filepath, line_no,
                        "Rule DB-4.4 [BLOCK]: Dropping a primary key must also drop its indexes (use DROP PRIMARY KEY DROP INDEX).",
                        RULE_DB_DROP_PK_INDEX
                    ))
    return errors

def check_db_no_self_join():
    errors = []
    self_join_from_pat = re.compile(r'\bFROM\s+([a-zA-Z0-9_]+)\s+[a-zA-Z0-9_]+\s*,\s*\1\s+[a-zA-Z0-9_]+\b', re.IGNORECASE)
    self_join_join_pat = re.compile(r'\bJOIN\s+([a-zA-Z0-9_]+)\s+[a-zA-Z0-9_]+\b.*?JOIN\s+\1\s+[a-zA-Z0-9_]+\b', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        statements = content_clean.split(';')
        for stmt in statements:
            if self_join_from_pat.search(stmt) or self_join_join_pat.search(stmt):
                line_no = 1
                stmt_lines = [line.strip() for line in stmt.splitlines() if line.strip() and line.strip() != '/']
                if stmt_lines:
                    first_line = stmt_lines[0]
                    for idx, line in enumerate(content_clean.splitlines(), 1):
                        if first_line in line:
                            line_no = idx
                            break
                errors.append(error(
                    filepath, line_no,
                    "Rule DB-4.11 [BLOCK]: No duplicate or self joins. Do not join the same table twice without a deliberate reason.",
                    RULE_DB_NO_SELF_JOIN
                ))
    return errors

def check_db_null_inequality():
    errors = []
    ineq_pat = re.compile(r'\b[a-zA-Z0-9_.]+\s*(?:<>|!=)\s*[\'":a-zA-Z0-9_]+', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if ineq_pat.search(line):
                if not re.search(r'\bIS\s+NULL\b', line, re.IGNORECASE):
                    errors.append(error(
                        filepath, line_no,
                        "Rule DB-5.1 [BLOCK]: Explicit NULL handling in inequality comparisons. Account for NULL explicitly with OR col IS NULL.",
                        RULE_DB_NULL_INEQUALITY
                    ))
    return errors

def check_db_terminate_slash():
    errors = []
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        lines = [line.strip() for line in content_clean.splitlines() if line.strip()]
        if lines and lines[-1] != '/':
            errors.append(error(
                filepath, len(content.splitlines()),
                "Rule DB-6.3 [BLOCK]: Script file must be terminated with / character.",
                RULE_DB_TERMINATE_SLASH
            ))
    return errors

def check_db_table_name():
    errors = []
    create_tbl_pat = re.compile(r'\bCREATE\s+TABLE\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = create_tbl_pat.search(line)
            if m:
                table_name = m.group(1)
                is_invalid = False
                if table_name.lower().startswith('t_') and len(table_name) <= 8:
                    is_invalid = True
                elif len(table_name) <= 6:
                    is_invalid = True
                
                if is_invalid:
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.1 [WARN]: Table name '{table_name}' is too short or ambiguous. Table names must clearly describe their contents.",
                        RULE_DB_TABLE_NAME
                    ))
    return errors

def check_db_view_name():
    errors = []
    create_view_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = create_view_pat.search(line)
            if m:
                view_name = m.group(1)
                if len(view_name) <= 6 or re.match(r'^v\d*$', view_name, re.IGNORECASE):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.2 [WARN]: View name '{view_name}' is too short or ambiguous. View names must clearly describe their contents.",
                        RULE_DB_VIEW_NAME
                    ))
    return errors

def check_db_fk_align():
    errors = []
    fk_pat = re.compile(
        r'FOREIGN\s+KEY\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*REFERENCES\s+[a-zA-Z0-9_]+\s*\(\s*([a-zA-Z0-9_]+)\s*\)',
        re.IGNORECASE
    )
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = fk_pat.search(line)
            if m:
                fk_col, ref_col = m.group(1), m.group(2)
                if fk_col.lower() != ref_col.lower():
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.3 [WARN]: Foreign key column '{fk_col}' name mismatch with referenced column '{ref_col}'. They should be named identically.",
                        RULE_DB_FK_ALIGN
                    ))
    return errors

def check_db_proc_prefix():
    errors = []
    proc_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = proc_pat.search(line)
            if m:
                proc_name = m.group(1).lower()
                prefixes = ('get_', 'update_', 'upd_', 'delete_', 'del_', 'insert_')
                if not proc_name.startswith(prefixes):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.4 [WARN]: Procedure '{m.group(1)}' name must be prefixed by an action (GET, UPDATE/UPD, DELETE/DEL, INSERT).",
                        RULE_DB_PROC_PREFIX
                    ))
    return errors

def check_db_func_prefix():
    errors = []
    func_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = func_pat.search(line)
            if m:
                func_name = m.group(1).lower()
                if not func_name.startswith('fn_'):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.5 [WARN]: Function '{m.group(1)}' must be prefixed by 'FN_' (e.g. FN_IS_... or FN_GET_...).",
                        RULE_DB_FUNC_PREFIX
                    ))
    return errors

def check_db_pkg_prefix():
    errors = []
    pkg_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?PACKAGE\s+(?:BODY\s+)?([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = pkg_pat.search(line)
            if m:
                pkg_name = m.group(1).lower()
                if not pkg_name.startswith('pkg_'):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.6 [WARN]: Package '{m.group(1)}' must be prefixed by 'PKG_'.",
                        RULE_DB_PKG_PREFIX
                    ))
    return errors

def check_db_trg_prefix():
    errors = []
    trg_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = trg_pat.search(line)
            if m:
                trg_name = m.group(1).lower()
                if not trg_name.startswith('trg_'):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.7 [WARN]: Trigger '{m.group(1)}' must be prefixed by 'TRG_'.",
                        RULE_DB_TRG_PREFIX
                    ))
    return errors

def check_db_seq_prefix():
    errors = []
    seq_pat = re.compile(r'\bCREATE\s+SEQUENCE\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = seq_pat.search(line)
            if m:
                seq_name = m.group(1).lower()
                if not seq_name.startswith('seq_'):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.8 [WARN]: Sequence '{m.group(1)}' must be prefixed by 'SEQ_'.",
                        RULE_DB_SEQ_PREFIX
                    ))
    return errors

def check_db_param_prefix():
    errors = []
    param_block_pat = re.compile(r'\b(?:PROCEDURE|FUNCTION)\s+[a-zA-Z0-9_]+\s*\(([^)]+)\)', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in param_block_pat.finditer(content_clean):
            param_block = m.group(1)
            line_no = 1
            first_line_of_block = param_block.strip().splitlines()[0] if param_block.strip() else ""
            for idx, line in enumerate(content_clean.splitlines(), 1):
                if first_line_of_block in line:
                    line_no = idx
                    break
            
            params = param_block.split(',')
            for param in params:
                param = param.strip()
                if not param:
                    continue
                parts = param.split()
                if not parts:
                    continue
                
                # Check for direction keyword (IN, OUT, INOUT) at the start
                if parts[0].upper() in ('IN', 'OUT', 'INOUT') and len(parts) > 1:
                    param_name = parts[1]
                else:
                    param_name = parts[0]
                
                param_name = param_name.strip('`')
                if not param_name.lower().startswith(('av_', 'aw_')):
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-1.9 [WARN]: Parameter '{param_name}' must be prefixed by 'av_' (read-only) or 'aw_' (insert/update).",
                        RULE_DB_PARAM_PREFIX
                    ))
    return errors

def check_db_var_prefix():
    errors = []
    var_pat = re.compile(
        r'^\s*([a-zA-Z0-9_]+)\s+(NUMBER|INTEGER|FLOAT|DOUBLE|INT|VARCHAR2|VARCHAR|CHAR|DATE|TIMESTAMP|BOOLEAN)\b(?:\s*\(.*?\))?\s*(?::=\s*.*?)?;',
        re.IGNORECASE | re.MULTILINE
    )
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in var_pat.finditer(content_clean):
            var_name = m.group(1)
            var_type = m.group(2).upper()
            
            if var_name.upper() in ('RETURN', 'SELECT', 'BEGIN', 'EXCEPTION', 'WHEN', 'THEN', 'ELSE', 'END', 'CREATE', 'ALTER'):
                continue
            
            line_no = 1
            matched_text = m.group(0).strip()
            first_line = matched_text.splitlines()[0] if matched_text else ""
            for idx, line in enumerate(content_clean.splitlines(), 1):
                if first_line in line:
                    line_no = idx
                    break
                    
            is_valid = True
            expected_prefix = ""
            if var_type in ('NUMBER', 'INTEGER', 'FLOAT', 'DOUBLE', 'INT'):
                is_valid = var_name.lower().startswith('li_')
                expected_prefix = 'li_'
            elif var_type in ('VARCHAR2', 'VARCHAR', 'CHAR'):
                is_valid = var_name.lower().startswith('ls_')
                expected_prefix = 'ls_'
            elif var_type in ('DATE', 'TIMESTAMP', 'BOOLEAN'):
                is_valid = var_name.lower().startswith('lo_')
                expected_prefix = 'lo_'
                
            if not is_valid:
                errors.append(warning(
                    filepath, line_no,
                    f"Rule DB-1.10 [WARN]: Variable '{var_name}' of type {var_type} must be prefixed by '{expected_prefix}'.",
                    RULE_DB_VAR_PREFIX
                ))
    return errors

def check_db_purpose_comment():
    errors = []
    header_pat = re.compile(
        r'\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION|PACKAGE|TRIGGER)\s+[a-zA-Z0-9_]+\b.*?\b(?:IS|AS)\b',
        re.IGNORECASE | re.DOTALL
    )
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        lines = content.splitlines()
        for m in header_pat.finditer(content_clean):
            header_end_idx = m.end()
            line_no = len(content_clean[:header_end_idx].splitlines())
            
            has_purpose_comment = False
            for idx in range(line_no, min(line_no + 3, len(lines))):
                next_line = lines[idx].strip()
                if next_line.startswith('--') or next_line.startswith('/*'):
                    has_purpose_comment = True
                    break
            
            if not has_purpose_comment:
                errors.append(warning(
                    filepath, line_no + 1,
                    "Rule DB-2.2 [WARN]: Purpose comment required right below the procedure/function/package/trigger header.",
                    RULE_DB_PURPOSE_COMMENT
                ))
    return errors

def check_db_case_number():
    errors = []
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        for line_no, line in enumerate(content.splitlines(), 1):
            if re.search(r'--\s*(?:changed|modified|edited)\b', line, re.IGNORECASE):
                if not re.search(r'--\s*START\s+CASE\s+FIBI-\d+', content, re.IGNORECASE):
                    errors.append(warning(
                        filepath, line_no,
                        "Rule DB-2.3 [WARN]: Modified code blocks must be marked with a start/end case comment block referencing the case number (e.g. -- START CASE FIBI-XXXX).",
                        RULE_DB_CASE_NUMBER
                    ))
        
        starts = list(re.finditer(r'--\s*START\s+CASE\s+(FIBI-\d+)', content, re.IGNORECASE))
        ends = list(re.finditer(r'--\s*END\s+CASE\s+(FIBI-\d+)', content, re.IGNORECASE))
        if len(starts) != len(ends):
            errors.append(warning(
                filepath, 1,
                f"Rule DB-2.3 [WARN]: Mismatched case comment blocks. Found {len(starts)} START blocks and {len(ends)} END blocks.",
                RULE_DB_CASE_NUMBER
            ))
    return errors

def check_db_keywords_upper():
    errors = []
    keywords = ('select', 'from', 'where', 'begin', 'end', 'insert', 'update', 'delete', 'into', 'values', 'declare', 'create', 'alter', 'drop', 'table', 'procedure', 'function', 'package', 'trigger', 'if', 'then', 'else', 'elsif', 'return')
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        content_no_strings = re.sub(r"'[^']*'", "''", content_clean)
        for line_no, line in enumerate(content_no_strings.splitlines(), 1):
            for kw in keywords:
                m = re.search(r'\b(' + kw + r')\b', line)
                if m:
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-4.1 [WARN]: SQL keyword '{m.group(1)}' must be written in UPPER case.",
                        RULE_DB_KEYWORDS_UPPER
                    ))
    return errors

def check_db_identifiers_lower():
    errors = []
    allowed_upper = {
        'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'IS', 'NULL', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET', 'DELETE', 'CREATE', 'TABLE', 'VIEW', 'PROCEDURE', 'FUNCTION', 'PACKAGE', 'TRIGGER', 'SEQUENCE', 'ALTER', 'DROP', 'ADD', 'CONSTRAINT', 'FOREIGN', 'KEY', 'REFERENCES', 'INDEX', 'PRIMARY', 'BEGIN', 'END', 'AS', 'IF', 'THEN', 'ELSE', 'ELSIF', 'LOOP', 'FOR', 'WHILE', 'DECLARE', 'NUMBER', 'VARCHAR2', 'VARCHAR', 'CHAR', 'DATE', 'TIMESTAMP', 'BOOLEAN', 'RETURN', 'RETURNS', 'EXCEPTION', 'WHEN', 'OTHERS', 'OUT', 'INOUT', 'USE', 'SQL_SAFE_UPDATES', 'NOW', 'COUNT', 'DELIMITER', 'CASE', 'DEFAULT', 'CLOB', 'BLOB', 'BODY', 'REPLACE'
    }
    upper_word_pat = re.compile(r'\b([a-zA-Z0-9_]*[A-Z][a-zA-Z0-9_]*)\b')
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        content_no_strings = re.sub(r"'[^']*'", "''", content_clean)
        for line_no, line in enumerate(content_no_strings.splitlines(), 1):
            for m in upper_word_pat.finditer(line):
                word = m.group(1)
                if word.isdigit():
                    continue
                if word.upper() not in allowed_upper:
                    errors.append(warning(
                        filepath, line_no,
                        f"Rule DB-4.2 [WARN]: Identifier '{word}' must be written in lower case.",
                        RULE_DB_IDENTIFIERS_LOWER
                    ))
    return errors

def check_db_alias_consistent():
    errors = []
    from_comma_pat1 = re.compile(r'\bFROM\s+([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\b', re.IGNORECASE)
    from_comma_pat2 = re.compile(r'\bFROM\s+([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\s*,\s*([a-zA-Z0-9_]+)(?!\s+[a-zA-Z0-9_])\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if from_comma_pat1.search(line) or from_comma_pat2.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-4.3 [WARN]: Inconsistent table alias usage. Use table aliases consistently across all tables in a script.",
                    RULE_DB_ALIAS_CONSISTENT
                ))
    return errors

def check_db_no_schema_prefix():
    errors = []
    prefix_pat = re.compile(r'\b(?:FROM|JOIN|UPDATE|INSERT\s+INTO)\s+([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            m = prefix_pat.search(line)
            if m:
                errors.append(warning(
                    filepath, line_no,
                    f"Rule DB-4.5 [WARN]: Schema prefix '{m.group(1)}' found. Objects within scripts must not be prefixed with the schema name to ensure portability.",
                    RULE_DB_NO_SCHEMA_PREFIX
                ))
    return errors

def check_db_boolean_int():
    errors = []
    ret_bool_pat = re.compile(r'\bRETURN\s+(TRUE|FALSE)\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if ret_bool_pat.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-4.6 [WARN]: Boolean-returning functions must use 1 for success and 0 for failure (do not return TRUE/FALSE directly).",
                    RULE_DB_BOOLEAN_INT
                ))
    return errors

def check_db_complex_logic_comment():
    errors = []
    complex_pat = re.compile(r'\b(?:MOD|POWER|DECODE|ABS|TRUNC|ROUND)\b|[-+*/]{2,}', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        lines = content.splitlines()
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if complex_pat.search(line):
                has_comment = False
                start_check = max(0, line_no - 3)
                for idx in range(start_check, line_no):
                    if idx < len(lines) and ('--' in lines[idx] or '/*' in lines[idx]):
                        has_comment = True
                        break
                if not has_comment:
                    errors.append(warning(
                        filepath, line_no,
                        "Rule DB-4.7 [WARN]: Complex or non-obvious operations must have an explanatory comment.",
                        RULE_DB_COMPLEX_LOGIC_COMMENT
                    ))
    return errors

def check_db_magic_value_comment():
    errors = []
    literal_comp_pat = re.compile(r'\bWHERE\b.*?(?:=\s*\d+|=\s*\'[^\']+\'|<>\s*\d+|<>\s*\'[^\']+\')', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        statements = content_clean.split(';')
        for stmt in statements:
            if literal_comp_pat.search(stmt):
                stmt_lines = [line.strip() for line in stmt.splitlines() if line.strip() and line.strip() != '/']
                if not stmt_lines:
                    continue
                first_line = stmt_lines[0]
                line_no = 1
                for idx, line in enumerate(content_clean.splitlines(), 1):
                    if first_line in line:
                        line_no = idx
                        break
                
                original_lines = content.splitlines()
                has_comment = False
                for idx in range(line_no - 1, min(line_no + len(stmt_lines), len(original_lines))):
                    if '--' in original_lines[idx] or '/*' in original_lines[idx]:
                        has_comment = True
                        break
                if not has_comment:
                    errors.append(warning(
                        filepath, line_no,
                        "Rule DB-4.8 [WARN]: Magic / constant values used in WHERE clauses must be documented with an explanatory comment.",
                        RULE_DB_MAGIC_VALUE_COMMENT
                    ))
    return errors

def check_db_use_type_declaration():
    errors = []
    var_pat = re.compile(
        r'^\s*([a-zA-Z0-9_]+)\s+(NUMBER|INTEGER|FLOAT|DOUBLE|INT|VARCHAR2|VARCHAR|CHAR|DATE|TIMESTAMP)\b(?:\s*\(.*?\))?\s*(?::=\s*.*?)?;',
        re.IGNORECASE | re.MULTILINE
    )
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in var_pat.finditer(content_clean):
            var_name = m.group(1)
            var_type = m.group(2).upper()
            
            if var_name.upper() in ('RETURN', 'SELECT', 'BEGIN', 'EXCEPTION', 'WHEN', 'THEN', 'ELSE', 'END', 'CREATE', 'ALTER'):
                continue
            
            line_no = 1
            matched_text = m.group(0).strip()
            first_line = matched_text.splitlines()[0] if matched_text else ""
            for idx, line in enumerate(content_clean.splitlines(), 1):
                if first_line in line:
                    line_no = idx
                    break
            
            errors.append(warning(
                filepath, line_no,
                f"Rule DB-4.9 [WARN]: Variable '{var_name}' of type {var_type} should be declared using '%TYPE' derived from a database column.",
                RULE_DB_USE_TYPE_DECLARATION
            ))
    return errors

def check_db_where_order():
    errors = []
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        statements = content_clean.split(';')
        for stmt in statements:
            if 'WHERE' in stmt.upper():
                where_idx = stmt.upper().find('WHERE')
                where_clause = stmt[where_idx:]
                filter_match = re.search(r'\b[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\s*(?:=|<|>|!=|<>)\s*[\'":\w]+', where_clause)
                join_match = re.search(r'\b([a-zA-Z0-9_]+)\.[a-zA-Z0-9_]+\s*=\s*(?!\1\b)[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\b', where_clause)
                
                if filter_match and join_match:
                    if filter_match.start() < join_match.start():
                        stmt_lines = stmt.strip().splitlines()
                        first_line = stmt_lines[0] if stmt_lines else ""
                        line_no = 1
                        for idx, line in enumerate(content_clean.splitlines(), 1):
                            if first_line in line:
                                line_no = idx
                                break
    return errors

def check_db_set_where_column():
    errors = []
    update_pat = re.compile(r'\bUPDATE\s+[a-zA-Z0-9_]+\s+SET\s+([a-zA-Z0-9_]+)\s*=\s*.*?\bWHERE\b(.*?)(?:;|$)', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in update_pat.finditer(content_clean):
            col_name = m.group(1).lower()
            where_clause = m.group(2).lower()
            if col_name not in where_clause:
                line_no = len(content_clean[:m.start()].splitlines()) + 1
                errors.append(warning(
                    filepath, line_no,
                    f"Rule DB-5.2 [WARN]: Include the updated column '{m.group(1)}' in the WHERE clause to skip redundant writes.",
                    RULE_DB_SET_WHERE_COLUMN
                ))
    return errors

def check_db_no_function_where():
    errors = []
    func_where_pat = re.compile(r'\bWHERE\b.*?\b([a-zA-Z0-9_]+)\s*\(\s*[a-zA-Z0-9_.]+\s*\)\s*(?:=|<|>|!=|<>)', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in func_where_pat.finditer(content_clean):
            func_name = m.group(1).upper()
            if func_name in ('EXISTS', 'COUNT', 'EXTRACT', 'ABS', 'MOD', 'POWER', 'ROUND', 'TRUNC', 'DECODE'):
                continue
            line_no = len(content_clean[:m.start()].splitlines()) + 1
            errors.append(warning(
                filepath, line_no,
                f"Rule DB-5.3 [WARN]: Avoid wrapping column in function '{m.group(1)}' inside the WHERE clause to allow index usage.",
                RULE_DB_NO_FUNCTION_WHERE
            ))
    return errors

def check_db_prefer_outer_join():
    errors = []
    not_in_pat = re.compile(r'\bNOT\s+IN\s*\(\s*SELECT\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if not_in_pat.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-5.4 [WARN]: Prefer outer joins over 'NOT IN' subqueries for better performance.",
                    RULE_DB_PREFER_OUTER_JOIN
                ))
    return errors

def check_db_no_like_equal():
    errors = []
    like_pat = re.compile(r'\bLIKE\s+\'([^\'%_]+)\'', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if like_pat.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-5.5 [WARN]: Avoid 'LIKE' in place of '=' for exact-match comparisons where no wildcards are used.",
                    RULE_DB_NO_LIKE_EQUAL
                ))
    return errors

def check_db_count_column():
    errors = []
    count_pat = re.compile(r'\bCOUNT\s*\(\s*\*\s*\)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if count_pat.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-5.6 [WARN]: COUNT() should use a specific column or 1, not * (e.g. COUNT(1) or COUNT(id)).",
                    RULE_DB_COUNT_COLUMN
                ))
    return errors

def check_db_use_bind_variables():
    errors = []
    literal_pat = re.compile(r'\bWHERE\b.*?\b[a-zA-Z0-9_.]+\s*=\s*(\d+)\b', re.IGNORECASE | re.DOTALL)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for m in literal_pat.finditer(content_clean):
            if re.search(r'\b(?:PROCEDURE|FUNCTION|PACKAGE BODY)\b', content_clean, re.IGNORECASE):
                line_no = len(content_clean[:m.start()].splitlines()) + 1
                errors.append(warning(
                    filepath, line_no,
                    f"Rule DB-5.7 [WARN]: Use bind variables or parameters instead of hardcoded literal '{m.group(1)}'.",
                    RULE_DB_USE_BIND_VARIABLES
                ))
    return errors

def check_db_exists_distinct():
    errors = []
    distinct_pat = re.compile(r'\bSELECT\s+DISTINCT\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if distinct_pat.search(line):
                if re.search(r'\bFROM\s+[a-zA-Z0-9_]+(?:\s+[a-zA-Z0-9_]+)?\s*,\s*[a-zA-Z0-9_]+|\bJOIN\b', line, re.IGNORECASE):
                    errors.append(warning(
                        filepath, line_no,
                        "Rule DB-5.8 [WARN]: Use EXISTS instead of SELECT DISTINCT to de-duplicate a join when table is only used as filter.",
                        RULE_DB_EXISTS_DISTINCT
                    ))
    return errors

def check_db_driving_table_order():
    errors = []
    comma_join_pat = re.compile(r'\bFROM\s+[a-zA-Z0-9_]+\s*,\s*[a-zA-Z0-9_]+\b', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        for line_no, line in enumerate(content_clean.splitlines(), 1):
            if comma_join_pat.search(line):
                errors.append(warning(
                    filepath, line_no,
                    "Rule DB-5.9 [WARN]: Ensure the driving table (usually smaller table) is listed last in the FROM clause for optimal right-to-left parsing.",
                    RULE_DB_DRIVING_TABLE_ORDER
                ))
    return errors

def check_db_filename_lowercase():
    errors = []
    obj_pat = re.compile(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:PROCEDURE|FUNCTION|PACKAGE)\s+([a-zA-Z0-9_]+)', re.IGNORECASE)
    for filepath in find_sql_files():
        content = _read_file(filepath)
        if not content:
            continue
        content_clean = _strip_sql_comments(content)
        m = obj_pat.search(content_clean)
        if m:
            obj_name = m.group(1).lower()
            filename = os.path.basename(filepath)
            expected_name = f"{obj_name}.sql"
            if filename != expected_name:
                errors.append(warning(
                    filepath, 1,
                    f"Rule DB-6.1 [WARN]: Filename '{filename}' must match object name, in lower case, with a '.sql' extension (expected: '{expected_name}').",
                    RULE_DB_FILENAME_LOWERCASE
                ))
    return errors

def check_db_package_one_file():
    errors = []
    for filepath in find_sql_files():
        filename = os.path.basename(filepath).lower()
        if filename.endswith('_spec.sql') or filename.endswith('_body.sql'):
            errors.append(warning(
                filepath, 1,
                f"Rule DB-6.2 [WARN]: Package header and body must be saved together in a single file (found: '{filename}').",
                RULE_DB_PACKAGE_ONE_FILE
            ))
    return errors

def check_db_combine_schema_changes():
    errors = []
    for filepath in find_sql_files():
        filename = os.path.basename(filepath).lower()
        if filename.startswith(('add_column_', 'add_index_', 'create_table_')):
            errors.append(warning(
                filepath, 1,
                f"Rule DB-6.4 [WARN]: Release schema changes must be combined into dbchanges_MMDDYY.sql (found: '{filename}').",
                RULE_DB_COMBINE_SCHEMA_CHANGES
            ))
    return errors

def check_db_separate_data_scripts():
    errors = []
    for filepath in find_sql_files():
        filename = os.path.basename(filepath).lower()
        if filename.startswith('dbchanges_'):
            content = _read_file(filepath)
            if not content:
                continue
            content_clean = _strip_sql_comments(content)
            inserts = len(re.findall(r'\bINSERT\s+INTO\b', content_clean, re.IGNORECASE))
            if inserts > 10:
                errors.append(warning(
                    filepath, 1,
                    f"Rule DB-6.5 [WARN]: dbchanges file contains {inserts} INSERT statements. Large data scripts must be kept in a separate file.",
                    RULE_DB_SEPARATE_DATA_SCRIPTS
                ))
    return errors

def normalize_path(p):
    p = p.replace('\\', '/')
    if p.startswith('./'):
        p = p[2:]
    return p

def get_pr_added_lines():
    global _PR_ADDED_LINES_CACHE
    if _PR_ADDED_LINES_CACHE is not None:
        return _PR_ADDED_LINES_CACHE

    base_branch = os.environ.get('GITHUB_BASE_REF')
    if not base_branch:
        code, stdout, stderr = run_command("git symbolic-ref --short refs/remotes/origin/HEAD")
        base_branch = stdout.strip().replace("origin/", "") if code == 0 and stdout.strip() else "main"

    if not re.match(r'^[A-Za-z0-9._/-]+$', base_branch):
        log(f"Invalid base branch name '{base_branch}'; custom rule findings will not be posted.")
        _PR_ADDED_LINES_CACHE = {}
        return {}

    run_command(f"git fetch origin {base_branch} --depth=1")
    code, stdout, stderr = run_command(f"git diff --unified=0 --diff-filter=ACMR origin/{base_branch}...HEAD -- .")
    if code != 0:
        log(f"Unable to read PR diff against origin/{base_branch}; custom rule findings will not be posted.")
        _PR_ADDED_LINES_CACHE = {}
        return {}

    added_lines_by_file = {}
    current_file = None
    new_line = None

    for line in stdout.splitlines():
        if line.startswith('+++ b/'):
            current_file = normalize_path(line[6:])
            added_lines_by_file.setdefault(current_file, set())
            continue

        if line.startswith('@@ '):
            match = re.search(r'\+(\d+)(?:,(\d+))?', line)
            if not match:
                new_line = None
                continue
            new_line = int(match.group(1))
            continue

        if current_file is None or new_line is None:
            continue

        if line.startswith('+') and not line.startswith('+++'):
            added_lines_by_file[current_file].add(new_line)
            new_line += 1
        elif line.startswith('-') and not line.startswith('---'):
            continue
        else:
            new_line += 1

    _PR_ADDED_LINES_CACHE = added_lines_by_file
    return added_lines_by_file

def filter_errors_to_pr_added_lines(errors):
    added_lines_by_file = get_pr_added_lines()
    if not added_lines_by_file:
        return []

    filtered = []
    dropped = 0
    for err in errors:
        file_name = normalize_path(err['file'])
        if int(err['line']) in added_lines_by_file.get(file_name, set()):
            filtered.append(err)
        else:
            dropped += 1

    if dropped:
        log(f"Filtered out {dropped} custom findings outside PR-added lines.")
    return filtered

def write_github_step_summary(errors):
    summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
    if not summary_file:
        return
        
    markdown = []
    markdown.append("### 🐶 PR Review Rules Validation Report")
    
    if not errors:
        markdown.append("✅ **All custom checks passed! No violations found.**")
    else:
        markdown.append(f"❌ **Found {len(errors)} unresolved violations in the workspace:**\n")
        markdown.append("| File | Line | Rule | Message |")
        markdown.append("| --- | --- | --- | --- |")
        for err in errors:
            repo = os.environ.get('GITHUB_REPOSITORY', '')
            sha = os.environ.get('GITHUB_SHA', 'main')
            file_link = f"[{err['file']}](https://github.com/{repo}/blob/{sha}/{err['file']}#L{err['line']})"
            markdown.append(f"| {file_link} | {err['line']} | `{err['source']}` | {err['message']} |")
            
    try:
        with open(summary_file, 'a', encoding='utf-8') as f:
            f.write('\n'.join(markdown) + '\n')
    except Exception as e:
        log(f"Error writing to step summary: {e}")

def merge_and_write_checkstyle(new_errors, checkstyle_path="checkstyle-result.xml"):
    errors_by_file = {}
    
    if os.path.exists(checkstyle_path) and os.path.getsize(checkstyle_path) > 0:
        try:
            tree = ET.parse(checkstyle_path)
            root = tree.getroot()
            for file_elem in root.findall('file'):
                file_name = file_elem.get('name')
                file_name_norm = normalize_path(file_name)
                
                if file_name_norm not in errors_by_file:
                    errors_by_file[file_name_norm] = []
                    
                for err_elem in file_elem.findall('error'):
                    errors_by_file[file_name_norm].append({
                        'line': int(err_elem.get('line', 1)),
                        'col': int(err_elem.get('column', 1)),
                        'message': err_elem.get('message', ''),
                        'source': err_elem.get('source', ''),
                        'severity': err_elem.get('severity', 'error')
                    })
        except Exception as e:
            log(f"Error parsing existing checkstyle XML: {e}. Recreating...")

    for err in new_errors:
        file_name_norm = normalize_path(err['file'])
        if file_name_norm not in errors_by_file:
            errors_by_file[file_name_norm] = []
            
        is_dup = False
        for existing in errors_by_file[file_name_norm]:
            if existing['line'] == err['line'] and existing['message'] == err['message'] and existing['source'] == err['source']:
                is_dup = True
                break
        if not is_dup:
            errors_by_file[file_name_norm].append({
                'line': err['line'],
                'col': err['col'],
                'message': err['message'],
                'source': err['source'],
                'severity': err.get('severity', 'error')
            })

    def escape_attr(val):
        return escape(str(val), {'"': '&quot;', "'": '&apos;'})

    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<checkstyle version="8.0">']
    for file_name, file_errors in errors_by_file.items():
        xml_lines.append(f'  <file name="{escape_attr(file_name)}">')
        for err in file_errors:
            severity = err.get('severity', 'error')
            xml_lines.append(
                f'    <error line="{err["line"]}" column="{err["col"]}" severity="{escape_attr(severity)}" message="{escape_attr(err["message"])}" source="{escape_attr(err["source"])}" />'
            )
        xml_lines.append('  </file>')
    xml_lines.append('</checkstyle>')
    
    with open(checkstyle_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(xml_lines) + '\n')
    
    log(f"Updated checkstyle result at '{checkstyle_path}'. Total files: {len(errors_by_file)}.")

def main():
    new_errors = []
    
    # Run all rules
    new_errors.extend(check_sql_injection())
    new_errors.extend(check_snapshot_versions())
    new_errors.extend(check_lombok_di())
    new_errors.extend(check_circular_dependencies())
    new_errors.extend(check_transactional_visibility())
    new_errors.extend(check_constructor_logic())
    new_errors.extend(check_secrets())
    new_errors.extend(check_wrapper_equality())
    new_errors.extend(check_lazy_equals())
    new_errors.extend(check_try_with_resources())
    new_errors.extend(check_finally_return())
    new_errors.extend(check_immutable_mutation())
    new_errors.extend(check_foreach_modify())
    new_errors.extend(check_comparator_consistency())
    new_errors.extend(check_threadlocal_leak())
    new_errors.extend(check_rest_auth())
    new_errors.extend(check_request_body_validation())
    new_errors.extend(check_entity_request_body())
    new_errors.extend(check_jpql_injection())
    new_errors.extend(check_missing_authorization())
    new_errors.extend(check_log_secrets())
    new_errors.extend(check_file_upload_security())
    new_errors.extend(check_multi_step_transaction())
    new_errors.extend(check_lazy_initialization_dto())
    new_errors.extend(check_cascade_safety())
    new_errors.extend(check_modifying_query())
    new_errors.extend(check_money_bigdecimal())
    new_errors.extend(check_parameterized_logs())
    new_errors.extend(check_unbounded_loads())
    new_errors.extend(check_rule_17_1_person_identity())
    new_errors.extend(check_rule_17_2_module_codes())
    new_errors.extend(check_rule_17_3_file_upload_routing())
    new_errors.extend(check_rule_17_4_dual_path_stored_procedures())
    new_errors.extend(check_rule_17_5_award_mutation_bypass())
    new_errors.extend(check_rule_17_6_elastic_sync())
    new_errors.extend(check_rule_17_7_async_user_context())
    new_errors.extend(check_rule_17_8_hardcoded_client_logic())
    new_errors.extend(check_rule_17_9_log_tokens())
    new_errors.extend(check_rule_17_10_core_dependency())
    new_errors.extend(check_rule_17_11_char_boolean_conversion())
    new_errors.extend(check_rule_17_12_timezone_timestamps())
    new_errors.extend(check_rule_17_13_permitAll_justification())
    new_errors.extend(check_rule_17_14_native_sql_concat())
    new_errors.extend(check_changed_behavior_tests_warning())
    new_errors.extend(check_sonar_major_justification_warning())
    new_errors.extend(check_pin_versions_warning())
    new_errors.extend(check_document_new_properties_warning())
    new_errors.extend(check_uncommon_abbreviations_warning())
    new_errors.extend(check_service_dao_interface_impl_warning())
    new_errors.extend(check_magic_values_warning())
    new_errors.extend(check_enum_fixed_values_warning())
    new_errors.extend(check_long_literal_suffix_warning())
    new_errors.extend(check_class_suffixes_warning())
    new_errors.extend(check_boolean_naming_warning())
    new_errors.extend(check_prefer_slf4j_warning())
    new_errors.extend(check_lombok_dto_warning())
    new_errors.extend(check_spring_all_args_ctor_warning())
    new_errors.extend(check_async_scheduled_failure_handling_warning())
    new_errors.extend(check_access_static_via_class_warning())
    new_errors.extend(check_deprecated_apis_warning())
    new_errors.extend(check_null_safe_equality_warning())
    new_errors.extend(check_dto_wrappers_warning())
    new_errors.extend(check_stringbuilder_in_loops_warning())
    new_errors.extend(check_tightest_visibility_warning())
    new_errors.extend(check_break_method_signature_warning())
    new_errors.extend(check_collection_capacity_warning())
    new_errors.extend(check_iterate_map_entryset_warning())
    new_errors.extend(check_spring_singleton_vs_dcl_warning())
    new_errors.extend(check_threadlocal_random_warning())
    new_errors.extend(check_nesting_level_warning())
    new_errors.extend(check_complex_boolean_warning())
    new_errors.extend(check_http_verb_semantics_warning())
    new_errors.extend(check_proper_status_codes_warning())
    new_errors.extend(check_thin_controllers_warning())
    new_errors.extend(check_error_envelope_stack_trace_warning())
    new_errors.extend(check_paginate_lists_warning())
    new_errors.extend(check_avoid_n_plus_one_warning())
    new_errors.extend(check_named_params_in_query_warning())
    new_errors.extend(check_projections_for_search_warning())
    new_errors.extend(check_prefer_jpql_criteria_warning())
    new_errors.extend(check_native_sql_explicit_columns_warning())
    new_errors.extend(check_transactional_readonly_warning())
    new_errors.extend(check_no_transaction_remote_io_warning())
    new_errors.extend(check_avoid_self_invocation_warning())
    new_errors.extend(check_avoid_generic_update_warning())
    new_errors.extend(check_map_is_columns_warning())
    new_errors.extend(check_swallow_exception_warning())
    new_errors.extend(check_log_exc_get_message_warning())
    new_errors.extend(check_catch_npe_index_warning())
    new_errors.extend(check_try_catch_scope_warning())
    new_errors.extend(check_prefer_application_exception_warning())
    new_errors.extend(check_no_print_stack_trace_warning())
    new_errors.extend(check_brace_spacing_warning())
    new_errors.extend(check_max_line_length_warning())
    new_errors.extend(check_utf8_encoding_warning())
    new_errors.extend(check_manual_variable_alignment_warning())
    new_errors.extend(check_hygiene_whitespace_warning())
    new_errors.extend(check_commented_code_warning())
    new_errors.extend(check_todo_jira_warning())
    new_errors.extend(check_layer_package_warning())
    new_errors.extend(check_type_suffixes_warning())
    new_errors.extend(check_loop_db_calls_warning())
    new_errors.extend(check_caching_keys_warning())
    new_errors.extend(check_commit_hygiene_warning())
    new_errors.extend(check_pr_hygiene_warning())
    new_errors.extend(check_tests_deterministic_warning())
    new_errors.extend(check_domain_fixtures_warning())
    new_errors.extend(check_spring_boot_test_reserve_warning())
    new_errors.extend(check_prefer_typed_dto_warning())
    new_errors.extend(check_core_authenticated_user_warning())
    new_errors.extend(check_message_q_router_warning())
    new_errors.extend(check_no_dao_in_controller_warning())
    new_errors.extend(check_mutable_static_maps_warning())
    new_errors.extend(check_java_11_compat_warning())
    new_errors.extend(check_yes_no_flags_warning())
    new_errors.extend(check_constant_first_equals_warning())
    new_errors.extend(check_multipart_format_check_warning())
    new_errors.extend(check_jpa_getter_setter_only_warning())
    new_errors.extend(check_dto_boolean_wrapper_warning())
    new_errors.extend(check_log_context_ids_warning())
    new_errors.extend(check_db_sql_safe_updates())
    new_errors.extend(check_db_update_user_timestamp())
    new_errors.extend(check_db_changeset_unique_id())
    new_errors.extend(check_db_no_delimiter())
    new_errors.extend(check_db_changeset_path_match())
    new_errors.extend(check_db_no_secrets())
    new_errors.extend(check_db_drop_paired())
    new_errors.extend(check_db_create_or_replace())
    new_errors.extend(check_db_select_into_exception())
    new_errors.extend(check_db_drop_pk_index())
    new_errors.extend(check_db_no_self_join())
    new_errors.extend(check_db_null_inequality())
    new_errors.extend(check_db_terminate_slash())
    new_errors.extend(check_db_table_name())
    new_errors.extend(check_db_view_name())
    new_errors.extend(check_db_fk_align())
    new_errors.extend(check_db_proc_prefix())
    new_errors.extend(check_db_func_prefix())
    new_errors.extend(check_db_pkg_prefix())
    new_errors.extend(check_db_trg_prefix())
    new_errors.extend(check_db_seq_prefix())
    new_errors.extend(check_db_param_prefix())
    new_errors.extend(check_db_var_prefix())
    new_errors.extend(check_db_purpose_comment())
    new_errors.extend(check_db_case_number())
    new_errors.extend(check_db_keywords_upper())
    new_errors.extend(check_db_identifiers_lower())
    new_errors.extend(check_db_alias_consistent())
    new_errors.extend(check_db_no_schema_prefix())
    new_errors.extend(check_db_boolean_int())
    new_errors.extend(check_db_complex_logic_comment())
    new_errors.extend(check_db_magic_value_comment())
    new_errors.extend(check_db_use_type_declaration())
    new_errors.extend(check_db_where_order())
    new_errors.extend(check_db_set_where_column())
    new_errors.extend(check_db_no_function_where())
    new_errors.extend(check_db_prefer_outer_join())
    new_errors.extend(check_db_no_like_equal())
    new_errors.extend(check_db_count_column())
    new_errors.extend(check_db_use_bind_variables())
    new_errors.extend(check_db_exists_distinct())
    new_errors.extend(check_db_driving_table_order())
    new_errors.extend(check_db_filename_lowercase())
    new_errors.extend(check_db_package_one_file())
    new_errors.extend(check_db_combine_schema_changes())
    new_errors.extend(check_db_separate_data_scripts())
    
    try:
        new_errors.extend(check_compilation())
    except Exception as e:
        log(f"Error during compilation check: {e}")
        
    try:
        new_errors.extend(check_unused_dependencies())
    except Exception as e:
        log(f"Error during unused dependency check: {e}")
        
    try:
        new_errors.extend(check_version_bumps())
    except Exception as e:
        log(f"Error during version bump check: {e}")

    new_errors = filter_errors_to_pr_added_lines(new_errors)

    # Write merged results
    merge_and_write_checkstyle(new_errors)
    
    # Generate GitHub Step Summary
    write_github_step_summary(new_errors)
    
if __name__ == "__main__":
    main()
