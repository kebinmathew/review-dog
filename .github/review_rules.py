#!/usr/bin/env python3
import os
import sys
import re
import subprocess
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

# Constants for Rule IDs
RULE_COMPILATION = "Rule-1.1-Compilation-Failure"
RULE_SQL_INJECTION = "Rule-1.2-SonarQube-SQL-Injection"
RULE_UNUSED_DEPENDENCY = "Rule-1.4-Unused-Dependency"
RULE_SNAPSHOT_VERSION = "Rule-1.5-Snapshot-Version"
RULE_VERSION_BUMP = "Rule-1.6-Version-Bump"

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

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def check_compilation():
    errors = []
    if not os.path.exists('pom.xml'):
        return errors

    log("Running Maven compilation check...")
    # Run maven compile (test-compile compiles both main and test classes)
    code, stdout, stderr = run_command("mvn clean test-compile")
    if code != 0:
        log("Maven compilation failed! Parsing errors...")
        full_output = stdout + "\n" + stderr
        # Regex to match maven compilation errors:
        # [ERROR] /path/to/File.java:[line,col] error message
        # OR /path/to/File.java:line: error: message
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
                        # Resolve path relative to current workspace if it's absolute
                        if os.path.isabs(file_path):
                            file_path = os.path.relpath(file_path)
                        
                        # Only report if it is a file in our workspace
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
            # Fallback: if compilation failed but we couldn't parse the file/line, report it on pom.xml or line 1 of first java file
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

        # Strip multi-line comments (preserving newlines to maintain line numbers)
        def replacer_multiline(match):
            return re.sub(r'[^\n]', ' ', match.group(0))
        content_no_comments = re.sub(r'/\*.*?\*/', replacer_multiline, content, flags=re.DOTALL)

        # Strip single-line comments
        def replacer_singleline(match):
            return re.sub(r'[^\n]', ' ', match.group(0))
        content_no_comments = re.sub(r'//.*', replacer_singleline, content_no_comments)

        # Find statement boundaries
        statement_boundaries = [0]
        for match in re.finditer(r'[;{}]', content_no_comments):
            statement_boundaries.append(match.end())
        
        # Line number mapping
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
            
            # Parse string literals in this statement
            literal_matches = list(re.finditer(r'"([^"\\]|\\.)*"', statement_text))
            if not literal_matches:
                continue
                
            # Check if any literal matches SQL pattern
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
                
            # Replace literals in statement_text to get the template
            template = ""
            last_idx = 0
            for idx, m in enumerate(literal_matches):
                template += statement_text[last_idx:m.start()]
                template += f"__STR_LITERAL_{idx}__"
                last_idx = m.end()
            template += statement_text[last_idx:]
            
            # Check if there is a '+' operator in the template
            if '+' not in template:
                continue
                
            # Analyze parts split by '+'
            parts = template.split('+')
            for idx, part in enumerate(parts):
                part_stripped = part.strip()
                if not part_stripped:
                    continue
                
                # Get tokens in this part
                tokens = re.findall(r'\b[a-zA-Z0-9_]+\b', part_stripped)
                if not tokens:
                    continue
                
                # Identify which token is the operand
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
                    # Constants are safe (all uppercase)
                    if re.match(r'^[A-Z0-9_]+$', token):
                        continue
                    # Numbers are safe
                    if re.match(r'^\d+$', token):
                        continue
                    # It's a variable/method call
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
    # Run maven dependency:analyze-only (requires compilation first)
    code, stdout, stderr = run_command("mvn dependency:analyze-only")
    full_output = stdout + "\n" + stderr
    
    if "Unused declared dependencies found:" in full_output:
        log("Unused dependencies found! Parsing...")
        # Find lines after "Unused declared dependencies found:"
        lines = full_output.splitlines()
        started = False
        unused_deps = []
        for line in lines:
            if "Unused declared dependencies found:" in line:
                started = True
                continue
            if started:
                # Unused list ends at next section headers
                if "Used undeclared dependencies found:" in line or "Build success" in line or "BUILD SUCCESS" in line or not line.strip().startswith("[WARNING]"):
                    if not line.strip().startswith("[WARNING]    "):
                        started = False
                if started and line.strip().startswith("[WARNING]    "):
                    # Format: [WARNING]    group.id:artifact-id:type:version:scope
                    dep_str = line.strip().replace("[WARNING]    ", "").strip()
                    parts = dep_str.split(':')
                    if len(parts) >= 2:
                        unused_deps.append((parts[0], parts[1])) # (groupId, artifactId)
        
        # Locate unused dependencies in pom.xml files
        pom_files = find_pom_files()
        for pom_file in pom_files:
            try:
                with open(pom_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                for group_id, artifact_id in unused_deps:
                    # Let's find the dependency block
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
    # Strip xmlns to avoid namespace parsing complexity
    pom_content_clean = pom_content.replace('xmlns="http://maven.apache.org/POM/4.0.0"', '')
    # Remove default namespace definition completely
    pom_content_clean = re.sub(r'\sxmlns="[^"]+"', '', pom_content_clean)
    try:
        root = ET.fromstring(pom_content_clean)
        # Find project version (direct child of project, not inside parent or dependency)
        version_elem = root.find('./version')
        version = version_elem.text.strip() if version_elem is not None else None
        
        # Find properties
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
        # Detect default remote branch
        code, stdout, stderr = run_command("git symbolic-ref --short refs/remotes/origin/HEAD")
        if code == 0 and stdout.strip():
            base_branch = stdout.strip().replace("origin/", "")
        else:
            base_branch = "main"

    log(f"Comparing changes against base branch: origin/{base_branch}")
    
    # Run git fetch to make sure the base branch commit is present
    run_command(f"git fetch origin {base_branch}:{base_branch}")
    
    # Get list of changed files
    code, stdout, stderr = run_command(f"git diff --name-only origin/{base_branch}...HEAD")
    if code != 0 or not stdout.strip():
        # Fallback to direct diff with origin/base_branch
        code, stdout, stderr = run_command(f"git diff --name-only origin/{base_branch}")
        if code != 0:
            log("Failed to get git diff. Skipping version bump checks.")
            return errors
            
    changed_files = [line.strip() for line in stdout.splitlines() if line.strip()]
    log(f"Changed files in PR: {changed_files}")

    # Find modules (subdirectories containing pom.xml, except root)
    pom_files = find_pom_files()
    modules = []
    for pom in pom_files:
        module_dir = os.path.dirname(pom)
        if module_dir != '.' and module_dir != '':
            modules.append(module_dir)
            
    log(f"Detected modules: {modules}")

    # Read base branch root pom properties
    root_pom_properties_base = {}
    if os.path.exists('pom.xml'):
        code, stdout, stderr = run_command(f"git show origin/{base_branch}:pom.xml")
        if code == 0:
            _, root_pom_properties_base = get_pom_version_and_properties(stdout)
            
    # Read current branch root pom properties
    root_pom_properties_current = {}
    if os.path.exists('pom.xml'):
        try:
            with open('pom.xml', 'r', encoding='utf-8') as f:
                _, root_pom_properties_current = get_pom_version_and_properties(f.read())
        except Exception:
            pass

    for module in modules:
        # Check if any files in this module changed (excluding pom.xml itself)
        module_changed = False
        changed_module_files = []
        for file in changed_files:
            # Check if file starts with module directory and is not module's pom.xml
            if file.startswith(module + '/') and not file.endswith('pom.xml'):
                module_changed = True
                changed_module_files.append(file)
                
        if not module_changed:
            continue
            
        log(f"Module '{module}' has changes in: {changed_module_files}")
        
        # Verify version bump
        version_bumped = False
        
        # 1. Check version in module's own pom.xml
        module_pom_path = os.path.join(module, 'pom.xml')
        base_version = None
        current_version = None
        
        # Get base version of the module pom.xml
        code, stdout, stderr = run_command(f"git show origin/{base_branch}:{module_pom_path}")
        if code == 0:
            base_version, _ = get_pom_version_and_properties(stdout)
            
        # Get current version of the module pom.xml
        if os.path.exists(module_pom_path):
            try:
                with open(module_pom_path, 'r', encoding='utf-8') as f:
                    current_version, _ = get_pom_version_and_properties(f.read())
            except Exception:
                pass
                
        if base_version and current_version and base_version != current_version:
            log(f"Module '{module}' version bumped in its pom.xml: {base_version} -> {current_version}")
            version_bumped = True
            
        # 2. Check root pom properties for a property like <module-name.version> or <module-name-version>
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
                log(f"Module '{module}' version property '{prop}' bumped in parent pom: {base_val} -> {current_val}")
                version_bumped = True
                break
                
        if not version_bumped:
            # Report error on module's pom.xml or the first changed file in the module
            target_file = module_pom_path if os.path.exists(module_pom_path) else changed_module_files[0]
            errors.append({
                'file': target_file,
                'line': 1,
                'col': 1,
                'message': f"Rule 1.6: Bump shared module versions when they change. Shared module '{module_name}' was changed but its version was not bumped.",
                'source': RULE_VERSION_BUMP
            })
            
    return errors

def merge_and_write_checkstyle(new_errors, checkstyle_path="checkstyle-result.xml"):
    # Group errors by file
    errors_by_file = {}
    
    # Read existing checkstyle if exists
    if os.path.exists(checkstyle_path) and os.path.getsize(checkstyle_path) > 0:
        try:
            tree = ET.parse(checkstyle_path)
            root = tree.getroot()
            for file_elem in root.findall('file'):
                file_name = file_elem.get('name')
                # Resolve to relative path for uniformity
                if os.path.isabs(file_name):
                    file_name_rel = os.path.relpath(file_name)
                else:
                    file_name_rel = file_name
                
                if file_name_rel not in errors_by_file:
                    errors_by_file[file_name_rel] = []
                    
                for err_elem in file_elem.findall('error'):
                    errors_by_file[file_name_rel].append({
                        'line': int(err_elem.get('line', 1)),
                        'col': int(err_elem.get('column', 1)),
                        'message': err_elem.get('message', ''),
                        'source': err_elem.get('source', '')
                    })
        except Exception as e:
            log(f"Error parsing existing checkstyle XML: {e}. Recreating...")

    # Merge new errors
    for err in new_errors:
        file_name = err['file']
        if os.path.isabs(file_name):
            file_name = os.path.relpath(file_name)
        if file_name not in errors_by_file:
            errors_by_file[file_name] = []
        errors_by_file[file_name].append({
            'line': err['line'],
            'col': err['col'],
            'message': err['message'],
            'source': err['source']
        })

    # Write back XML
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<checkstyle version="8.0">']
    for file_name, file_errors in errors_by_file.items():
        # Ensure path uses backslashes or forward slashes depending on OS, but forward slash is safer for Unix reviewdog
        unix_file_name = file_name.replace('\\', '/')
        xml_lines.append(f'  <file name="{escape(unix_file_name)}">')
        for err in file_errors:
            xml_lines.append(
                f'    <error line="{err["line"]}" column="{err["col"]}" severity="error" message="{escape(err["message"])}" source="{escape(err["source"])}" />'
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
    
    # These checks require maven and git. Let's run them and capture errors.
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

    # Write merged results
    merge_and_write_checkstyle(new_errors)
    
if __name__ == "__main__":
    main()
