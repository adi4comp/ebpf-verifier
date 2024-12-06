import os
import subprocess
import re
import sys

def natural_sort_key(s):
    return [int(text) if text.isdigit() else text.lower() 
            for text in re.split(r'(\d+)', s)]

def extract_sections(output):
    sections = []
    for line in output.split('\n'):
        if 'section=' in line:
            match = re.search(r'section=([\w/]+)', line)
            if match:
                sections.append(match.group(1))
    return sections

def run_check_binary(check_binary, binary_path, section=None):
    try:
        cmd = [check_binary, binary_path, section] if section else [check_binary, binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout.strip() or result.stderr.strip()
        
        if re.match(r'^-?\d+,\d+\.\d+,\d+$', output):
            parts = output.split(',')
            return {
                'status': int(parts[0])
            }
        if 'error:' in output.lower():
            return {
                'status': 'error',
                'error_message': output
            }
        if 'please specify a program' in output:
            sections = extract_sections(output)
            return {
                'status': 'no_program_specified',
                'sections': sections
            }
        return {
            'status': 'section_output',
            'raw_output': output
        }
    
    except subprocess.TimeoutExpired:
        return {
            'status': 'timeout',
            'error_message': 'Command timed out'
        }
    except Exception as e:
        return {
            'status': 'exception',
            'error_message': str(e)
        }

def parse_bpf_files(check_binary, directory='.'):
    results = {}
    bpf_files = sorted([f for f in os.listdir(directory) if f.endswith('.bpf.o')], 
                       key=natural_sort_key)
    
    for bpf_file in bpf_files:
        file_path = os.path.join(directory, bpf_file)
        base_name = os.path.splitext(bpf_file)[0]
        
        try:
            file_result = run_check_binary(check_binary, file_path)
            if file_result.get('status') == 'no_program_specified':
                section_results = {}
                for section in file_result.get('sections', []):
                    section_result = run_check_binary(check_binary, file_path, section)
                    section_results[section] = section_result

                if section_results:
                    results[base_name] = section_results
                else:
                    results[base_name] = file_result
            else:
                results[base_name] = file_result
        except Exception:
            continue
    
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py /path/to/check [directory]")
        sys.exit(1)
    
    check_binary = sys.argv[1]
    directory = sys.argv[2] if len(sys.argv) > 2 else '.'

    parse_results = parse_bpf_files(check_binary, directory)
    
    for filename, result in parse_results.items():
        print(f"{filename} = {result}")

if __name__ == "__main__":
    main()