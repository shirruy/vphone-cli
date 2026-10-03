"""Fix: For argument tracing TO a call, start from the instruction BEFORE the BL."""
import hashlib, json, os, struct, sys
import capstone

DUMPDIR = os.path.join(os.environ['TEMP'], '57zz-binaries')
OUT = 'artifacts/evidence/05f/phase05f-data-volume-create-callers.json'

# Import engine
sys.path.insert(0, 'scripts')
exec(open('scripts/phase05f-arm64-dataflow-engine.py').read().split('def run_unit_tests')[0])

CALLERS = [0x100024428, 0x10003f970, 0x100053458, 0x10007c1ac, 0x10007c1c4, 0x10007e874, 0x1001a2320]

def get_text_section(data):
    ncmds = struct.unpack_from('<I', data, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, off)
        if cmd == 0x19:
            nsects = struct.unpack_from('<I', data, off+64)[0]
            so = off + 72
            for i in range(nsects):
                sn = data[so:so+16].split(b'\x00')[0].decode('ascii',errors='replace')
                addr, size = struct.unpack_from('<QQ', data, so+32)
                sect_fo = struct.unpack_from('<I', data, so+48)[0]
                if sn == '__text':
                    return {'vm': addr, 'size': size, 'off': sect_fo}
                so += 80
        off += cmdsize
    return None

def main():
    data = open(os.path.join(DUMPDIR, 'restored_external.bin'), 'rb').read()
    sha = hashlib.sha256(data).hexdigest()
    text = get_text_section(data)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    results = []
    for cvm in CALLERS:
        func_start = cvm
        for back in range(4, min(2000, cvm - text['vm']), 4):
            prev_fo = text['off'] + (cvm - text['vm']) - back
            if prev_fo < text['off']: break
            prev = struct.unpack_from('<I', data, prev_fo)[0]
            if prev == 0xD503237F:
                func_start = cvm - back
                break

        fo = text['off'] + (func_start - text['vm'])
        size = cvm - func_start + 4  # include the BL itself
        insns = list(md.disasm(data[fo:fo+size], func_start))

        # KEY FIX: For argument tracing, start from the instruction BEFORE the BL
        # The BL at insns[-1] is the _APFSVolumeCreate call itself.
        # We trace backward from insns[-2] (the instruction before the call).
        # This way, intervening BLs between the x1 definition and the create
        # call are properly treated as clobber boundaries, but the create call
        # itself is the target, not a boundary.
        
        arg_trace_idx = len(insns) - 2  # index of instruction BEFORE the BL
        
        if arg_trace_idx < 0:
            # Call is the first instruction in the function
            x0_result = [{'state': 'FUNCTION_ENTRY_ARGUMENT', 'defines': 'x0'}]
            x1_result = [{'state': 'FUNCTION_ENTRY_ARGUMENT', 'defines': 'x1'}]
            x0_state = 'FUNCTION_ENTRY_ARGUMENT'
            x1_state = 'FUNCTION_ENTRY_ARGUMENT'
        else:
            # Create a temporary list WITHOUT the BL for argument tracing
            # This prevents the engine from treating the target BL as a boundary
            arg_insns = insns[:-1]  # all instructions except the target BL
            
            # Trace x0 and x1 backward through arg_insns
            # The engine will correctly stop at any intervening BL (helper calls)
            x0_chain, x0_term = trace_backward_abi_safe(arg_insns, 'x0', len(arg_insns)-1)
            x1_chain, x1_term = trace_backward_abi_safe(arg_insns, 'x1', len(arg_insns)-1)
            x0_state = x0_chain[-1]['state'] if x0_chain else 'NONE'
            x1_state = x1_chain[-1]['state'] if x1_chain else 'NONE'

        results.append({
            'callsite_vm': '0x%x' % cvm,
            'function_start_heuristic': '0x%x' % func_start,
            'x0_argument_provenance': x0_state,
            'x1_argument_provenance': x1_state,
            'x1_chain': x1_chain if arg_trace_idx >= 0 else [],
        })

        print('=== 0x%x ===' % cvm)
        print('  x0 argument: %s' % x0_state)
        print('  x1 argument: %s' % x1_state)
        if arg_trace_idx >= 0 and x1_chain:
            for e in x1_chain[:3]:
                print('    %s: %s -> %s' % (e.get('vm',''), e.get('insn','entry'), e.get('state','')))
        print()

    existing = json.load(open(OUT, encoding='utf-8')) if os.path.exists(OUT) else {}
    existing['abi_safe_argument_trace'] = {
        'method': 'argument tracing: exclude target BL, trace backward from preceding instruction',
        'note': 'The target BL (_APFSVolumeCreate) is NOT treated as a clobber boundary for its own arguments. Intervening helper BLs ARE correctly treated as boundaries.',
        'binary_sha256': sha,
        'callers': results,
        'x0_summary': {r['callsite_vm']: r['x0_argument_provenance'] for r in results},
        'x1_summary': {r['callsite_vm']: r['x1_argument_provenance'] for r in results},
    }
    json.dump(existing, open(OUT, 'w', encoding='utf-8', newline='\n'), indent=2)
    print('WROTE', OUT)
    return 0

if __name__ == '__main__':
    sys.exit(main())
