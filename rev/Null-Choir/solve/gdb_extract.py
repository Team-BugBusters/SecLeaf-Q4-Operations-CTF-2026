# Null Choir (SecLeaf CTF 2026) - GDB extraction script used during the solve.
#
# Runs INSIDE GDB (it imports the `gdb` module), not with plain python3:
#
#   cd ../attachments
#   printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' > in.txt
#   NC_WORKDIR="$PWD" gdb -q -batch -x ../solve/gdb_extract.py ./null_choir
#
# The binary and its data files (null_choir, canticle.score, echoes.trace) were
# not archived. With ASLR disabled the PIE base is 0x555555554000; the two
# breakpoint offsets below come from our disassembly of the stripped binary.
#
# Outputs (written to NC_WORKDIR):
#   recs.txt   decoded VM instruction records, "<r8> <16-byte hex>" per line
#   state.txt  final 48-byte VM state (hex)
#   regs.txt   runtime key in rbp, read at the END breakpoint
#              (reading rbp at an earlier point gave a wrong value)
import os

import gdb

WORKDIR = os.environ.get("NC_WORKDIR", os.getcwd())

gdb.execute('set disable-randomization on')
gdb.execute(f'starti < {WORKDIR}/in.txt')

B = 0x555555554000            # PIE base with randomisation off
inf = gdb.selected_inferior()
recs = []


class BP(gdb.Breakpoint):
    def __init__(s, a, tag):
        super().__init__('*0x%x' % (B + a))
        s.tag = tag

    def stop(s):
        r = lambda n: int(gdb.parse_and_eval('$' + n)) & (2**64 - 1)

        if s.tag == 'rec':
            # one decoded 16-byte VM instruction per hit
            m = bytes(inf.read_memory(r('rsp') + 0x50, 16))
            recs.append((r('r8'), m.hex()))

        elif s.tag == 'end':
            # final six-word (48-byte) state just before the comparison
            st = bytes(inf.read_memory(r('rsp') + 0x60, 48))
            open(f'{WORKDIR}/state.txt', 'w').write(st.hex() + '\n')
            open(f'{WORKDIR}/recs.txt', 'w').write('\n'.join('%d %s' % x for x in recs))
            open(f'{WORKDIR}/regs.txt', 'w').write('rbp=%x\n' % r('rbp'))

        return False               # never actually stop; just collect


BP(0x179b, 'rec')   # decoded VM instruction available
BP(0x1cc6, 'end')   # final VM state available

gdb.execute('continue')
