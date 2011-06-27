
import os
import subprocess

from logic import Conj
import constraint_gen
import logic


bundle_size = 32

bits = 32


def Main():
  asm_fh = open('tmp.S', 'w')

  def OnResult(info):
    # For relative jumps, fill in wildcards with 0 so that the jumps
    # point to somewhere valid.  Otherwise, use a non-zero value to
    # make things more interesting.
    if info['jump_type'] == 'relative_jump':
      wildcard_byte = '00'
    else:
      wildcard_byte = '11'
    def MapWildcard(byte):
      if byte == 'XX':
        return wildcard_byte
      else:
        return byte
    bytes = map(MapWildcard, info['bytes'])
    # Put each instruction in a separate bundle for two reasons:
    #  * It is the easiest way to prevent instructions from straddling
    #    bundle boundaries.
    #  * It helps ncval to continue if it hits an unknown instruction.
    padding = ['90'] * (bundle_size - len(bytes))
    if info['inst'] == 'calll':
      # The original ncval requires that 'call' instructions are
      # aligned such that they end at an instruction bundle boundary.
      # This is not required for safety, but we humour the validator.
      # See http://code.google.com/p/nativeclient/issues/detail?id=1955
      bytes = padding + bytes
    else:
      bytes = bytes + padding
    escaped_bytes = ''.join('\\x' + byte for byte in bytes)
    asm_fh.write('.ascii "%s"\n' % escaped_bytes)

  term = Conj(constraint_gen.OneOfEachType,
              constraint_gen.NaClConstraints)
  logic.GenerateAll(term, OnResult)
  asm_fh.close()
  subprocess.check_call(['gcc', '-c', '-m%i' % bits, 'tmp.S', '-o', 'tmp.o'])
  subprocess.check_call(['nacl-gcc', '-nostartfiles',
                         '-Wl,--entry=0', # Suppress warning about _start
                         '-m%i' % bits, 'tmp.o', '-o', 'tmp.exe'])
  # We assume that ncval and ncval_annotate.py are on PATH.
  # Run ncval_annotate.py to get errors with disassembly.
  # Run ncval on its own just in case.
  subprocess.check_call(['ncval_annotate.py', 'tmp.exe'])
  subprocess.check_call(['ncval', 'tmp.exe'], stdout=open(os.devnull, 'w'))


if __name__ == '__main__':
  Main()
