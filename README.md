# unpyarmor
## Usage
- Extract the encrypted code from the obfuscated file (it should be inside a bytes string as the third argument to ` __pyarmor__`). Write this as raw data to a file, say 'enc.bin'.
- Run `unpyarmor unpack enc.bin pytransform.key out.pyc`, where out.pyc is a pyc file where the decrypted code will be written.
- Use a python decompiler to decompile the decrypted pyc file, e.g. `decompyle3 out.pyc` or `uncompyle6 out.pyc`.

## Missing
- Python versions other than 3
- Advanced mode
- Super mode
- Possibly some other modes
