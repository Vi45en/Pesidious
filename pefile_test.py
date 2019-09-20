import pefile

exe_path = "C:\Program Files\PuTTY\putty.exe"
pe = pefile.PE(exe_path)


for section in pe.sections:
    print section