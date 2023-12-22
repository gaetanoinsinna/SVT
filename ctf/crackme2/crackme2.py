import angr 

p = angr.Project('./crackme2',load_options={"auto_load_libs":False})

es = p.factory.entry_state()

sm = p.factory.blank_state(addr=0x4010f0)

sm.explore(find=lambda s:b"Correct" in s.posix.dumps(1))

found = sm.found[0]