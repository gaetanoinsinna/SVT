# Simulation Manager

In order to find the right address to branch in

```
radare2 crackme2
aaaa
sf main
pdf
```
The address we are looking for is ```0x08048717``` that is the address where the success text is printed

In a ```angr``` envoirment we run these commands
 
```
ipython3

import angr
p = angr.Project('./crackme2',load_options={"auto_load_libs":False})
es = p.facotry.entry_state()
sm = p.factory.simulation_manager(es)
sm.explore(find=0x08048717)
```
