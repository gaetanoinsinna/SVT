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

And the output is

``` 
<SimulationManager with 2 active, 9 deadended, 1 found> 
```
That means that it has exited from program for 9 explored branches without reach the required state (deadened). Only in 1 branch he program reached the address passed (```0x08048717``)

The found and the active states can be accessed by the ```found``` and ```active``` lists
```
found = sm.found[0]
active = sm.active[0]
...
```

And can also be see the output of the application 

```
found = found.posix.dumps(0)
found = found.posix.dumps(1)
```

## Starting the simulation from any state

We can instantiate a Simulation Manager at any state, so we decide to instatiate in found
```
sm1 = p.factory.simulation_manager(found)
```
And from here we can perform a single step until we reach the desired output
```
sm1.step()
sm1.active[0].posix.dumps(1)
```

Until we reach the following output
```
Out[x]: b"############################################################\n##        Bienvennue dans ce challenge de cracking        ##\n############################################################\n\nVeuillez entrer le mot de passe : Bien joue, vous pouvez valider l'epreuve avec le pass : 123456789!\n"
```

## Pruning unwanted branches

We may want to avoid some parts of the code that we already know are useless. We can find them with ```radare2``` by checking the CFG. In this case we know which branch to take so we can discard the other one that is at address ```0x0804871e```

```
sm = p.factory.simulation_manager(es)
sm.explore(find=0x08048717,avoid=0x0804871e)

```
And the output is

``` 
<SimulationManager with 1 active, 1 found, 10 avoid> 
```

