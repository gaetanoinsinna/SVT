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
## Conditional execution with PIE binaries

> PIE stands for Position Independent Excutable, which means that every time a binary is runned the file it gets loaded into a different memory address. This means you cannot hardcode values such as address without finding out where they are.

```
ipython3

import angr
p = angr.Project('./crackme3',load_options={"auto_load_libs":False})
```

The memory layout is randomised in this example. With ```radare2``` find the offset of the branch we want to reach.
```
0x000011b9
```
and with ```angr```  find the base address
```
p.loader.min_addr
Out[x]: 4194304
```
> This address is an integer, so firstly convert it in hex value

And now we can find the real address
```
0x4011b9
```
and repeat the steps described in last sections in order to crack the program

```
sm.explore(find=0x4011b9)
found = sm.found[0]
sm1 = p.factory.simulation_manager(found)
sm1.step()
sm1.active[0].posix.dumps(1)
```

The lasts two steps have to be repeated until the desired output is reached and we can extract the corret input

```
sm1.active.posix.dumps(0) # 4294783846
```

## Working with known output
The ```find``` function can be used also to look for a specific output (e.g., a string found thanks a bug or whatelse).


```
sm.explore(find=lambda s:b"Bien joue" in s.posix.dumps(1))
print(sm.found[0].posix.dumps(0)) # 123456789/n
```

```
sm.explore(find=lambda s:b"Good job mate" in s.posix.dumps(1))
print(sm.found[0].posix.dumps(0)) # 4294783846
```

## Claripy

```
import angr, claripy
p = angr.Project('./fairlight',load_options={"auto_load_libs":False})
argv1 = claripy.BVS("argv1",8 * 0xe)
initial_state = p.factory.entry_state(args=["./fairlight",argv1])

sm.explore(find=0x00401a4d)
found = sm.found[0]
sm1 = p.factory.simulation_manager(found)
sm1.step() and sm1.active[0].posix.dumps(1)
```
Again, the last two steps until the output is founded
```
b'OK - ACCESS GRANTED: CODE{4ngrman4gem3nt}\n'
```
# Exercises 
## Exercise 1
```
offset = 0x0000124f # it represents the offset, may change time to time
base = 0x400000
addr = 0x40124f
```
---
```
sm.explore(find= lambda s:b"This is the answer" in s.posix.dumps(1))
```
## Exercise 2
This exercise could be solved by searching for the string "Good Job." among the strings or by disassambling the code, but this time we try to use Claripy.
| dc084082 b46a40c8 364df430
## Exercise 3
This exercise could be solved by searching for the string "Good Job." among the strings or by disassambling the code, but this time we try to use Claripy.
| NLYXSEYQ PDVULKVJ TLOPVCDT WNSRLTTQ
## Exercise 4

## Exercise 5
