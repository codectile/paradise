x86/x64 hooking library

## Examples

```c++
#include <iostream>
#include "X96Hook.h"

#define FUNC_FooBar     0xCAFEBABE //address of a function of type void()

/* The function looks like this
 * void FooBar()
 * {
 *      std::cout << "FooBar called \n";
 * }
 */

typedef void (*pfn_FooBar)();

void FooBar_hk() //our hook function
{
    std::cout << "hook called\n";
    
}

int main()
{
    X32Hook foo_hook;
    foo_hook.SetupHook((void*)FUNC_FooBar, FooBar_hk); //setup our hook
    foo_hook.InstallHook(); //install our hook function
    pfn_FooBar FooBar_t = (pfn_FooBar)FUNC_FooBar; //create a function pointer
    FooBar_t(); //call the hooked function (FUNC_FooBar)
    foo_hook.RemoveHook(); //remove the hook
    
    //possible output: hook called
    return 1;
}
    
```

#### Trampolines

```c++
#include <iostream>
#include "X96Hook.h"

#define FUNC_FooBar     0xCAFEBABE //address of a function of type void()
/* The function looks like this
 * void FooBar()
 * {
 *      std::cout << "FooBar called \n";
 * }
 */

typedef void (*pfn_FooBar)();
pfn_FooBar FooBar_t = NULL;

X32Hook foo_hook;

void FooBar_hk() //our hook function
{
    std::cout << "hook called\n";
    ((pfn_FooBar)foo_hook.Trampoline())(); //call the original un-hooked function to perform its tasks
    /* way without trampoline:
    
     * foo_hook.RemoveHook();
     * FooBar_t();
     * foo_hook.InstallHook();
     
     * using trampolines is way more optimized
     */
}

int main()
{
    foo_hook.SetupHook((void*)FUNC_FooBar, FooBar_hk); //setup our hook
    foo_hook.InstallHook(); //install our hook function
    FooBar_t = (pfn_FooBar)FUNC_FooBar; //assign FUNC_FooBar to FooBar_t
    FooBar_t(); //call the hooked function (FUNC_FooBar)
    foo_hook.RemoveHook(); //remove the hook
    
    //possible output:
    //hook called
    //FooBar called
    return 1;
}
```
