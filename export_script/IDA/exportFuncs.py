import contextlib
import idc
import re
import idaapi
# export functions addresses and names to a file


# calling convention
class calling_convention:
    fastcall = 112
    nothing = 16
    usercall = 240
    cdecl = 48
    noreturn = 64

def check_calling_conv(ea):
    f = idaapi.get_func(ea)
    cfunc = idaapi.decompile(f)
    tinfo = idaapi.tinfo_t()
    cfunc.get_func_type(tinfo)
    funcdata = idaapi.func_type_data_t()
    tinfo.get_func_details(funcdata)
    print(funcdata.cc, idc.get_func_name (ea))
    # NOTICE: here you can add other calling convention
    return funcdata.cc == calling_convention.fastcall


def validate(ea, n):
    print(n, idc.get_func_name (ea))
    with contextlib.suppress(Exception):
        name = idc.get_func_name (ea)
        # NOTICE: here you can add other function name pattern, but be careful, some functions 
        # shown in IDA are not real functions, so you can export a lot of functions that may 
        # crash frida
        if name.startswith("sub_"):
            # NOTICE: comment the return if you want to export only somme functions type.
            # Fastcall functions are the most common an the most important to reverse generally
            return True
            return check_calling_conv(ea)

    return False
    
    
print("Exporting functions... Can take a while... 2 to 15 minutes")
funcs = [idaapi.getn_func(i) for i in range(idaapi.get_func_qty()) ]
funcs = [f for f in funcs if len(list(FuncItems(f.start_ea))) > 20 ]
funcs = [f for n,f in enumerate(funcs) if validate(f.start_ea, n)]
funcs_ea_nameDict = {f.start_ea:idc.get_func_name (f.start_ea) for f in funcs}

# NOTICE: set the path to the file you want to export
with open("", "w") as f:
    for ea, name in funcs_ea_nameDict.items():
        # check function name 
        f.write(f"{hex(ea)} {name}\n")
        
print ("Export Done!")