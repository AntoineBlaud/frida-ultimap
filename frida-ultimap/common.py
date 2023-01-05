import contextlib
import psutil
import json
import pprint 
from collections import OrderedDict
import frida
import sys
import time

def find_pid_by_name(name):
    pid = next(
        (proc.pid for proc in psutil.process_iter() if proc.name() == name),
        None,
    )
    if pid is None:
        raise ValueError(f'Process with name {name} not found: PID={pid}')
    print(f'Process with name {name} found: PID={pid}')
    return pid

def find_remote_pid_by_name(device, name):
    pid = next(
        (proc.pid for proc in device.enumerate_processes() if proc.name == name), None
    )
    if pid is None:
        raise ValueError(f'Process with name {name} not found: PID={pid}')
    print(f'Process with name {name} found: PID={pid}')
    return pid
    


def load_exported_functions(filename, todrop=set()):
    # import IDA functions 
    funcs = _load_exported_functions(filename, todrop)
    return (
        "{"
        + ", ".join(["\"" + v + "\": " + k + "" for k, v in funcs.items()])
        + "};"
    )

def _load_exported_functions(filename, todrop=set()):
    f = open(filename, "r")
    funcs = [f.strip() for f in f]
    funcs = {func.split(" ")[0]: func.split(" ")[1] for func in funcs}
    funcs = {hex(int(k[2:], 16)) : v for k, v in funcs.items()}
    funcs = {k: v for k, v in funcs.items() if k not in todrop}
    funcs = OrderedDict(sorted(funcs.items(), key=lambda x: int(x[0][2:], 16)))
    return funcs
    
def load_functions_records(path, *filenames):
    functions = set()
    for file in filenames:
        f = open(f"{path}/{file}", "r")
        data = json.load(f)
        functions.update(data.keys())
    return functions
        

# TODO : dichotomic search  
def find_functionaddr_fromaddress(address, exported_functions):
    for k in range(len(exported_functions) - 1):
        address1  = int(exported_functions[k][2:], 16)
        address2 = int(exported_functions[k + 1][2:], 16)
        if address1 <= address < address2:
            return address1
    return None
        
def process_results(filestdout):
    func_count = None

    with open(filestdout, "r") as f:
        content = f.read()
    try:
        func_count = content.split(":::")[1]
    except IndexError as e:
        raise Exception("No results found, check frida.stdout file")

    return json.loads(func_count)


def find_process(processname, isdesktop):
    if isdesktop:
        session, pid = attach_to_process(processname)
    else:
        device = frida.get_usb_device()
        realprocessname = input(
            "[>] Enter (running process name) or (path) or (application bundle name) , ex: com.supercell.clashofclans: ")
        session, pid = attach_to_remote_process(device, realprocessname)

    return session, pid

def attach_to_process(processname):
    try:
        pid = find_pid_by_name(processname)
        session = frida.attach(pid)
    except Exception as e:
        print(e)
        # spawn process
        processargs = input(
            "[>] Enter full path of process following by args to spawn it (pid not found) : ").split(" ")
        session = frida.attach(frida.spawn(processargs))
        pid = find_pid_by_name(processname)
    return session, pid

def attach_to_remote_process(device, realprocessname):
    try:
        pid = find_remote_pid_by_name(device, realprocessname)
        session = device.attach(pid)
    except Exception as e:
        pid = device.spawn([realprocessname])
        session = device.attach(pid)
    return session, pid

def wait(session):
    while True:
        enter = input(
            "[>] Press enter to start recording, or type 'exit' to exit : ")
        if enter == "exit":
            session.detach()
            sys.exit(0)
        elif enter == "":
            break

def wait_and_redirect(delaytowait, backup_stdout, timeout, stdoutfile):
    sys.stdout = open(stdoutfile, "w")
    time.sleep(timeout + delaytowait)
    sys.stdout = backup_stdout    
        

def ask_timeout(default=8000):
    asktimeout = input(
        "[>] Enter recording time in milliseconds (press enter to attribute 8000 ms) : "
    )
    return default if asktimeout == "" else int(asktimeout)
        

def ask_drop(maindirectory, todrop):
    askdrop = input("[>] Drop functions registered in previous recording (y or n) : ")
    if askdrop == "y":
        previous_records = os.listdir(maindirectory)
        previous_records = [
            jsonf for jsonf in previous_records if jsonf.find(".json") > 0
        ]
        for record in previous_records:
            askdrop = input(f"[>] Drop {record} (y or n or all) : ")
            if askdrop == "y":
                todrop.update(load_functions_records(maindirectory, record))
            elif askdrop == "all":
                todrop = load_functions_records(maindirectory, *previous_records)
                break
    return todrop          
            
        
def attach_script(script, pid, session):
    frida_script = session.create_script(script)
    frida_script.load()
    with contextlib.suppress(Exception):
        device.resume(pid)
    # resume process if it has been spwaned
    with contextlib.suppress(Exception):
        device = frida.get_local_device()
        device.resume(pid)


def capture_results(delaytowait, backup_stdout, metadatafolder, processname, timeout, outfile):
    stdoutfile = f"{metadatafolder}/{processname}/{outfile}.stdout"
    wait_and_redirect(delaytowait, backup_stdout, timeout, stdoutfile)
    # load results from the stdout. Must parse it to find JSON object
    results = process_results(stdoutfile)
    pprint.pprint(results)
    # save results
    savedata = f"{metadatafolder}/{processname}/{outfile}.json"
    with open(savedata, "w") as f:
        json.dump(results, f)

    print(f"[INFO] Results saved in {stdoutfile} and in {savedata}. \
            Please check them before continuing")

def load_config(config_file):
    with open(config_file, "r") as f:
        processname, filename, exportedbase = f.read().strip().split("::")
        print(f"[INFO] Loaded previous configuration:")
        print(f"Export filename: {filename}")
        print(f"Process name: {processname}")
        print(f"Exported base address: {exportedbase}")
    return processname, filename, exportedbase

def get_config_from_user():
    processname = input("[>] Enter process name (or native lib name for mobile) : ")
    filename = input("[>] Enter filename of exported functions: ")
    exportedbase = input("[>] Enter base address of exported functions as hex : ")
    return processname, filename, exportedbase