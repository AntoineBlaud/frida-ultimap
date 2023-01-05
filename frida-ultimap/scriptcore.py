def replace_all(text, dic_vars):
    for i, j in dic_vars.items():
        text = text.replace(i, j)
    return text


def build_script(args, dic_vars):
    script = replace_all(global_var, dic_vars)
    if args.platform == "windows":
        script += platform_windows
    if args.platform == "linux":
        script += platform_linux
    if args.platform == "android":
        script += platform_android
    script+= common
    script += process_module
    script += hook
    script += timeout
    script += replace_all(register, dic_vars)
    return script

global_var = """
// dict Array of events
var events = {};
var funcs = $$REGISTER_FUNC$$;
var ida_base = $$IDA_BASE$$;
var module_name = "$$MODULE_NAME$$";
var timeout = $$TIMEOUT$$;
var dump_string_times = $$DUMPSTRINGTIMES$$;
var libeventscount = {};
var base_ea = 0x0;

var register_args = ["rcx", "rdx", "rsi" , "rdi", "rbp", "rsp", "rax", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

// you can add more libraries here
var default_windows_lib = ["KERNEL32.DLL", "ADVAPI32.DLL"]

// you can add more libraries here, but hooking libc6 will probably break the script.
// Maybe because it is shared by all processes
var default_linux_lib = [];


var default_android_lib = []

"""

platform_windows = """
var default_libs = default_windows_lib;

"""

platform_linux = """
var default_libs = default_linux_lib;

"""

platform_android = """
var default_libs = default_android_lib;

"""

common = """
function lib_includes(libname, liblist) {
  for (var i = 0; i < liblist.length; i++) {
    if (libname == liblist[i]) {
      return true
    }
  }
  return false
}
"""

process_module = """
setTimeout(function() {
  Process.enumerateModules({
    onMatch: function(module) {
      console.log("Found " + module.name + " at " + module.base);
      if (module.name == module_name) {
        base_ea = module.base
      }
      if (lib_includes(module.name, default_libs)) {
        let exports = module.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
          let ea = Module.getExportByName(module.name, exports[i].name)
          if (exports[i].name[0] == "_") {
            continue
          }
          try {
            Interceptor.attach(ea, {
              onEnter: function(args) {
                let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                  .map(DebugSymbol.fromAddress)
                let name = backtrace[0]["name"]
                events[name] = -1;
                if (libeventscount[name] == 10) {
                  Interceptor.detach(ea)
                }
              }
            });
          } catch (e) {
            console.log("Error: " + e);
          }
        }
      }
    },
    onComplete: function() {
      register();
    }
  });
}, 500);
"""


hook = """
function addHook(ea, name) {
  try {
    var ea = new NativePointer(base_ea - ida_base + ea);
    console.log("Hooking " + name + " at " + ea);
    Interceptor.attach(ea, {
      onEnter: function(args) {
        events[name] += 1;
        if (events[name] < dump_string_times) {
          for (var i = 0; i < register_args.length; i++) {
            if (this.context[register_args[i]] != null) {
              try {
                var str = this.context[register_args[i]].readPointer()
                  .readUtf8String();
                if (str.length > 4) {
                  console.log("Found string inside " + name + " at " + register_args[i] + " : " + str);
                }
              } catch (error) {}
            }
          }
        }
      }
    });
  } catch (error) {
    console.log("Error: " + error);
  }
}
"""


timeout = """
setTimeout(function() {
  console.log("Stopped frida");
  // enumerate events with call > 0
  var _events = {};
  for (var key in events) {
    if (events[key] != 0 && events[key] != null) {
      _events[key] = events[key];
    }
  }
  events = _events;
  // create a json 
  for (var key in events) {
    events[key] = {
      "count": events[key]
    };
  }
  var json = JSON.stringify(events);
  console.log("JSON:::" + json + ":::JSON");
}, timeout);
"""

register = """
function register() {
  for (var key in funcs) {
    let ea = funcs[key];
    let name = key;
    events[name] = 0;
    addHook(ea, name);
  }
}
"""
