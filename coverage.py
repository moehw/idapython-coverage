import sys
import os
import ctypes
import ctypes.util

try:
    import idc
    import idaapi
    import idautils
except Exception as e:
    print("Need IDAPython: {}".format(e))

VERBOSE = False
LOG     = True
IS_PDB  = False
IS_FILTER_EXPORT = False

CURRENT_DIR  = os.getcwd() + "/"
FILE_NAMES   = "func_list.txt"
FILE_OFFSETS = "offset_list.txt"
FILE_MAP     = os.path.splitext(idaapi.get_root_filename())[0] + ".map"

OUTPUT_FOLDER = CURRENT_DIR

class ToFileStdOut(object):
    def __init__(self):
        self.outfile = open(OUTPUT_FOLDER + 'idaout.txt', 'w')

    def write(self, text):
        self.outfile.write(text)

    def flush(self):
        self.outfile.flush()

    def isatty(self):
        return False

    def __del__(self):
        self.outfile.close()

sys.stdout = sys.stderr = ToFileStdOut()


def get_all_functions():
    bin_functions = set()
    for func_addr in Functions():
        function_name = demangle(get_func_name(func_addr))
        bin_functions.add(func_addr)
        if VERBOSE:
            print(function_name)
    return bin_functions

def get_callable_functions(func, func_set=None):
    if func_set is None:
        func_set = set()

    func_set.add(func)

    # Iterate through all function instructions and take instructions with xrefs from
    for x in FuncItems(func):
        for xref in XrefsFrom(x, idaapi.XREF_FAR):
            if xref.iscode:
                to_func = idaapi.get_func(xref.to)
                if to_func and to_func.startEA != func:
                    if to_func.startEA in func_set:
                        continue
                    if VERBOSE:
                        print("Function: {} \t -> {}".format(demangle(get_func_name(to_func.startEA)), hex(to_func.startEA)))
                    func_set_child = get_callable_functions(to_func.startEA, func_set)
                    func_set = func_set.union(func_set_child)
                # print(demangle(get_func_name(to_func.startEA)))
            # else:
            #     ref = xref.to

    return func_set

def get_func_from_map(map_file):
    func_list = set()

    pattern_base_offset = ' Preferred load address is '
    pattern_rva_base = 'Rva+Base'

    idx = 0

    for line in map_file:
        pos = line.find(pattern_base_offset)
        if pos != -1:
            base_offset = int(line[pos + len(pattern_base_offset):], base=16)
            break
        idx = idx + 1

    idx_curr = idx

    code_segment = ""
    for i in range(idx_curr, len(map_file)):
        splited_string = map_file[i].split()
        if len(splited_string) < 3:
            continue

        if splited_string[0].startswith("000"):
            if splited_string[2].startswith(".text"):
                code_segment = splited_string[0][0:4]
                idx_curr = i
                break

    if code_segment == "":
        return set()

    for i in range(idx_curr, len(map_file)):
        pos = map_file[i].find(pattern_rva_base)
        if pos != -1:
            idx = i
            break

    if idx_curr == idx:
        return set()
    
    idx = idx + 2
    idx_curr = idx

    entry_point = 0
    section_base = 0
    func_ptrs = dict()
    for i in range(idx_curr, len(map_file)):
        try:
            parts = map_file[i].split()

            if len(parts) < 3:
                continue
            
            # code segment
            if parts[0].startswith("entry"):
                if section_base == 0:
                    print("[WARN] No section base to calculate entry point")
                entry_point = int(parts[3][5:], 16) + section_base
                demangled = demangle(get_func_name(entry_point))
                if demangled is not None:
                    func_list.add(entry_point)
                    func_ptrs[demangled] = entry_point
                continue

            if parts[0].startswith(code_segment):
                if section_base == 0:
                    section_base = int(parts[2], base=16) - int(parts[0][5:], base=16)
                demangled = demangle(parts[1])
                if demangled is not None:
                    func_list.add(int(parts[2], base=16))
                    func_ptrs[demangled] = int(parts[2], base=16)
        except Exception as e:
            print("[EXCEPT] Error while parse function from map: {}".format(e))

    return func_list, func_ptrs, entry_point

def demangle(name):
    return demangle_ida(name)

def demangle_ida(name):
    mask = idc.GetLongPrm(idc.INF_SHORT_DN)
    demangled = idaapi.demangle_name(name, mask)
    if demangled is None:
        return name
    return demangled

MAX_DEMANGLED_LEN = 2**12
dbghelp_path = ctypes.util.find_library("dbghelp")
dbghelp = ctypes.windll.LoadLibrary(dbghelp_path)

def demangle_system(name):
    name = name.lstrip(".")
    mangled = ctypes.c_char_p(name.encode("utf8"))
    demangled = ctypes.create_string_buffer("\x00" * MAX_DEMANGLED_LEN)
    demangled_len = ctypes.c_int(MAX_DEMANGLED_LEN)
    ret = dbghelp.UnDecorateSymbolName(mangled, demangled, demangled_len, 0)
    if ret != 0:
        return demangled.value
    else:
        error_code = ctypes.windll.kernel32.GetLastError()
        print("[ERROR] UnDecorateSymbolName failed ({})".format(error_code))

    return name

class Import():

    def imports_names(self, ea, name, ord):
        self.items.append((ea, '' if not name else name, ord))
        # True -> Continue enumeration
        return True

    def get_imports(self):
        tree = {}
        nimps = idaapi.get_import_module_qty()

        for i in xrange(0, nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
            # Create a list for imported names
            self.items = []

            # Enum imported entries in this module
            idaapi.enum_import_names(i, self.imports_names)

            if name not in tree:
                tree[name] = []
            tree[name].extend(self.items)

        return tree

    def print_imports(self):
        for dll_name, imp_entries in self.get_imports().items():
            print("DLL: " + str(dll_name))
            for imp_ea, imp_name, imp_ord in imp_entries:
                print("%s [0x%08x]" % (imp_name, imp_ea))

class Export():
    
    def get_exports(self):
        return list(idautils.Entries())

    def print_exports(self):
        for exp_i, exp_ord, exp_ea, exp_name in self.get_exports():
            # item.setText(0, "%s [#%d] [0x%08x]" % (exp_name, exp_ord, exp_ea))
            print(0, "%s [#%d] [0x%08x]" % (exp_name, exp_ord, exp_ea))


def get_export_tree():
    exp_func_sets = set()
    exports = Export()
    for exp_i, exp_ord, exp_ea, exp_name in exports.get_exports():
        exp_func_sets = get_callable_functions(exp_ea, exp_func_sets)
    return exp_func_sets

def get_map_tree(map_file):
    func_list = set()
    func_ptrs = dict()
    func_list, func_ptrs, entry_point = get_func_from_map(map_file)
    return func_list, func_ptrs, entry_point


def get_funcs_by_name_from_binary(name, bin_functions=None):
    func_addrs = set()
    for func_addr in bin_functions if bin_functions is not None else Functions():
        func_name = get_func_name(func_addr)
        # Check if the function name == "name"
        if (name in func_name) or (name in demangle(func_name)):
            func_addrs.add(func_addr)
    return func_addrs

def get_funcs_by_name_from_map(func_name, map_dict=None):
    map_addrs = set()
    if map_dict is not None and len(map_dict) > 0:
        for map_func, map_ptr in map_dict.items():
            if func_name in map_func:
                map_addrs.add(map_ptr)
    return map_addrs

def get_funcs_by_names(func_names, bin_functions=None, map_dict=None):
    func_addrs = set()
    map_addrs = set()
    bin_addrs = set()

    for func_name in func_names:
        map_addrs = get_funcs_by_name_from_map(func_name, map_dict)
        bin_addrs = get_funcs_by_name_from_binary(func_name, bin_functions)

        bin_addrs = bin_addrs.union(map_addrs)
        func_addrs = func_addrs.union(bin_addrs)

        if len(bin_addrs) == 0:
            print("[WARN] There is no function with name: {}".format(func_name))
            continue
        if VERBOSE:
            print("Function ({}) addresses: {}".format(func_name, bin_addrs))
        
    return func_addrs

def get_funcs_by_offsets(func_offsets):
    func_addrs = set()
    for func_offset in func_offsets:
        func = idaapi.get_func(func_offset).startEA
        if func:
            if VERBOSE:
                print("Function: {} \t -> {}".format(demangle(get_func_name(func)), hex(func_offset)))
            func_addrs.add(func)
        else:
            print("[WARN] No function on offset {}".format(hex(func_offset)))
    return func_addrs

def log_offsets_set(func_set, file_name):
    log_func = open(file_name, "w")
    for func in func_set:
        func_name = demangle(get_func_name(func))
        log_func.write(func_name + "\t -> " + hex(func) + "\n")
    log_func.close()

def main():
    print("*** Coverage ***")

    if os.path.exists(CURRENT_DIR + FILE_OFFSETS):
        function_file = CURRENT_DIR + FILE_OFFSETS
        is_names = False
    elif os.path.exists(CURRENT_DIR + FILE_NAMES):
        function_file = CURRENT_DIR + FILE_NAMES
        is_names = True
    else:
        print("[ERROR] There is no file with functions to analyze")
        return

    with open(function_file) as f:
        func_list_to_analyze = [x.rstrip("\n") for x in f.readlines()] if is_names else \
                               [int(x, 16) for x in f.readlines()]

    print("Looking for function:")
    for func in func_list_to_analyze:
        if isinstance(func, int):
            print("-> " + hex(func))
        else:
            print("-> " + func)

    exp_func_sets = set()
    if IS_FILTER_EXPORT:
        if VERBOSE:
            print("\n>> Exports:")
        exp_func_sets = get_export_tree()
        if VERBOSE:
            print("Export tree count: {}".format(len(exp_func_sets)))
    
    map_func_list = set()
    map_dict = dict()
    if os.path.exists(CURRENT_DIR + FILE_MAP):
        if VERBOSE:
            print("\n>> Parse map file:")
        with open(CURRENT_DIR + FILE_MAP) as f:
            map_file = f.readlines()
        map_func_list, map_dict, entry_point = get_map_tree(map_file)
        if VERBOSE:
            print("Map functions count: {}".format(len(map_func_list)))


    if VERBOSE:
        print("\n>> Binary functions:")
    bin_functions = get_all_functions()
    if VERBOSE:
        print("Binary functions count: {}".format(len(bin_functions)))
    

    if VERBOSE:
        print("\n>> Processing intersection...")
    if len(map_func_list) > 0:
        bin_functions = bin_functions.intersection(map_func_list)
    if len(exp_func_sets) > 0:
        bin_functions = bin_functions.intersection(exp_func_sets)
    print("\nAll functions count: {}".format(len(bin_functions)))


    func_sets = set()
    if is_names:
        func_addrs = get_funcs_by_names(func_list_to_analyze, bin_functions, map_dict)
        for func_addr in func_addrs:
            func_sets = get_callable_functions(func_addr, func_sets)
    else:
        func_addrs = get_funcs_by_offsets(func_list_to_analyze)
        for func_addr in func_addrs:
            func_sets = get_callable_functions(func_addr, func_sets)

    func_sets = func_sets.intersection(bin_functions)

    print("\nCalled functions: {}".format(len(func_sets)))

    procent = (len(bin_functions) * 1.0) / 100
    print("\nCalled Functions to All Functions (percentage):\n> {}%".format(len(func_sets) / procent))

    if LOG:
        log_offsets_set(func_sets, OUTPUT_FOLDER + "func_functions.txt")
        func_to_do = bin_functions.difference(func_sets)
        log_offsets_set(func_to_do, OUTPUT_FOLDER + "func_to_do.txt")

if IS_PDB:
    try:
        symbol_path = os.environ["_NT_SYMBOL_PATH"]
        os.environ["_NT_SYMBOL_PATH"] = symbol_path + ";" + CURRENT_DIR
        idaapi.load_and_run_plugin("pdb", 3)
    except Exception as e:
        print("[WARN] Error while loading .pdb: {}".format(e))
    
try:
    idc.auto_wait()
    main()
except Exception as e:
    print("[EXCEPT] {}".format(e))

idc.Exit(0)
