# interpreter: python2.7.15
# python2 non-native dependencies:
# - tabulate: used to pretty-print vulnerabilities
# - collections: used to know that we go through the dictionary on the correct order

import sys
import os
import json
import re
from tabulate import tabulate
from collections import OrderedDict

# file output list of json
vuln_list = []

stdin_tracker = dict()          # keys are of format 'rbp-hex_address'
global_arg_registers = {
        "rdi":"",
        "rsi":"",
        "rdx":"",
        "rcx":"",
        "r8":"",
        "r9":""
}

# what we know it's in there (direct memory access and '\0' tracker)
memory_tracker = dict()         # keys are of format 'rbp-hex_address'

# new dictionary to facilitate things: keys are the rbp relative addresses (now ordered for "lea" instruction)
stackvariables_dict = OrderedDict()

class Vulnerabilities:
    def __init__(self):
        # represents an overflow on 1 or more variables of the same stack frame
        self.var_overflow = "No"

        # represents an overflow on the saved &rbp of the same stack frame
        self.rbp_overflow = "No"

        # represents an overflow on the return address of that same stack frame
        self.return_overflow = "No"

        # represents an overflow of padding values (non-reserved memory)
        self.invalid_access = "No"

        # represents an overflow that leads to access below/above that stack frame aswell,
        # but it actually leads to access to another stack frame, which is therefore called
        # a "stack corruption"
        self.stack_corruption = "No"

        # one that leads to access to the init stack frame
        self.init_sf_access = "No"

        self.out_of_sf_address = 16

        # constant rbp-relative addresses
        self.rbp_overflow_range = range(0,8)
        self.return_overflow_range = range(8,16)

        # dynamic rbp-relative addresses
        self.var_overflow_range = []
        self.invalid_access_range = []
        self.stack_corruption_range = [self.out_of_sf_address]

        self.rbp_overflow_address = 0
        self.return_overflow_address = 0
        self.var_overflow_addresses = []        # var overflown addresses
        self.invalid_access_addresses = []      # invalid access addresses
        self.stack_corruption_address = 0       # stack corruption address
        

        # Vulnerabilities
        self.vulnerabilities = []

        # Vulnerabilities' Properties
        self.vuln_function = ""
        self.fnname = ""
        self.fnaddress = ""
        self.overflow_var_name = ""
        self.overflown_var_names = []

    def write_to_vuln_list(self):
        # project output order
        rbp_ret_overflow_keys = ("vulnerability", "vuln_function", "address", "fnname", "overflow_var")
        var_overflow_keys = ("vulnerability", "vuln_function", "address", "fnname", "overflow_var", "overflown_var")
        invalidaccs_scorruption_keys = ("vulnerability", "vuln_function", "address", "fnname", "overflow_var", \
            "overflown_address")
        
        # OrderedDict is used again to preserve same order as in the project outputs
        if self.invalid_access == "YES":
            for addr in self.invalid_access_addresses:
                invalidaccs_values = ("INVALIDACCS", self.vuln_function, self.fnaddress, self.fnname, \
                    self.overflow_var_name, "rbp" + hex(addr) if addr < 0 else "rbp+" + hex(addr))
                invalidaccs_dict = OrderedDict(zip(invalidaccs_scorruption_keys, invalidaccs_values))
                vuln_list.append(invalidaccs_dict)
        if self.var_overflow == "YES":
            for i, addr in enumerate(self.var_overflow_addresses):
                var_overflow_values = ("VAROVERFLOW", self.vuln_function, self.fnaddress, self.fnname, \
                    self.overflow_var_name, self.overflown_var_names[i])
                var_overflow_dict = OrderedDict(zip(var_overflow_keys, var_overflow_values))
                vuln_list.append(var_overflow_dict)
        if self.rbp_overflow == "YES":
            rbp_overflow_values = ("RBPOVERFLOW", self.vuln_function, self.fnaddress, self.fnname, self.overflow_var_name)
            rbp_overflow_dict = OrderedDict(zip(rbp_ret_overflow_keys, rbp_overflow_values))
            vuln_list.append(rbp_overflow_dict)
        if self.return_overflow == "YES":
            ret_overflow_values = ("RETOVERFLOW", self.vuln_function, self.fnaddress, self.fnname, self.overflow_var_name)
            ret_overflow_dict = OrderedDict(zip(rbp_ret_overflow_keys, ret_overflow_values))
            vuln_list.append(ret_overflow_dict)
        if self.stack_corruption == "YES":
            addr = self.stack_corruption_address
            scorruption_values = ("rbp" + hex(addr) if addr < 0 else "rbp+" + hex(addr), self.fnname, self.vuln_function, \
                 self.fnaddress, "SCORRUPTION", self.overflow_var_name)
            scorruption_values = ("SCORRUPTION", self.vuln_function, self.fnaddress, self.fnname, \
                 self.overflow_var_name, "rbp" + hex(addr) if addr < 0 else "rbp+" + hex(addr))
            scorruption_dict = OrderedDict(zip(invalidaccs_scorruption_keys, scorruption_values))
            vuln_list.append(scorruption_dict)

    def set_vuln_var_properties(self, vuln_function, fnname, fnaddress, overflow_var_name):
        self.vuln_function = vuln_function
        self.fnname = fnname
        self.fnaddress = fnaddress
        self.overflow_var_name = overflow_var_name

    def set_dynamic_ranges(self, other_vars_address_ranges, padding_address_ranges):
        self.var_overflow_range = other_vars_address_ranges
        self.invalid_access_range = [padding_address_ranges]

    def set_vulns(self, overflown_addresses, sf_list):
        for addr in self.rbp_overflow_range:
            if addr in overflown_addresses:
                self.rbp_overflow_address = addr
                self.rbp_overflow = "YES"
                break
        for addr in self.return_overflow_range:
            if addr in overflown_addresses:
                self.return_overflow_address = addr
                self.return_overflow = "YES"
                break

        for variable in self.var_overflow_range:
            if not variable:
                break
            addr = variable[0]
            if addr in overflown_addresses:
                self.var_overflow_addresses.append(addr)
                # ugly code, sorry.
                var_name = ""
                for sf in sf_list:
                    if sf.func == self.vuln_function:
                        for i, item_addr in enumerate(sf.addresses):
                            if item_addr == addr:
                                var_name = sf.item_names[i]
                self.overflown_var_names.append(var_name)                    # setting this for output file
                self.var_overflow = "YES"

        for invalid_access_range in self.invalid_access_range:
            if not invalid_access_range:
                break
            invalid_location = invalid_access_range[0]
            if invalid_location in overflown_addresses:
                self.invalid_access_addresses.append(invalid_location)
                self.invalid_access = "YES"

        if self.out_of_sf_address in overflown_addresses:
            self.stack_corruption_address = self.out_of_sf_address
            self.stack_corruption = "YES"

    # NEW-ADDITION
    def check_illegal_direct_mem_access(self, stackvariables_dict, func, op, address):
        # direct memory access
        initially_allocated_padding_address_ranges = []
        for allocated_item in stackvariables_dict.keys():
            item_addr = int(allocated_item.split("_rbp")[1],16)
            item_type = stackvariables_dict[allocated_item][1]
            item_size = stackvariables_dict[allocated_item][2]
            if stackvariables_dict[allocated_item][1]=="padding" and allocated_item.split("_rbp")[0] == func:
                initially_allocated_padding_address_ranges += range(item_addr, item_addr + item_size)

        overflown_address = ""
        for mem_id in memory_tracker.keys():
            if int(mem_id.strip("rbp"),16) in initially_allocated_padding_address_ranges:
                overflown_address = int(mem_id.strip("rbp"),16)
                break

        if overflown_address:
            # appending value to vuln_list
            self.invalid_access = "YES"
            self.invalid_access_addresses.append(overflown_address)
            special_invalidaccs_keys = ("vulnerability", "vuln_function", "address", "op", "overflown_address")
            for addr in self.invalid_access_addresses:
                invalidaccs_values = ("INVALIDACCS", func, address, op, "rbp" + hex(overflown_address))
                invalidaccs_dict = OrderedDict(zip(special_invalidaccs_keys, invalidaccs_values))
                vuln_list.append(invalidaccs_dict)
            return True
        return False


    def __repr__(self):
        header = [mark_dangerous("Variable overflow"),mark_dangerous("RBP overflow"),mark_dangerous("Return address overflow")\
        ,mark_dangerous("Invalid Access"),mark_dangerous("Stack Corruption")]
        vulns = [self.var_overflow,self.rbp_overflow,self.return_overflow,self.invalid_access,self.stack_corruption]

        var_overflow_addresses_len = len(self.var_overflow_addresses)
        var_overflow_addresses_repr = ""
        for i, addr in enumerate(self.var_overflow_addresses):
            var_overflow_addresses_repr += hex(addr)
            if i != var_overflow_addresses_len-1:
                var_overflow_addresses_repr += ", "

        invalid_access_addresses_len = len(self.invalid_access_addresses)
        invalid_access_address_repr = ""
        for i, addr in enumerate(self.invalid_access_addresses):
            invalid_access_address_repr += hex(addr)
            if i != invalid_access_addresses_len-1:
                invalid_access_address_repr += ", "

        addresses = [var_overflow_addresses_repr,hex(self.rbp_overflow_address),hex(self.return_overflow_address),\
        invalid_access_address_repr,hex(self.stack_corruption_address)]
        vulns_repr = "\n|" + "-"*106 + "|" + "\n" + tabulate([vulns, addresses], headers=header, tablefmt='orgtbl') + "\n"
        return vulns_repr

# this class represents a Stack Frame but with the return address embbeded, which is not
# natively part of the stack frame. This could be called "StackFramePlus".
class StackFrame:
    def __init__(self, func):
        self.func = func
        self.items = []
        self.sizes = []
        self.addresses = []
        self.address_ranges = []
        self.item_names = []
        self.item_types = []
        self.varsize = 0
        self.totalsize = 0
        self.paddingsize = 0
        self.global_addresses = []

    def isEmpty(self):
        return self.items == []
    
    def push(self, item, item_size, item_address, item_name, item_type):
        # don't repeat stack elements obtained from LEAs
        if item not in self.items:
            self.items.append(item)
            self.sizes.append(item_size)
            self.addresses.append(item_address)
            # calculate address range for item
            address_range = range(item_address, item_address+item_size)
            self.address_ranges.append(address_range)
            # item name and type is also relevant
            self.item_names.append(item_name)
            self.item_types.append(item_type)

    def pop(self):
        return self.items.pop()

    def peek(self):
        return self.items[len(self.items)-1]

    def varsize(self):
        return self.varsize

    def totalsize(self):
        return self.totalsize

    def __repr__(self):
        stack_frame_repr = "###### " + self.func + "'s StackFrame ######\n"
        beautify_str = "+------------------------------+\n"
        stack_frame_width = len(beautify_str) - 2
        stack_frame_repr += "StackFrame's total size: " + str(self.totalsize) + " bytes\n"
        stack_frame_repr += "StackFrame's variable-allocated size: " + str(self.varsize) + " bytes\n"
        stack_frame_repr += "StackFrame's padding size: " + str(self.paddingsize) + " bytes\n"

        stack_frame_repr += beautify_str
        items_len = len(self.items)
        sorting_func = lambda x: self.addresses[x]
        for i in sorted(range(items_len-1, -1, -1), key=sorting_func):
            dynamic_str = "| " + self.items[i]
            stack_frame_repr += dynamic_str.ljust(stack_frame_width) + "| <-- size: " + str(self.sizes[i]) + \
                                ", address: " + str(self.addresses[i]) + ", name: " + str(self.item_names[i]) + \
                                ", type: " + str(self.item_types[i]) + "\n"
            stack_frame_repr += beautify_str
        return stack_frame_repr

def check_overflow(var, buffer_address, maximum_size, func, fnname, fnaddress, sf_list, stack_items_stats=False):
    dangerous_buffer_address = ""
    # if this var's address corresponds to the dangerous buffer argument of a function
    if var["address"] == buffer_address:
        if var["type"] != "buffer":
            raise ValueError("Variable type must be buffer.")
        vulns = Vulnerabilities()
        # if a dangerous buffer was found...
        if var["bytes"] < maximum_size:
            overflown_addresses = []
            rbp_ret_size = 16
            maximum_written_sf_size = rbp_ret_size + int(var["address"].split("rbp-")[1],16)

            last_overflown_address = 0
            if maximum_size == sys.maxint:
                maximum_size = maximum_written_sf_size + 1
                last_overflown_address = 16

            for i, sf in enumerate(sf_list):
                for j,sf_item in enumerate(sf.items):
                    # if the current item corresponds to the dangerous buffer address
                    if sf_item.strip("[]") == buffer_address:
                        # parse the initial rbp-relative address of the buffer and transform it into a base-16 int
                        compiled_pattern = re.compile("rbp-")
                        dangerous_buffer_address = compiled_pattern.split(buffer_address)[1]
                        dangerous_buffer_address = - int(dangerous_buffer_address, 16)
                        first_overflown_address = dangerous_buffer_address + var["bytes"]
                        # if one of these conditions happen
                        if last_overflown_address != 16 or (dangerous_buffer_address - maximum_size == 16):
                            last_overflown_address = dangerous_buffer_address + (maximum_size - 1)
                            #last_overflown_address += 1 #if maximum_size > maximum_written_sf_size else 0

                        print mark_dangerous("Overflow in adversarial controlled var \"%s\" at address %s in %s")  %(var["name"], var["address"], sf.func)

                        # overflown addresses list ordered top-down in the stack
                        overflown_addresses = range(first_overflown_address,last_overflown_address+1)
                        print overflown_addresses
                        print mark_dangerous("Overflown addresses: %s to %s") %(overflown_addresses[0], overflown_addresses[-1])
                        overflown_bytes = len(overflown_addresses)
                        print mark_dangerous("Overflow size: %d bytes") % (overflown_bytes)

                        vuln_func = sf.func
                        overflow_var_name = var["name"]

            other_vars_address_ranges = []
            padding_address_ranges = []
            sf_list_len = len(sf_list)

            for i, sf in enumerate(sf_list):
                items_len = len(sf.items)
                for j in range(items_len):
                    # if it's not the dangerous buffer and its address is bigger (hence, it's lower on the stack), 
                    # and it's not RBP or the RET address, and it is not padding, and it is a variable that belongs
                    # to the stack frame of the dangerous variable then it is a var that may be overflown
                    if sf.addresses[j] > dangerous_buffer_address and sf.addresses[j] != 0 and sf.addresses[j] != 8 \
                    and sf.item_types[j]!="padding" and sf.func == vuln_func:
                        other_vars_address_ranges.append(sf.address_ranges[j])

                    # if it's padding from the vulnerable function
                    if sf.item_types[j]=="padding" and sf.func == vuln_func:
                        padding_address_ranges += sf.address_ranges[j]

                    if stack_items_stats:
                        item_name = sf.item_names[j]
                        item_address = sf.addresses[j]
                        item_address_range = sf.address_ranges[j]
                        print "%s (address: rbp%s): %s to %s" \
                               %(item_name,hex(item_address) if item_address < 0 else "+" + hex(item_address),item_address_range[0], item_address_range[-1])

            vulns.set_dynamic_ranges(other_vars_address_ranges, padding_address_ranges)
            vulns.set_vuln_var_properties(vuln_func, fnname, fnaddress, overflow_var_name)
            vulns.set_vulns(overflown_addresses, sf_list)
            print vulns
        else:
            print "No overflow derived from a function."

        # write output to file (append mode)
        vulns.write_to_vuln_list()
        

def set_null_byte(null_byte_location):
    mem_identifier = "rbp" + hex(null_byte_location)
    memory_tracker[mem_identifier] = "0x0"      # \0

def basic_limiter_specifics(buffer_address, src_address, lim, maximum_input_size):
    # fgets, strncpy, strncat
    maximum_size = maximum_input_size
    if src_address=="stdin":
        maximum_size = int(lim, 16)
    else:
        if src_address in stdin_tracker.keys():
            maximum_size = int(lim, 16)
    stdin_tracker[buffer_address] = maximum_size
    return maximum_size

def infinite_buffer_function_specifics(buffer_address, src_address, fnname, maximum_input_size):
    # strcpy, strcat, fscanf
    maximum_size = maximum_input_size
    if src_address=="stdin":
        maximum_size = sys.maxint
    else:
        if fnname=="strcpy@plt" or fnname=="__isoc99_fscanf@plt":
            if src_address in stdin_tracker.keys():
                maximum_size = stdin_tracker[src_address]   # already includes '\0'
        else:   # strcat@plt
            if buffer_address in stdin_tracker.keys():
                    maximum_size = stdin_tracker[buffer_address] - 1
            if src_address in stdin_tracker.keys():
                maximum_size += stdin_tracker[src_address] - 1
                # '\0' is put in the position after buffer, so our stack writing size gets bigger
                maximum_size += 1
    stdin_tracker[buffer_address] = maximum_size
    return maximum_size

def format_string_srcbuffers_function_specifics(subfunc, buffer_address, fnname, maximum_input_size):
    # sprintf, snprintf
    if fnname=="sprintf@plt":
        format_string = subfunc[3][1]
    else:
        buffer_max_size = int(subfunc[3][1],16)
        format_string = subfunc[3][2]
    format_string_count = format_string.count("%s")
    src_addresses = []
    for i in range(format_string_count):
        if fnname=="sprintf@plt":
            src_addresses.append(subfunc[3][i+2])
        else:
            src_addresses.append(subfunc[3][i+3])
    src_max_size = 0
    for addr in src_addresses:
        src_max_size += stdin_tracker[addr]

    if fnname=="sprintf@plt":
        maximum_input_size = src_max_size
        stdin_tracker[buffer_address] = maximum_input_size
    else:
        maximum_input_size = min(maximum_input_size, buffer_max_size)     # buffer_max_size limits the size of our input
        stdin_tracker[buffer_address] = maximum_input_size
    return maximum_input_size

def determine_specifics(func, subfunc, caller_identifier):
    func_identifier = func + "_"
    buffer_address = ""
    # initial maximum input size is the integer max value
    maximum_input_size = sys.maxint
    fnname = subfunc[0]
    print "[!] %s function call" %(fnname)
    arg_str = "Arguments: "
    # print stdin_tracker
    print memory_tracker
    subfunc_len = len(subfunc[3])
    for i in range(subfunc_len):
        arg_str += subfunc[3][i] if subfunc[3][i]!="stdin" else mark_dangerous(subfunc[3][i])
        if i!=subfunc_len-1:
            arg_str += ", "
    print arg_str

    if fnname=="gets@plt":
        buffer_address = subfunc[3][0]
        stdin_tracker[buffer_address] = maximum_input_size
        # maximum_input_size is infinite in gets...
    # strcpy and strcat are special because they read until the null-terminator '\0' which,
    # if overwritten by non-vulnerable functions, can cause a vulnerability in these ones
    elif fnname=="strcpy@plt":
        buffer_address = subfunc[3][0]
        src_address = subfunc[3][1]
        maximum_input_size = infinite_buffer_function_specifics(buffer_address, src_address, fnname, maximum_input_size)
        # https://linux.die.net/man/3/strcpy
        null_byte_location = int(buffer_address.split("rbp")[1],16) + maximum_input_size - 1
        set_null_byte(null_byte_location)

        if "PTR" in src_address:
            src_address = src_address.split("PTR")[1].strip("[ ]")
            stackid = func_identifier + src_address
            pointed_stackid = stackvariables_dict[stackid][0]
            # tests 24/25/26/27 incompatible with test 23
            if stackvariables_dict[stackid][1] == "pointer-to-buffer":    # additional check
                max_pointed_buffer_size = stdin_tracker[pointed_stackid.strip(caller_identifier)]
                print max_pointed_buffer_size   # it needs to exist, that's not even an option
                print "This is a pointer, it points to address %s"  %(pointed_stackid)
                #maximum_input_size = 8     # test 23
                maximum_input_size = max_pointed_buffer_size    # tests 24/25/26/27
            else:
                raise ValueError("Something went wrong, this is strcpy and this is not \
                    a buffer you're pointing to...")

        null_byte_lookup_range = range(int(src_address.split("rbp")[1],16), int(buffer_address.split("rbp")[1],16))
        for i, addr in enumerate(null_byte_lookup_range):
            if "rbp" + hex(addr) in memory_tracker and memory_tracker["rbp" + hex(addr)]=="0x0":    # NEW-ADDITION: 2nd condition
                # the maximum input size here is limited by the null byte every time, even if the previous
                # stdin tracked limit is higher, because strcpy stops copying when it encounters a null byte
                maximum_input_size = i + 1
                break                       # NEW-ADDITION: this was a bug, we weren't breaking the cycle after finding a '\0'

    elif fnname=="strcat@plt":
        buffer_address = subfunc[3][0]
        src_address = subfunc[3][1]
        maximum_input_size = infinite_buffer_function_specifics(buffer_address, src_address, fnname, maximum_input_size)
        # https://en.cppreference.com/w/c/string/byte/strcat
        null_byte_location = int(buffer_address.split("rbp")[1],16) + maximum_input_size - 1
        set_null_byte(null_byte_location)

    elif fnname=="fgets@plt":
        buffer_address = subfunc[3][0]
        lim = subfunc[3][1]
        src_address = subfunc[3][2]
        maximum_input_size = basic_limiter_specifics(buffer_address, src_address, lim, maximum_input_size)
        # https://linux.die.net/man/3/fgets
        null_byte_location = int(buffer_address.split("rbp")[1],16) + maximum_input_size - 1    # source do erro do teste 22, mas
                                                                                                # o que nos fazemos esta correto
                                                                                                # segundo a documentacao do fgets
        set_null_byte(null_byte_location)

    elif fnname=="strncpy@plt":
        buffer_address = subfunc[3][0]
        src_address = subfunc[3][1]
        lim = subfunc[3][2]
        maximum_input_size = basic_limiter_specifics(buffer_address, src_address, lim, maximum_input_size)
        # https://linux.die.net/man/3/strcpy    (read warning about strncpy)

        # code for putting '\0' in a new address according to the previous existence of '\0' in the source buffer's end
        src_address_end = int(src_address.split("rbp")[1],16) + maximum_input_size - 1
        src_address_end = "rbp" + hex(src_address_end)
        if src_address_end in memory_tracker.keys() and memory_tracker[src_address_end]=="0x0":
            max_null_byte_location = int(buffer_address.split("rbp")[1],16) + int(lim,16) - 1
            set_null_byte(max_null_byte_location)

        # code for removing null-terminators from memory_tracker in case they are overflown
        if src_address in stdin_tracker.keys():
            null_byte_location = int(lim,16) + int(src_address.split("rbp")[1],16) - 1
            null_byte_location = "rbp" + hex(null_byte_location)
            if null_byte_location in memory_tracker.keys() and memory_tracker[null_byte_location] == "0x0":
                # '\0' was overflown
                # remove '\0' entry from memory_tracker
                memory_tracker.pop(null_byte_location, None)

    elif fnname=="strncat@plt":
        buffer_address = subfunc[3][0]
        src_address = subfunc[3][1]
        lim = subfunc[3][2]
        maximum_input_size = basic_limiter_specifics(buffer_address, src_address, lim, maximum_input_size)
        # https://linux.die.net/man/3/strncat
        null_byte_location = int(buffer_address.split("rbp")[1],16) + maximum_input_size - 1
        set_null_byte(null_byte_location)

    elif fnname=="__isoc99_scanf@plt":
        format_string = subfunc[3][0]
        buffer_address = subfunc[3][1]
        stdin_tracker[buffer_address] = maximum_input_size
        # maximum_input_size is infinite in scanf...

    elif fnname=="__isoc99_fscanf@plt":
        src_address = subfunc[3][0]
        format_string = subfunc[3][1]
        buffer_address = subfunc[3][2]
        maximum_input_size = infinite_buffer_function_specifics(buffer_address, src_address, fnname, maximum_input_size)
    
    # TODO??? format_string: if 2 %s in this case? it messes with dst buffers, it's weird

    elif fnname=="sprintf@plt" or fnname=="snprintf@plt":
        buffer_address = subfunc[3][0]
        maximum_input_size = format_string_srcbuffers_function_specifics(subfunc, buffer_address, fnname, maximum_input_size)
        print maximum_input_size
        # https://www.tutorialspoint.com/c_standard_library/c_function_sprintf.htm
        # https://www.geeksforgeeks.org/snprintf-c-library/

    elif fnname=="read@plt":
        # first argument (file descriptor) isn't present in our list 'subfunc', but no need for it.
        buffer_address = subfunc[3][0]
        buffer_max_size = int(subfunc[3][1],16)
        src_address = "unknown but controlled"               # assume it's controlled by adversary
        src_max_size = sys.maxint
        maximum_input_size = infinite_buffer_function_specifics(buffer_address, src_address, fnname, maximum_input_size)
        maximum_input_size = min(src_max_size, buffer_max_size)     # buffer_max_size limits the size of our input
        print maximum_input_size
        # https://linux.die.net/man/3/read

    return buffer_address, maximum_input_size

def functions(subfuncs_called, sf_list):
    out_file_dir = "outputs"
    if not os.path.exists(out_file_dir):
        os.mkdir(out_file_dir)
    out_file_name = os.path.basename(sys.argv[1]).replace("json","output.json")
    out_file_path = out_file_dir + os.sep + out_file_name
    if os.path.exists(out_file_path):
        os.remove(out_file_path)
    for func in subfuncs_called:
        variables = program_dict[func]["variables"]
        print "Checking __%s__ for overflows..." %(func)
        caller_identifier = find_caller(subfuncs_called, func)
        for subfunc in subfuncs_called[func]:
            buffer_address, maximum_input_size = determine_specifics(func, subfunc, caller_identifier)
            fnname = subfunc[0].replace("@plt","")
            fnaddress = subfunc[1]
            for var in variables:
                check_overflow(var, buffer_address, maximum_input_size, func, fnname, \
                    fnaddress, sf_list)

    # note that the outputs of professor don't follow a correct scheme for the order in which
    # we put INVALID ACCESS and VAR OVERFLOW vulnerabilities. Apparently, it is not sorted by
    # any attribute, so we can't know how to sort it.
    out_str = json.dumps(vuln_list, indent=4, separators=(',', ': '))

    f = open(out_file_path, "a")
    f.write(out_str)
    f.close()
    print "Changes written to %s"  %(f.name)
            

def mark_dangerous(string):
    dangerous_string = '\033[91m' + string + '\033[0m'
    return dangerous_string

def approximate(reg_name):
    if reg_name in ("eax","ebx","ecx","edx","edi","esi","ebp","esp","eip"):
        # approximation: assume when compiler uses only half the register, that the other half is all 0's
        reg_name = "r" + reg_name[1:]
    return reg_name

def twos_comp(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val                         # return positive value as is

def f7_uniqifier(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]

def find_caller(subfuncs_called, func):
    caller_identifier = ""
    for caller in subfuncs_called:
        for subfunc in subfuncs_called[caller]:
            if caller_identifier:
                break
            if subfunc[0]==func:
                caller_identifier = caller + "_"
                caller_found = True
        if caller_identifier:
                break
    return caller_identifier
def parse(variables_stats=False, stack_stats=True, extra_stack_stats=False, function_stats=False):
    subfuncs_called = OrderedDict()
    sf_list = [[]]*len(program_dict)
    registers = {
        "rax":"0x0",
        "rbx":"0x0",
        "rcx":"0x0",
        "rdx":"0x0",
        "rsi":"0x0",
        "rdi":"0x0",
        "r8":"0x0",
        "r9":"0x0",
        "r10":"0x0",
        "r11":"0x0",
        "r12":"0x0",
        "r13":"0x0",
        "r14":"0x0",
        "r15":"0x0",
        "rbp":"0x0",
        "rsp":"0x0",
        "rip":"0x0",
        "ZF":"0x0"
    }
    arg_registers = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
    all_registers = registers.keys()

    for i, func in enumerate(program_dict):
        # we define a new "Stack" object for each function because, in reality, this object corresponds to
        # a "stack frame". What happens is that it is impossible to have an overflow that affects the whole stack
        # without affecting the current stack frame because it will always mess with the saved RBP or the return address
        # of the current stack frame.
        sf = StackFrame(func)

        caller_identifier = find_caller(subfuncs_called, func)

        func_identifier = func + "_"
        delayed_pushes = []
        subfuncs_called[func] = []
        instructions = program_dict[func]["instructions"]
        ninstructions = program_dict[func]["Ninstructions"]
        variables = program_dict[func]["variables"]
        nvariables = len(variables)
        
        if variables_stats:
            print "###### %s ######" % (func)
            print "Number of instructions: %d" % (ninstructions)
            print "Number of variables: %d" % (nvariables)
            print "Variables:"
            for var in variables:
                print "%s, %s, %d, %s" % (var["name"],var["type"],var["bytes"],var["address"])

        for var in variables:
            stackvariables_dict[func_identifier + var["address"]] = [var["name"],var["type"],var["bytes"]]

        vulns = Vulnerabilities()
        for j, instr in enumerate(instructions):
            if instr["op"]=="push":
                # in case we are pushing rbp to the stack
                if instr["args"]["value"]=="rbp":
                    # if the function is main, then we don't know what return address it contains
                    rbp_size = 8
                    ret_size = 8
                    rbp_address = 0x0
                    ret_address = 0x8
                    if func=="main":
                        sf.push("ret_address main", ret_size, ret_address, "main ret address", "ret")
                    else:
                        for subfunc in subfuncs_called[subfuncs_called.keys()[i-1]]:
                            # if there's a subfunction from a caller who called the current function,
                            # then the ret address is the one that we stored, the one that is after the call opcode
                            if subfunc[0]==func:
                                sf.push(subfunc[2], ret_size, ret_address, func + " ret address", "ret")
                    sf.push(instr["args"]["value"] + " " + func, rbp_size, rbp_address, func + " saved rbp", "rbp")
                # else just push the value to the stack because it is a variable that doesn't require a reference
                else:
                    var_size = "unknown, this hasn't happened in any test input..."
                    var_address = "unknown, this hasn't happened in any test input..."
                    sf.push(instr["args"]["value"], var_size, var_address, "unknown name", "unknown type")

            elif instr["op"]=="mov":
                instr["args"]["dest"] = approximate(instr["args"]["dest"])
                # if the destination is defined by RBP and a subtraction, then this
                # is a local variable of the function that must be referenced by
                # address and, as so, we push it to the stack
                if instr["args"]["dest"].find("[rbp-0x")!=-1:
                    stack_dest = func_identifier + instr["args"]["dest"].split("PTR")[1].strip("[ ]")
                    pointed_value = ""
                    # pushing must be delayed if we're moving a function argument to the stack because, if not,
                    # the stack won't have the items pushed in the correct order
                    delay = instr["args"]["value"] in arg_registers

                    # try/except because if there's a KeyError exception, then this means that
                    # this stack item hasn't yet been instantiated. This could very possibly mean
                    # that it is a function argument
                    try:
                        var_size = stackvariables_dict[stack_dest][2]
                    except KeyError, e:
                        # it should be in argument registers because it is most likely a function argument,
                        # but we are going to consider that it could be any known register
                        if instr["args"]["value"] in all_registers:
                            var_size = 8    # register address size
                        elif "BYTE PTR" in instr["args"]["dest"]:
                            # memory_tracker HERE: direct memory access
                            mem_identifier = stack_dest.strip(func_identifier)  # the finalized correct way would be to keep func_identifier and 
                                                                                # calculate later, but this seems good enough right now.
                                                                                # NEW-ADDITION: this was a bug, we weren't stripping the function identifier
                            memory_tracker[mem_identifier] = instr["args"]["value"]
                            # NEW-ADDITION: direct memory access check
                            print "Checking illegal memory access..."
                            op_invalidaccs = vulns.check_illegal_direct_mem_access(stackvariables_dict, func, instr["op"], instr["address"])
                            if op_invalidaccs:
                                print vulns
                            continue    # continue to next instruction
                        else:
                            raise ValueError("I didn't expect '%s' to not be a register or %s to not be a memory pointer."\
                             %(instr["args"]["value"], instr["args"]["dest"]))
                        pointed_value = caller_identifier + global_arg_registers[instr["args"]["value"]]
                        pointed_value_name = stackvariables_dict[pointed_value][0]
                        pointed_value_type = stackvariables_dict[pointed_value][1]
                        stackvariables_dict[stack_dest] = [pointed_value, "pointer-to-" + pointed_value_type, var_size]
                        var_address = int(stack_dest.strip(func_identifier +"rbp"),16)
                        if delay:
                            delayed_pushes.append([instr["args"]["value"]+" *["+pointed_value+"]", var_size, var_address, "&"+pointed_value_name, stackvariables_dict[stack_dest][1]])
                        else:
                            sf.push(instr["args"]["value"]+" *["+pointed_value+"]", var_size, var_address, "&"+pointed_value_name, stackvariables_dict[stack_dest][1])
                            
                    # true if the try was successful
                    if not pointed_value:
                        var_address = int(stack_dest.strip(func_identifier +"rbp"),16)
                        if delay:
                            delayed_pushes.append([instr["args"]["value"], var_size, var_address, stackvariables_dict[stack_dest][0], stackvariables_dict[stack_dest][1]])
                        else:
                            sf.push(instr["args"]["value"], var_size, var_address, stackvariables_dict[stack_dest][0], stackvariables_dict[stack_dest][1])
                            
                    # determine if there's padding and, if there is, push the variable individual padding to the stack 
                    if (var_size%16)==0:
                        pass
                    else:
                        var_padding_size = 16 - var_size
                        var_padding = "\"" + stackvariables_dict[stack_dest][0] + "\"" + " item-padding"
                        var_padding_address = var_address - var_padding_size
                        stack_dest = func_identifier + "rbp" + str(hex(var_padding_address))
                        stackvariables_dict[stack_dest] = [var_padding, "padding", var_padding_size]
                        if delay:
                            delayed_pushes.append([var_padding, var_padding_size, var_padding_address, var_padding, stackvariables_dict[stack_dest][1]])
                        else:
                            sf.push(var_padding, var_padding_size, var_padding_address, var_padding, stackvariables_dict[stack_dest][1])
                            
                # this is due to the fact that we clean up registers after a call operation, but we don't
                # clean the global_arg_registers structure... (this could be improved)
                elif instr["args"]["value"] in arg_registers:
                    registers[instr["args"]["dest"]] = global_arg_registers[instr["args"]["value"]]
                    registers[instr["args"]["dest"]] = registers[instr["args"]["value"]]
                # else if the value is a register (that isn't an arg register), then we put its value in the register
                elif instr["args"]["value"] in all_registers:
                    registers[instr["args"]["dest"]] = registers[instr["args"]["value"]]
                # else we just put the value into the register (a part a special case, i.e., stdin)
                else:
                    # if this is the stdin value, we put 'stdin' directly in the register
                    special_var_name = "stdin" if ("obs" in instr["args"].keys() and instr["args"]["obs"].find("stdin")!=-1) \
                                        else instr["args"]["value"]
                    registers[instr["args"]["dest"]] = special_var_name

            # if the instruction is a "lea" and the value is fetched from RBP minus "something" address, then
            # that means it's being fetched from the stack
            elif instr["op"]=="lea":
                if instr["args"]["value"].find("[rbp-0x")!=-1:
                    stack_dest = func_identifier + instr["args"]["value"].strip("[]")
                    var_size = stackvariables_dict[stack_dest][2]
                    var_address = int(stack_dest.strip(func_identifier +"rbp"),16)

                    sf.push(instr["args"]["value"], var_size, var_address, stackvariables_dict[stack_dest][0], stackvariables_dict[stack_dest][1])

                    # push delayed pushes
                    for to_push in delayed_pushes:
                        sf.push(to_push[0],to_push[1],to_push[2],to_push[3], to_push[4])
                instr["args"]["dest"] = approximate(instr["args"]["dest"])

                if "obs" in instr["args"].keys() and "%s" in instr["args"]["obs"]:
                    registers[instr["args"]["dest"]] = instr["args"]["obs"]
                else:
                    registers[instr["args"]["dest"]] = instr["args"]["value"].strip("[]")

            elif instr["op"]=="call":
                arg_registers_values = [registers["rdi"],registers["rsi"],registers["rdx"],registers["rcx"],registers["r8"],registers["r9"]]

                for k, reg in enumerate(arg_registers_values):
                    # go fetch the register's content in case it's referenced
                    if reg in all_registers:
                        arg_registers_values[k] = registers[reg]
                        # if this register is already in the register values, then it belongs to the same
                        # reference and should be erased as it does not pose a new argument
                        if reg in arg_registers:
                            arg_registers_values[arg_registers.index(reg)] = "0x0"
                # update global arg_registers at this point
                for k, reg in enumerate(arg_registers):
                    global_arg_registers[reg] = arg_registers_values[k]
                    registers[reg] = arg_registers_values[k]

                # filter arguments for empty values
                arg_registers_values = filter(lambda k: "0x0" not in k, arg_registers_values)

                # filter arguments for identical references
                arg_registers_values = f7_uniqifier(arg_registers_values)

                # [subfunc_name, subfunc_call_address, ret_address, args]
                subfuncs_called[func].append([instr["args"]["fnname"].strip("<>"),instr["address"], instructions[j+1]["address"], arg_registers_values])
                # reset registers that are gonna be used for next function args
                for key in arg_registers:
                    registers[key] = "0x0"

            elif instr["op"]=="nop":
                pass

            elif instr["op"]=="sub":
                # if the instruction opcode is a "sub", is the 3rd opcode inside the function and
                # the destination register is "rsp" (stack pointer), then this is the instruction with
                # which the stack frame's size is allocated
                sub_value = twos_comp(int(instr["args"]["value"], 16), 64)
                if instr["pos"]==2 and instr["args"]["dest"]=="rsp":
                    # stack frame variable allocated sizes
                    sf.varsize = int(instr["args"]["value"], 16)
                    # stack frame total size: var allocated sizes plus rbp and return_address sizes
                    sf.totalsize = sf.varsize + 16
                registers[instr["args"]["dest"]] = hex(int(registers[instr["args"]["dest"]],16) - sub_value)
                
            elif instr["op"]=="add":
                # if the instruction opcode is a "add", is the 3rd opcode inside the function and
                # the destination register is "rsp" (stack pointer), then this is the instruction with
                # which the stack frame's size is allocated
                add_value = twos_comp(int(instr["args"]["value"], 16), 64)
                if instr["pos"]==2 and instr["args"]["dest"]=='rsp':
                    # stack frame variable allocated sizes
                    sf.varsize = abs(add_value)
                    # stack frame total size: var allocated sizes plus rbp and return_address sizes
                    sf.totalsize = sf.varsize + 16
                registers[instr["args"]["dest"]] = hex(int(registers[instr["args"]["dest"]],16) + add_value)
            elif instr["op"]=="leave":
                # if it's main ignore that init is the caller and don't touch in rsp
                if func == "main":
                    pass
                else:
                    registers["rsp"] = "[" + caller_identifier + "rbp]"
            elif instr["op"]=="ret":
                # if it's main we don't know where it goes (it goes to init, but statically we don't know what address that is)
                if func == "main":
                    pass
                else:
                    registers["rip"] = subfunc[2]
            # TOTEST more extensively
            elif instr["op"]=="cmp":
                #If value is a register.
                # <reg> <reg>
                if instr["args"]["arg0"] in registers.keys() and instr["args"]["arg1"] in registers.keys():
                    flag_res = int(registers[instr["args"]["arg0"]], 16) - int(registers[instr["args"]["arg1"]], 16)
                # <mem> <reg>
                elif instr["args"]["arg0"].find("rbp")!=-1 and instr["args"]["arg1"] in registers.keys():
                    sf_pointed_address = int(instr["args"]["arg0"].split("PTR [rbp")[1].strip("]"),16)
                    flag_res = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) - int(registers[instr["args"]["arg1"]], 16)
                # <reg> <mem>
                elif instr["args"]["arg1"].find("rbp")!=-1 and instr["args"]["arg0"] in registers.keys():
                    sf_pointed_address = int(instr["args"]["arg1"].split("PTR [rbp")[1].strip("]"),16)
                    flag_res = int(registers[instr["args"]["arg0"]], 16) - int(sf.items[sf.addresses.index(sf_pointed_address)], 16) 
                # <mem> <const>
                elif instr["args"]["arg0"].find("rbp")!=-1 and "0x" in instr["args"]["arg1"]:
                    sf_pointed_address = int(instr["args"]["arg0"].split("PTR [rbp")[1].strip("]"),16)
                    flag_res = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) - int(instr["args"]["arg1"], 16)

                # FAZER REG CONST PARA O TEST
                #If value is a hex value.
                # <reg> <const>
                elif instr["args"]["arg0"] in registers.keys() and "0x" in instr["args"]["arg1"]:
                    flag_res = int(registers[instr["args"]["arg0"]], 16) - int(instr["args"]["arg1"], 16)
                
                if flag_res == 0:
                    zero_flag = 1
                else:
                    zero_flag = 0

                registers["ZF"] = hex(zero_flag)
                print "cmp, zero_flag: " + str(zero_flag)
            
            elif instr["op"]=="test":
                #if both values are registers proceed
                # <reg> <reg>
                if instr["args"]["arg1"] in registers.keys() and instr["args"]["arg0"] in registers.keys():
                    test_result = int(registers[instr["args"]["arg0"]], 16) & int(registers[instr["args"]["arg1"]], 16)
                # <mem> <reg>
                elif instr["args"]["arg0"].find("rbp")!=-1 and instr["args"]["arg1"] in registers.keys():
                    sf_pointed_address = int(instr["args"]["arg0"].split("PTR [rbp")[1].strip("]"),16)
                    test_result = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) & int(registers[instr["args"]["arg1"]], 16)
                # <reg> <mem>
                elif instr["args"]["arg1"].find("rbp")!=-1 and instr["args"]["arg0"] in registers.keys():
                    sf_pointed_address = int(instr["args"]["arg1"].split("PTR [rbp")[1].strip("]"),16)
                    test_result = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) & int(registers[instr["args"]["arg0"]], 16)

                #caso semelhante ao anterior mas com uma constante no value    
                # <reg> <const> 
                elif "0x" in instr["args"]["arg0"] and instr["args"]["arg1"] in registers.keys():
                    test_result = int(registers[instr["args"]["arg1"]], 16) & int(instr["args"]["arg1"], 16)

                # <const> <reg> 
                elif "0x" in instr["args"]["arg1"] and instr["args"]["arg0"] in registers.keys():
                    test_result = int(registers[instr["args"]["arg0"]], 16) & int(instr["args"]["arg1"], 16)

                # <mem> <const>
                elif instr["args"]["arg0"].find("rbp")!=-1 and "0x" in instr["args"]["arg1"]:
                    sf_pointed_address = int(instr["args"]["arg0"].split("PTR [rbp")[1].strip("]"),16)
                    test_result = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) & int(instr["args"]["arg1"], 16)

                # <const> <mem>
                elif instr["args"]["arg1"].find("rbp")!=-1 and "0x" in instr["args"]["arg0"]:
                    sf_pointed_address = int(instr["args"]["arg1"].split("PTR [rbp")[1].strip("]"),16)
                    test_result = int(sf.items[sf.addresses.index(sf_pointed_address)], 16) & int(instr["args"]["arg0"], 16)

                # Com esta variavel mantemos o binario original porque ele ao entrar na funcao do complemento de dois vai mudar os bits e como tal a paridade
                mantain_bin = test_result

                test_result = twos_comp(test_result, 64)
                if test_result == 0:
                    zero_flag = 1
                else:
                    zero_flag = 0

                if test_result < 0:
                    negative_flag = 1
                else:
                    negative_flag = 0
                # if the count of bits isn't an even number then the parity flag is 1
                if bin(mantain_bin).count("1") % 2 != 0:
                    parity_flag = 1
                registers["ZF"] = hex(zero_flag)
                print "test, zero_flag: " + str(zero_flag)

            elif instr["op"]=="je":
                if registers["ZF"] == hex(1):
                    registers["rip"] = instr["args"]["address"]
                else:
                    pass
            elif instr["op"]=="jmp":
                registers["rip"] = instr["args"]["address"]
            elif instr["op"]=="jne":
                if registers["ZF"] == hex(0):
                    registers["rip"] = instr["args"]["address"]
                else:
                    pass

            # every time a instruction is run, set the "rip" to the next instruction
            if instr["op"]!="ret" and instr["op"]=="jmp" and instr["op"]=="je" and instr["op"]=="jne":
                registers["rip"] = instructions[j+1]["address"]
            
        # padding size: variable allocated size minus all variables' sizes (which is
        # items' sizes that don't correspond to padding)
        sf.paddingsize = sf.varsize - sum([size for k,size in enumerate(sf.sizes[2:]) if sf.item_types[k+2]!="padding"])
        # pushing unused variables
        for var in variables:
            var_name = var["name"]
            var_size = var["bytes"]
            var_type = var["type"]
            var_address = int(var["address"].split("rbp")[1],16)
            if var_address not in sf.addresses:
                sf.push("allocated but unused variable", var_size, var_address, var_name, var_type)
        sf_list[i] = sf

    if extra_stack_stats:
        print "Full stack items dictionary (auxiliary structure):\n%s" %(stackvariables_dict)

    if stack_stats:
        print "STACK (splits in the stack represent different frames):"
        for sf in reversed(sf_list):
            print sf

    if function_stats:
        print "FUNCTIONS:"
        print "func_name: [subfunc_name, subfunc_call_address, ret_address, args]"
        for func in subfuncs_called:
            print func + ":\n" + str(subfuncs_called[func])

    for i, sf in enumerate(sf_list):
        items_len = len(sf.items)
        for j in range(items_len):
            if i==0 and j==0:
                sf.global_addresses.append(sf.sizes[j])
            elif i!=0 and j==0:
                sf.global_addresses.append(sf_list[i-1].global_addresses[-1] + sf.sizes[j])
            else:
                sf.global_addresses.append(sf.global_addresses[j-1] + sf.sizes[j])

    functions(subfuncs_called, sf_list)

# opening json file and putting it in a python dictionary
f = open(sys.argv[1])
program_dict = json.loads(f.read(), object_pairs_hook=OrderedDict)
f.close()

# parsing input dictionary to give us important stuff
parse()

