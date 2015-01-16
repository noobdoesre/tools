#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
This is just a little script for ImmunityDebugger that will resolve
exposed COM functions to their relative address. Check usage for some TODO items.

NOTE: Requires comtypes http://sourceforge.net/projects/comtypes/
Also comtypes .exe requires MS VC 9.0 redistributables:
 http://www.microsoft.com/downloads/thankyou.aspx?familyId=9b2da534-3e03-4391-8a4d-074b9f2bc1bf&displayLang=en

You will need to register your activex that you are auditing. Use "regsvr32 activexthing.dll"
IUf you're doing this on Vista, remember to run regsvr32 from an elevated cmd.exe!

"""

"""
from noobdoesre:
I changed the original script of https://github.com/kbandla/ to bring another one handy function - 
	now you do can export addresses of COM interfaces to IDC and use it to name all known handlers
Use this script within Windbg
"""

from pykd import *
import sys
import pefile
from ctypes import *
from ctypes.wintypes import *
try:
    from comtypes import *
    from comtypes.typeinfo import *
    from comtypes.automation import *
except ImportError:
    raise Exception('Comtypes library needed')

ole32 = windll.ole32
kernel32 = windll.kernel32


class MEMORY_BASIC_INFORMATION(Structure):

    _fields_ = [
        ('BaseAddress', c_void_p),
        ('AllocationBase', c_void_p),
        ('AllocationProtect', c_ulong),
        ('RegionSize', c_ulong),
        ('State', c_ulong),
        ('Protect', c_ulong),
        ('Type', c_ulong),
        ]


def usage():
    print('Usage: !py activextoidc_pykd <name of dll> <base address in ida> <full path to idcFile>')


def get_linear_address(address):
    mbi = MEMORY_BASIC_INFORMATION()
    kernel32.VirtualQuery(address, byref(mbi), sizeof(mbi))
    return mbi.AllocationBase


def enum_type_info_members(
    p_iref_type_info,
    p_reftype_attr,
    p_iunknown,
    base_addr,
    idaBase,
    dllSize,
    idcFile,
	textSectionAddress
    ):
    if p_reftype_attr.cFuncs == 0x0:
        return

    vtable = 0x0
    code_base = textSectionAddress

    for i in range(p_reftype_attr.cFuncs):
        func_desc = p_iref_type_info.GetFuncDesc(i)
        method_name = p_iref_type_info.GetNames(func_desc.memid)
        inv_kind = func_desc.invkind
        lpVtbl = cast(p_iunknown, POINTER(POINTER(c_void_p)))
        value = get_linear_address(lpVtbl[0x0][func_desc.oVft])
        if str(method_name[0x0]) == 'QueryInterface':
            import struct
            address = lpVtbl[0x0][i] - (value + 0x1000)
            address = address + code_base
            vtable = searchMemory(address, dllSize, struct.pack('L', address))
			
        if value is not None and lpVtbl[0x0][i] is not None:
            if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind \
																						== INVOKE_PROPERTYPUTREF:
                address = lpVtbl[0x0][i] - (value + 0x1000)
                address = address + code_base
        else:   
            if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind \
																						== INVOKE_PROPERTYPUTREF:
                try:
                    address = loadDWords(vtable + i * 4, 1)[0]
                except Exception:
                    address = 0x0
        if address < base_addr + dllSize and address > base_addr:
            idcFile.write('MakeName(0x%08x, "%s");\n' % (address
                          - base_addr + idaBase, str(method_name[0x0])))
        else:
            print('// Address of %s is out of the module'
                    % str(method_name[0x0]))
            idcFile.write('// Address of %s is out of the module\n'
                          % str(method_name[0x0]))

			
try:
	activex = sys.argv[0x1]
	idaBase = int(sys.argv[2], 16)
	idcFilePath = sys.argv[3]
	
except:
	usage()
	exit()

#module = imm.getModule(activex)
try:
    dll = module(activex)
except:
	print('Module "%s" not found. Check the Executable modules (Alt+E)' % activex)
	exit()

pe = pefile.PE(dll.image(), fast_load=True)
print("Module at " + hex(dll.begin()))
textSectionAddress = 0
for section in pe.sections:
	print(hex(section.Characteristics) + ' | ' + hex(section.VirtualAddress))
	if section.Characteristics & 0x20000000 != 0:
		textSectionAddress = dll.begin() + section.VirtualAddress
		break

tlib = LoadTypeLib(dll.image())
ticount = tlib.GetTypeInfoCount()
i = 0x0

with open(idcFilePath, 'w') as idcFile:
	while i < ticount:
		p_itype_info = tlib.GetTypeInfo(i)
		if p_itype_info:
			p_type_attr = p_itype_info.GetTypeAttr()
			if p_type_attr.typekind is TKIND_COCLASS:
				for ref in range(p_type_attr.cImplTypes):
					h_ref_type = p_itype_info.GetRefTypeOfImplType(ref)
					if h_ref_type:
						p_iref_type_info = p_itype_info.GetRefTypeInfo(h_ref_type)
						if p_iref_type_info:
							p_reftype_attr = p_iref_type_info.GetTypeAttr()
							try:
								p_iunknown = CoCreateInstance(p_type_attr.guid)
							except:
								pass
							if p_iunknown:
								enum_type_info_members(
									p_iref_type_info,
									p_reftype_attr,
									p_iunknown,
									dll.begin(),
									idaBase,
									dll.size(),
									idcFile,
									textSectionAddress
									)
			i += 1

print('Go on and rename em all!')
exit()	