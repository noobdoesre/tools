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
I changed a bit script of https://github.com/kbandla for you to create and .idc file on the fly
Copy-paste the contents of file you got and put it into File->IDC Command window in IDA
"""

from ctypes import *
from ctypes.wintypes import *
try:
   from comtypes import *
   from comtypes.typeinfo import *
   from comtypes.automation import *
except ImportError:
   raise Exception("Comtypes library needed")

from immlib import *

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


def usage(imm):
   imm.log("Usage: !activextoidc <name of dll> <base address in ida> <full path to idcFile>")

def get_linear_address(address):
   mbi = MEMORY_BASIC_INFORMATION()
   kernel32.VirtualQuery(address,byref(mbi),sizeof(mbi))
   return mbi.AllocationBase


def enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm, base_addr, idaBase, dllSize, idcFile):
   if p_reftype_attr.cFuncs == 0:
      return

   vtable = 0x0
   code_base = imm.getKnowledge("codebase")

   for i in range(p_reftype_attr.cFuncs):
      func_desc = p_iref_type_info.GetFuncDesc(i)
      method_name = p_iref_type_info.GetNames(func_desc.memid)
      inv_kind = func_desc.invkind
      lpVtbl = cast(p_iunknown, POINTER(POINTER(c_void_p)))
      value = get_linear_address(lpVtbl[0][func_desc.oVft])
      if str(method_name[0]) == "QueryInterface":
         import struct
         address = (((lpVtbl[0][i])-(value+0x1000)))
         address = address + code_base
         pages = imm.getMemoryPageByOwnerAddress( base_addr ) # workaround
         for page in pages:
            mem = page.getMemory()
            ndx = mem.find( struct.pack("L", address) )
            if ndx != -1:
               vtable = page.getBaseAddress() + ndx
               break

      if value is not None and lpVtbl[0][i] is not None:
         if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind == INVOKE_PROPERTYPUTREF:
            address = (((lpVtbl[0][i])-(value+0x1000)))
            address = address + code_base
      else:
         if func_desc.invkind == INVOKE_FUNC or func_desc.invkind == INVOKE_PROPERTYPUT or func_desc.invkind == INVOKE_PROPERTYPUTREF:
            try:
               address = imm.readLong( vtable + i*4)
            except Exception:
               address = 0
      if address < base_addr + dllSize and address > base_addr:
         idcFile.write('MakeName(0x%08x, \"%s\");\n' % (address - base_addr + idaBase, str(method_name[0])))
      else:
         imm.log("// Address of %s is out of the module" % (str(method_name[0])))
         idcFile.write("// Address of %s is out of the module\n" % (str(method_name[0])))


def main(args):
   imm = Debugger()

   try:
      activex = args[0]
      idaBase = int(args[1], 16)
      idcFilePath = args[2]

   except:
      usage(imm)
      return

   module = imm.getModule(activex)
   if not module:
      return "Module \"%s\" not found. Check the Executable modules (Alt+E)" % activex
   
   imm.addKnowledge("codebase",module.getCodebase(),force_add=1)
   tlib = LoadTypeLib(module.getPath())
   ticount = tlib.GetTypeInfoCount()
   i = 0
   
   try:
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
                           p_iunknown = CoCreateInstance(p_type_attr.guid)
                           if p_iunknown:
                              enum_type_info_members(p_iref_type_info,p_reftype_attr,p_iunknown,imm,\
                                 module.getBaseAddress(), idaBase, module.getSize(), idcFile)
               i+=1

   except IOError:
      return "Can't open log file"
   except:
      return "Error creating some class \(-_-)/"

   return "Go on and rename em all!"