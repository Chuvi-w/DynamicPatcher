//#include <stdafx.h>

#ifdef _WIN32
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winnt.h>
#pragma pack(push, 1)
struct FuncHook2_s 
{
	unsigned char _jmp; //e9
	int addr;
};
#pragma pack(pop)

#else
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#ifndef PAGESIZE
#define PAGESIZE 4096
#endif
#pragma push()
#pragma pack(1)
struct FuncHook2_s {
	unsigned char _jmp; //e9
	int addr;
};
#pragma pop()

#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
#define MAX_PATH FILENAME_MAX
#include <tier1/strtools.h>
#endif

#include "CDynPatcher.h"
#include "CSectionData.h"
CDynPatcher::CDynPatcher() :DllHandler(0), DllBase(0), bSelfLoaded(false), szLibName(0)
{
   HookData.clear();
   szLibName=0;
}

CDynPatcher::~CDynPatcher()
{
   CloseLib();
}





void CDynPatcher::Error(const char *File, const char *Func, int Line, bool IsCritical, char *Fmt, ...)
{
   static char Buff[0x1000];
   int len=0;
   
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"[CDynPatcher] %serror",IsCritical?"critical":"");
   if(File&&Func&&Line&&strlen(File)<MAX_PATH&&strlen(Func)<300)
   {
      len+=_snprintf(&Buff[len],sizeof(Buff)-len-1," at %s(%s:%i)",CSectionData::GetFileName(File),Func,Line);
   }
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,":");
   va_list marker;
   if(!Fmt)
   {
      len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"(NO DESCRIPTION)\r\n");
   }
   else
   {
      va_start( marker, Fmt );
      len+=_vsnprintf(&Buff[len],sizeof(Buff)-len-1, Fmt, marker );
   }
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"\r\n");
   printf("%s",Buff);
   if(IsCritical)
   {
      #ifdef WIN32
      __asm{int 3};
      
      if(!IsDebuggerPresent())
      {
         exit(0);
      }
      #else
      exit(0);
      #endif
   }
}

void CDynPatcher::Message(const char *File, const char *Func, int Line, char *Fmt, ...)
{
   static char Buff[0x1000];
   int len=0;
   
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"[CDynPatcher]");
   if(File&&Func&&Line&&strlen(File)<MAX_PATH&&strlen(Func)<300)
   {
      len+=_snprintf(&Buff[len],sizeof(Buff)-len-1," at %s(%s:%i)",CSectionData::GetFileName(File),Func,Line);
   }
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,":");
   va_list marker;
   if(!Fmt)
   {
      len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"(NO DESCRIPTION)\r\n");
   }
   else
   {
      va_start( marker, Fmt );
      len+=_vsnprintf(&Buff[len],sizeof(Buff)-len-1, Fmt, marker );
   }
   len+=_snprintf(&Buff[len],sizeof(Buff)-len-1,"\r\n");
   printf("%s",Buff);
}

bool CDynPatcher::Init(const char *LibName,bool ForceLoad)
{
   if (!LibName)
   {
      szLibName = "<<===NO LIBRARY NAME===>>";
      return false;
   }

   if(!LoadLib(LibName,ForceLoad))
   {
      DynErr(false,"Unable to load \"%s\"",LibName);
      return false;
   }
#ifdef WIN32
   if(!ParseGenericDllData_PE())
   {
      DynErr(false,"Failed to parse \"%s\"",szLibName);
      return false;
   }
   DynMsg("\"%s\" parsed",szLibName);
#else
	FILE *fl = fopen(szLibName, "rb");
	int LibSize;
	void* LibBuf;
	if (fl == NULL) 
	{
		DynErr(false,"Failed to open '%s' for read\n", szLibName);
		return false;
	}

	fseek(fl, 0, SEEK_END);
	LibSize = ftell(fl);
	fseek(fl, 0, SEEK_SET);


	if (LibSize < 0)
	LibSize = 0;
	LibBuf = malloc(LibSize + 4);
	fread(LibBuf, 1, LibSize, fl);
	fclose(fl);
   if(!ParseGenericDllData_ELF(LibBuf, LibSize))
   {
      DynErr(false,"Failed to parse \"%s\"",szLibName);
      return false;
   }
#endif
   return true;
}


bool CDynPatcher::Init(const wchar_t *LibName, bool ForceLoad /*= false*/)
{
	return 0;
   static char UTF8LibName[MAX_PATH];
   //Q_UnicodeToUTF8(LibName, UTF8LibName, MAX_PATH-1);
   return Init(UTF8LibName, ForceLoad);
}

bool CDynPatcher::Init(void *FuncAddr)
{
   char szTmpName[400];
   sprintf(szTmpName, "Unk_load_by_func_addr_%p", FuncAddr);
   szLibName = new  char[strlen(szTmpName) + 1];
   strcpy(szLibName, szTmpName);
   bSelfLoaded = false;
#ifdef _WIN32
   MEMORY_BASIC_INFORMATION mem;
   VirtualQuery(FuncAddr, &mem, sizeof(mem));
   szTmpName[0] = 0;
   GetModuleFileNameA(reinterpret_cast<HMODULE>(mem.AllocationBase ), szTmpName, sizeof(szTmpName) - 1);
 
   if (szTmpName[0] != 0)
   {
      delete[]szLibName;
      szLibName = new char[strlen(CSectionData::GetFileName(szTmpName)) + 1];
      strcpy(szLibName, CSectionData::GetFileName(szTmpName));
   }
   IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)mem.AllocationBase;
   IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS*)((unsigned long)dos + (unsigned long)dos->e_lfanew);
   
   if (pe->Signature == IMAGE_NT_SIGNATURE)
   {
      this->DllHandler = mem.AllocationBase;
      if (!ParseGenericDllData_PE())
      {
         DynErr(false, "Failed to parse \"%s\"", szLibName);
         return false;
      }
      DynMsg("\"%s\" parsed",szLibName);
   }
#else
   Dl_info info;
   if (dladdr(FuncAddr, &info) && info.dli_fbase &&info.dli_fname)
   {
      delete [] szLibName;
      szLibName = new  char[strlen(info.dli_fname) + 1];
      strcpy(szLibName, info.dli_fname);
      bool ParseOK=false;
      size_t LoadLibSize=0;
      DllBase = info.dli_fbase;
      LoadLibSize = (size_t)GetBaseLen(DllBase);
      DllHandler = dlopen(info.dli_fname, RTLD_NOW);
      dlclose(DllHandler);
      DynMsg("Found library \"%s\" at addr %p. Base=%p, size=%x, handler=%p",szLibName,FuncAddr,DllBase,LoadLibSize,DllHandler);
      FILE *fl = fopen(szLibName, "rb");
      int LibSize;
      void* LibBuf;
      if (fl)
      {  
         fseek(fl, 0, SEEK_END);
         LibSize = ftell(fl);
         fseek(fl, 0, SEEK_SET);
         DynMsg("Reading \"%s\" as file. Size=%x",szLibName,LibSize);

         if (LibSize < 0)
            LibSize = 0;
         LibBuf = malloc(LibSize + 4);
         fread(LibBuf, 1, LibSize, fl);
         fclose(fl);
         ParseOK=ParseGenericDllData_ELF(LibBuf, LibSize);
         free(LibBuf);       
      }
      else
      {
         DynMsg("Unable to read \"%s\" as file. Trying to use information from Dl_info.",szLibName);
         ParseOK=ParseGenericDllData_ELF(DllBase, LoadLibSize);
      }
      if (!ParseOK)
      {
         DynErr(false, "Failed to parse \"%s\"", szLibName);
         return false;
      }
   }
#endif
   else
   {
      DynErr(false, "Failed find library at %p",FuncAddr);
      return false;
   }
   return true;
}



#ifdef WIN32
#ifndef max
	#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif




bool CDynPatcher::ParseGenericDllData_PE() 
{
   if(!this->DllHandler)
      return false;
    DynMsg(("Base addr=%p\n"), this->DllHandler);
	int i = 0;
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>( this->DllHandler);
   
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
   {
		DynErr(false,"Invalid dos header signature");
		return false;
	}

	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS) ((size_t)this->DllHandler + dosHeader->e_lfanew);
	if (NTHeaders->Signature != 0x4550) 
   {
		DynErr(false,"Invalid NT Headers signature");
		return false;
	}
   PIMAGE_OPTIONAL_HEADER opt = &NTHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER cSection = (PIMAGE_SECTION_HEADER) ((size_t)(&NTHeaders->OptionalHeader) + NTHeaders->FileHeader.SizeOfOptionalHeader);

	PIMAGE_SECTION_HEADER CodeSection = NULL;
	
   char SectionName[IMAGE_SIZEOF_SHORT_NAME + 1];

	for (i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++, cSection++) 
   {
      memcpy(&SectionName, cSection->Name, IMAGE_SIZEOF_SHORT_NAME);
      SectionName[IMAGE_SIZEOF_SHORT_NAME] = 0;
	  DynMsg(("Section: \"%s\": "), SectionName);
      if (cSection->VirtualAddress == NTHeaders->OptionalHeader.BaseOfCode)
      {
		  DynMsg("(%p-%p) (%p-%p) ", vtr(cSection->VirtualAddress), reinterpret_cast<DWORD>(vtr(cSection->VirtualAddress)) + cSection->SizeOfRawData, vtr(cSection->VirtualAddress), reinterpret_cast<DWORD>(vtr(cSection->VirtualAddress)) + cSection->Misc.VirtualSize);
         CodeSection = cSection;
      }
		if (cSection->VirtualAddress >= NTHeaders->OptionalHeader.BaseOfData) 
      {
		  DynMsg("(%p-%p) (%p-%p) ", vtr(cSection->VirtualAddress), reinterpret_cast<DWORD>(vtr(cSection->VirtualAddress)) + cSection->SizeOfRawData, vtr(cSection->VirtualAddress), reinterpret_cast<DWORD>(vtr(cSection->VirtualAddress)) + cSection->Misc.VirtualSize);
         rdata.Add((uint32_t)this->DllHandler + cSection->VirtualAddress,cSection->SizeOfRawData,this);
         vdata.Add((uint32_t)this->DllHandler + cSection->VirtualAddress,cSection->Misc.VirtualSize,this);
		}
		DynMsg(("\n"));
			
	}

	if (CodeSection == NULL) 
   {
		DynErr(false,"Code section not found");
		return false;
	}

	if (!rdata.IsValid()) 
   {
		DynErr(false,"RData sections not found", __FUNCTION__);
		return false;
	}

	if (!vdata.IsValid()) 
   {
		DynErr(false,"VData sections not found", __FUNCTION__);
		return false;
	}


	this->code.Add((uint32_t)this->DllHandler + CodeSection->VirtualAddress,CodeSection->Misc.VirtualSize,this);

	rdata.Sort();
	vdata.Sort();

#ifdef PARSE_IMPORT_EXPORT
   if (NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
   {
      Msg(_T("IMAGE_DIRECTORY_ENTRY_IMPORT exist\n"));
   }
   if (NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size)
   {
      Msg(_T("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT exist\n"));
   }
   if (NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size)
   {
      Msg(_T("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT exist\n"));
   }


   CImportTable *ImpTab;
   PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

   if(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)/*if size of the table is 0 - Import Table does not exist */
   {
      pImportDescriptor = vtrt<PIMAGE_IMPORT_DESCRIPTOR>(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
     
      while(pImportDescriptor->Name)
      {
         ImpTab=new CImportTable;
         if(ImpTab->ParseImportTable(DllHandler,pImportDescriptor, &rdata))
         {
            ImportData.push_back(ImpTab);
         }
         else
         {
            delete ImpTab;
         } 
         pImportDescriptor++;
      }
   }
//#error http://www.deltann.ru/10/d-112007/p-169
   /*
   typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;    //0x00
    DWORD   TimeDateStamp;      //0x4
    WORD    MajorVersion;       //0x8
    WORD    MinorVersion;       //0xA
    DWORD   Name;               //0xC   nameRVA
    DWORD   Base;               //0x10  ordinalBASE
    DWORD   NumberOfFunctions;  //0x14  addressTableEntries
    DWORD   NumberOfNames;      //0x18  numberOfNamePointers
    DWORD   AddressOfFunctions; //0x1C  exportAddressTableRVA
    DWORD   AddressOfNames;     //0x20  namePointerRVA
    DWORD   AddressOfNameOrdinals;//0x24   ordinalTableRVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/
   PIMAGE_EXPORT_DIRECTORY pExportDir;
   char *name;
   uint32_t f_index,f_address,ordinal ;
   char *pForward;
   //DebuggerBreak();
   ExportData_t *ExpData;
   uint32_t pAddr;
   if(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
   {
      pExportDir=vtrt<PIMAGE_EXPORT_DIRECTORY>(NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
      for(uint32_t i=0;i<max(pExportDir->NumberOfFunctions,pExportDir->NumberOfNames);i++)
      {
         if (i < pExportDir->NumberOfNames)
         {
           name = vtrt<char*>(reinterpret_cast<uint32_t*>(vtrt<uint32_t*>(pExportDir->AddressOfNames)[i]));
           f_index = vtrt<uint16_t*>(pExportDir->AddressOfNameOrdinals)[i];
         }
         else
         {
           name = "n/a";  f_index = i;
         }
         pAddr = static_cast<uint32_t>(vtrt<uint32_t*>(pExportDir->AddressOfFunctions)[f_index]);
         //f_address = (uint32_t)vtr(vtrt<uint32_t*>(pExportDir->AddressOfFunctions)[f_index]);
         f_address = (uint32_t)vtr(pAddr);
         // ïîèñê "ðàçðûâîâ" â òàáëèöå àäðåñîâ
         if (f_address == reinterpret_cast<uint32_t>(this->DllHandler))
         {
           // Msg("Hole! (i=%i)\n",i);
            continue;
         }
          ordinal = f_index + pExportDir->Base;
         if ((f_address > (uint32_t) pExportDir) && (f_address < (uint32_t) ((uint32_t) pExportDir + (uint32_t) NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)))
         {
                 pForward = ( char *)f_address; 
         }
         else 
         {
            pForward  = 0;
         }

        // Msg("%-30s [%03d/%03d] %08Xh %s \n",name, ordinal, i, f_address, (pForward)?pForward:"");
/*
         ExpData = new ExportData_t;
         ExpData->FuncName = name;
         ExpData->FuncAddr = f_address;
         ExpData->pVFuncAddr = pAddr;
         ExportData.push_back(ExpData);
*/
      }
   
   }

#endif
   this->DllBase = this->DllHandler;
   this->DllSize = opt->SizeOfImage;
	return true;
}

#else
bool CDynPatcher::ParseGenericDllData_ELF(void* FileData, uint32_t FileSize) 
{
   if(!this->DllBase)
   {
		DynErr(false,"DllBase not set");
		return false;
	}
	if (FileSize < sizeof(Elf32_Ehdr)) 
	{
		DynErr(false,"bad library file (header)");
		return false;
	}

	Elf32_Ehdr* ehdr = (Elf32_Ehdr*) FileData;
	if (ehdr->e_ident[0] != 0x7F ||
		ehdr->e_ident[1] != 'E' ||
		ehdr->e_ident[2] != 'L' ||
		ehdr->e_ident[3] != 'F') {

			DynErr(false,"ELF Signature mismatch (got %.2X %.2X %.2X %.2X)\n", ehdr->e_ident[0], ehdr->e_ident[1], ehdr->e_ident[2], ehdr->e_ident[3]);
			return false;
	}

	int i;

	if (sizeof(Elf32_Phdr) > ehdr->e_phentsize)
		return false;

	if (sizeof(Elf32_Shdr) > ehdr->e_shentsize)
		return false;

	if (FileSize < (ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum)) {
		DynErr(false,"bad library file (program headers)");
		return false;
	}

	if (FileSize < (ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum)) {
		DynErr(false,"bad library file (section headers)");
		return false;
	}

	Elf32_Phdr* cpHdr = (Elf32_Phdr*)((size_t)FileData + ehdr->e_phoff);
	for (i = 0; i < ehdr->e_phnum; i++) 
   {
      rdata.Add((uint32_t)this->DllBase + cpHdr->p_vaddr,cpHdr->p_filesz,this);
      vdata.Add((uint32_t)this->DllBase + cpHdr->p_vaddr,cpHdr->p_memsz,this);
		cpHdr = (Elf32_Phdr*)((size_t)cpHdr + ehdr->e_phentsize);
	}


	//ALERT(at_logged, "[DPROTO]: %s: e_shstrndx = 0x%.8X; e_shoff=0x%.8X;\n", __FUNCTION__, ehdr->e_shstrndx, ehdr->e_shoff);
	uint32_t StringSectionHdrOff = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
	if (FileSize < (StringSectionHdrOff + ehdr->e_shentsize)) {
		DynErr(false,"bad library file (string section not found)");
		return false;
	}
	Elf32_Shdr* shstrHdr = (Elf32_Shdr*) ((size_t)FileData + StringSectionHdrOff);
	char* StringTable = (char*) ((size_t)FileData + shstrHdr->sh_offset);
	this->GlobalsBase = 0;
	Elf32_Shdr* csHdr = (Elf32_Shdr*)((size_t)FileData + ehdr->e_shoff);
    for (i = 0; i < ehdr->e_shnum; i++) 
    {
        const char* sname = StringTable + csHdr->sh_name;
        //DynMsg("Seg[%d].name = 0x%.8X\n", i, csHdr->sh_name);
        //DynMsg("Seg[%d].name = '%s'\n", i, sname);
        if (!strcmp(sname, ".got")) 
        {
            this->GlobalsBase = (uint32_t)this->DllBase + csHdr->sh_addr;
            sect_got.Add((uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,this);
            //DynMsg("Seg[%d].name = 0x%.8X\n", i, csHdr->sh_name);
            DynMsg("Seg[%d].name = '%s'  0x%x 0x%x val=%i\n", i, sname,(uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,sect_got.IsValid());
        } 
        else if (!strcmp(sname, ".text")) 
        {
            code.Add((uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,this);
            DynMsg("Seg[%d].name = '%s'  0x%x 0x%x val=%i\n", i, sname,(uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,code.IsValid());
        } 
        else if (!strcmp(sname, ".plt")) 
        {
            sect_plt.Add((uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,this);
            DynMsg("Seg[%d].name = '%s'  0x%x 0x%x val=%i \n", i, sname,(uint32_t)this->DllBase + csHdr->sh_addr,csHdr->sh_size,sect_plt.IsValid());
        }
        csHdr = (Elf32_Shdr*)((size_t)csHdr + ehdr->e_shentsize);
    }
		
	if (GlobalsBase == 0) 
   {
		DynErr(false,"bad library file (.got section not found)");
		return false;
	}

	if (!code.IsValid()) 
   {
		DynErr(false,"bad  library file (.text section not found)");
		return false;
	}

	if (!sect_plt.IsValid()) 
   {
		DynErr(false,"bad  library file (.plt section not found)");
		return false;
	}
   DllSize=FileSize;
	return true;
}

//char MBuffer[32768];
void* CDynPatcher::LocateLib(const char* libname) 
{
	char fname[128];
	char linebuf[512];
	char clib[256];
	const char *clp;
	FILE *fl;
	int sl;
	void* RegStart;
	void* RegEnd;
	Dl_info dli;

	sprintf(fname, "/proc/%d/maps", getpid());
	fl = fopen(fname, "r");
	if (fl == NULL) 
   	{
		return NULL;
	}

	//setbuffer(fl, MBuffer, sizeof(MBuffer));
	while (fgets(linebuf, sizeof(linebuf), fl)) 
   {
		sl = sscanf(linebuf, "%x-%x %s %s %s %s %s", &RegStart, &RegEnd, fname, fname, fname, fname, clib);
		if (sl != 7) 
      {
			continue;
		}

		if (dladdr(RegStart, &dli) == 0) 
      {
			continue;
		}

		clp = CSectionData::GetFileName(dli.dli_fname);
		if (strcmp(libname, clp) == 0) 
      {
			fclose(fl);
			return dli.dli_fbase;
		}
	}
	fclose(fl);
	return NULL;
}

uint32_t CDynPatcher::GetBaseLen(void *baseAddress)
{
   pid_t pid = getpid();
   char file[255];
   char buffer[2048];
   snprintf(file, sizeof(file)-1, "/proc/%d/maps", pid);
   FILE *fp = fopen(file, "rt");
   if (fp)
   {
      long length = 0;

      void *start = NULL;
      void *end = NULL;

      while (!feof(fp))
      {
         if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL)
            return 0;

         sscanf(buffer, "%lx-%lx", reinterpret_cast<long unsigned int *> (&start), reinterpret_cast<long unsigned int *> (&end));

         if (start == baseAddress)
         {
            length = (unsigned long)end - (unsigned long)start;

            char ignore[100];
            int value;

            while (!feof(fp))
            {
               if (fgets(buffer, sizeof(buffer) - 1, fp) == NULL)
                  return 0;

               sscanf
                  (
                  buffer,
                  "%lx-%lx %*s %*s %*s %d",
                  reinterpret_cast<long unsigned int *> (&start),
                  reinterpret_cast<long unsigned int *> (&end),
                  &value
                  );

               if (!value)
               {
                  break;
               }
               else
               {
                  length += (unsigned long)end - (unsigned long)start;
               }
            }

            break;
         }
      }

      fclose(fp);

      return length;
   }

   return 0;
}
bool CDynPatcher::MProtect_Ex(void *addr, int npages)
{
   void *paddr;
   paddr = (void *)(((size_t)addr) & ~(PAGESIZE - 1));
   return !mprotect(paddr, PAGESIZE*(npages + 1), PROT_READ | PROT_WRITE | PROT_EXEC);
}

#endif

bool CDynPatcher::LoadLib(const char *LibName, bool ForceLoad)
{
   if(!LibName)
      return false;
   DynMsg("Loading library:%s%s",LibName,ForceLoad?" (Force)":"");
   if(DllHandler)
   {
      DynErr(false,"Library \"%s\" already loaded",szLibName);
      return false;
   }
   szLibName = new  char[strlen(LibName) + 1];
//#ifdef _WIN32
   strcpy(szLibName, LibName);
#ifdef LINUX
    int Len=strlen(LibName) + 1;
    V_StripExtension(LibName,szLibName,Len);
    V_SetExtension( szLibName, ".so", Len);
#endif
    const char *LibFileName = CSectionData::GetFileName(szLibName);
   DynMsg("LibName=\"%s\"; LibFileName=\"%s\"",szLibName,LibFileName);
#ifdef _WIN32
   DllHandler=GetModuleHandleA(LibFileName);
   //DynMsg("GetModuleHandleA(%s)=0x%p",LibFileName,DllHandler);
   if(DllHandler)
   {
      bSelfLoaded=false;
      return true;
   }
   else if(ForceLoad)
   {
      //DynMsg("Force loading!");
      DllHandler=LoadLibraryA(szLibName);
      //DynMsg("LoadLibraryA(%s)=0x%p",LibName,DllHandler);
      if(DllHandler)
      {
         bSelfLoaded=true;
         return true;
      }
   }
#else
   DllBase=LocateLib(LibFileName);
   DynMsg("LocateLib(%s)=0x%p",LibFileName,DllBase);
   if(DllBase)
   {
      DllHandler=dlopen(szLibName,RTLD_NOW);
      DynMsg("dlopen(%s)=0x%p",szLibName,DllHandler);
      dlclose(DllHandler);
      DynMsg("DllHandler aftrer dlclose=0x%p",DllHandler);
      if(DllHandler)
      {
         bSelfLoaded=false;
         return true;
      }
      else
      {
         DllBase=0;
         return false;
      }
   }
   else if(ForceLoad)
   {
      DynMsg("Force loading!");
      DllHandler=dlopen(szLibName, RTLD_NOW);
      DynMsg("dlopen(%s)=0x%p",szLibName,DllHandler);
      if(!DllHandler)
      {
         return false;
      }
      DllBase=LocateLib(LibFileName);
      DynMsg("LocateLib(%s)=0x%p",LibFileName,DllBase);
      if(!DllBase)
      {
         dlclose(DllHandler);
         DllHandler=NULL;
         return false;
      }
      bSelfLoaded=true;
      return true;
   }
#endif
   return false;
}

bool CDynPatcher::CloseLib()
{
   if(!DllHandler)
      return false;

   DynMsg("Closing \"%s\"",szLibName);
   UnsetHooks();
#ifdef PARSE_IMPORT_EXPORT
   DeleteImportData();
#endif
   if (szLibName)
   {
      delete [] szLibName;
   }

   if(DllHandler)
   {
      if(bSelfLoaded)
      {
#ifndef _WIN32
         dlclose(DllHandler);
#else
         FreeLibrary(reinterpret_cast<HMODULE>(DllHandler));
#endif
    }
      DllHandler=NULL;
      return true;
   }
   DllHandler=NULL;
   return false;
}


/*
bool CDynPatcher::FindSymbol(const char* sName, uint32_t* pSym) 
{
   if(!DllHandler)
   {
      return false;
   }

	uint32_t csym =
#ifdef WIN32
      reinterpret_cast<uint32_t>(GetProcAddress(reinterpret_cast<HMODULE>(DllHandler), sName));
#else
      reinterpret_cast<uint32_t>(dlsym(DllHandler, sName));
#endif
	if (csym == 0) 
   {
		DynErr(false,"Cant Resolve '%s'\n", sName);
		return false;
	}
   if(pSym)
	   *pSym = csym;
	return true;
}
*/


uint32_t CDynPatcher::FindString(uint32_t StartAddr, const char* str, bool FullMatch) 
{
	CSectionData* csect = NULL;
	uint32_t cs;
	if (StartAddr == 0) 
   {
		cs = rdata.GetStart();
		csect = &rdata;
	}
	else 
   {
		cs = StartAddr + 1;
		CSectionData *cur = &rdata;
		while (cur) 
      {
			if (cur->GetStart() >= StartAddr) 
         {
				csect = cur;
				break;
			}
			cur = cur->GetNext();
		}
	}

	while (csect) 
   {
		cs = csect->FindString(str, cs, FullMatch);
		if (cs)
			return cs;

		csect = csect->GetNext();
		if (csect)
			cs = csect->GetStart();
	}
	return NULL;
}

uint32_t CDynPatcher::FindDataRef(uint32_t StartAddr, uint32_t RefAddr) 
{
	CSectionData* csect = NULL;
	uint32_t cs;
	if (StartAddr == 0) 
   {
		cs = rdata.GetStart();
		csect = &rdata;
	}
	else 
   {
		cs = StartAddr + 1;
		//we need to find ourself x_x
		CSectionData *cur = &rdata;
		while (cur) 
      {
			if (cur->GetStart() >= StartAddr) 
         {
				csect = cur;
				break;
			}
			cur = cur->GetNext();
		}
	}

	while (csect) 
   {
		cs = csect->FindDataRef(RefAddr, cs);
		if (cs)
			return cs;

		csect = csect->GetNext();
		if (csect)
			cs = csect->GetStart();
	}
	return NULL;
}



uint32_t CDynPatcher::ScanForTemplate_Backward(const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect) 
{
	uint8_t* Code_End = (uint8_t*) (Code_Start - Code_Size);
	uint8_t* Code_Cur = (uint8_t*) (Code_Start - TemplSize);
   CSectionData *LookupSect=pLookupSect;
   if(!pLookupSect)
   {
      LookupSect=&code;
   }

	if ((uint32_t)Code_End < LookupSect->GetStart())
		Code_End = (uint8_t*) LookupSect->GetStart();

	size_t Result = 0;
	int i;
	bool not_match;

	while (Code_Cur >= Code_End && !Result) 
   {
		not_match = false;
		for (i = 0; i < TemplSize; i++) 
      {
			if ((Code_Cur[i] & Mask[i]) != (Templ[i] & Mask[i])) 
         {
				not_match = true;
				break;
			}
		}
		if (!not_match) 
      {
			Result = (uint32_t) Code_Cur;
		}
		Code_Cur--;
	}
	return Result;
}

uint32_t CDynPatcher::ScanForTemplate_Forward(const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect) 
{
	uint8_t* Code_End = (uint8_t*) (Code_Start + Code_Size);
	uint8_t* Code_Cur = (uint8_t*) (Code_Start);
   CSectionData *LookupSect=pLookupSect;
   if(!pLookupSect)
   {
      LookupSect=&code;
   }

	if ((uint32_t)Code_End > LookupSect->GetEnd())
		Code_End = (uint8_t*) LookupSect->GetEnd();

	Code_End -= TemplSize;

	size_t Result = 0;
	int i;
	bool not_match;

	while (Code_Cur <= Code_End && !Result) 
   {
		not_match = false;
		for (i = 0; i < TemplSize; i++) 
      {
			if ((Code_Cur[i] & Mask[i]) != (Templ[i] & Mask[i])) 
         {
				not_match = true;
				break;
			}
		}
		if (!not_match) 
      {
			Result = (size_t) Code_Cur;
		}
		Code_Cur++;
	}

	return Result;
}

uint32_t CDynPatcher::ScanForTemplate_Backward(const char* Templ, const char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect)
{
   return ScanForTemplate_Backward(reinterpret_cast<const unsigned char*>(Templ), reinterpret_cast<const unsigned char*>(Mask), TemplSize, Code_Start, Code_Size, pLookupSect);
}
uint32_t CDynPatcher::ScanForTemplate_Forward(const char* Templ, const char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect)
{
   return ScanForTemplate_Forward(reinterpret_cast<const unsigned char*>(Templ), reinterpret_cast<const unsigned char*>(Mask), TemplSize, Code_Start, Code_Size, pLookupSect);
}

uint32_t CDynPatcher::FindRef_Mov(uint32_t StartAddr, uint32_t RefAddress)
{
    if(StartAddr<code.GetStart())
    {
        StartAddr=code.GetStart();
    }
    
    if(StartAddr>code.GetEnd())
    {
        DynErr(false,"!!StartAddr>code.GetEnd()!! (0x%x>0x%x)\n",StartAddr,code.GetEnd());
        return 0;
    }   
    
   /* 
    if(StartAddr<code.GetStart())
    {
        DynErr(false,"!!StartAddr<code.GetStart()!! (0x%x>0x%x)\n",StartAddr,code.GetStart());
        return 0;
    } 
     */
    uint32_t addr= code.FindRef_Mov(StartAddr,RefAddress);
    if(addr)
    {
       // Msg("start=0x%x FindRef_Mov=%x end=0x%x \n",code.GetStart(),addr,code.GetEnd());
        return addr;
    }
    

    uint32_t Size;
    char ScanDataC7[] = "\xC7\x00\x00\x00\x00\x00\x00";
    char ScanMaskC7[] = "\xFF\x00\x00\xFF\xFF\xFF\xFF";
    *reinterpret_cast<uint32_t*>(&ScanDataC7[3])=RefAddress;
    //Msg("Ref=%x ScanDataC7=%x %x %x %x %x %x %x\n",RefAddress,ScanDataC7[0]&0xFF,ScanDataC7[1]&0xFF,ScanDataC7[2]&0xFF,ScanDataC7[3]&0xFF,ScanDataC7[4]&0xFF,ScanDataC7[5]&0xFF,ScanDataC7[6]&0xFF);
    Size=code.GetEnd()-StartAddr;
    addr=ScanForTemplate_Forward(reinterpret_cast<const unsigned char*>(ScanDataC7), reinterpret_cast<const unsigned char*>(ScanMaskC7), sizeof(ScanMaskC7)-1 , StartAddr, Size, &code);
    //Msg("start=0x%x RefMovAddr=%x end=0x%x StartAddr=0x%x RefAddress=0x%x\n",code.GetStart(),addr,code.GetEnd(),StartAddr,RefAddress);
    if(addr)
    {
        return addr;
    }
    
    return 0;
}

uint32_t CDynPatcher::FindRef_Push(uint32_t StartAddr, uint32_t RefAddress) 
{
	uint32_t ret=code.FindRef_Push(StartAddr,RefAddress);
	return ret;
}

uint32_t CDynPatcher::FindRef_Call(uint32_t StartAddr, uint32_t RefAddress)
{
	uint32_t ret=code.FindRef_Call(StartAddr,RefAddress);
	return ret;
}


uint32_t CDynPatcher::FindRef_Jmp(uint32_t StartAddr, uint32_t RefAddress)
{
   	uint32_t ret=code.FindRef_Jmp(StartAddr, RefAddress);
	return ret;
}




uint32_t CDynPatcher::HookFunctionCall(void *OrigAddr, void *NewAddr)
{
   uint32_t ref = 0;
   HookData_t HData;
   FuncHook2_s* hook;
   int OldSize = HookData.size();
#ifdef WIN32
   DWORD Oldp;
#endif
   ref = FindRef_Call(ref, reinterpret_cast<uint32_t>(OrigAddr));
   int num = 1;
#ifndef _WIN32
	Dl_info AddrInfo;
   Dl_info RefInfo;
	if (!dladdr(OrigAddr, &AddrInfo))
   {
		memset(&AddrInfo,0,sizeof(AddrInfo));
   }
#endif
   while (ref)
   {
#ifndef _WIN32
	
   if (!dladdr(ref, &RefInfo))
	{
		memset(&RefInfo,0,sizeof(RefInfo));	
	}
	DynMsg("Call %i to 0x%p(%s) at %x(%s)\n", num++,OrigAddr, AddrInfo.dli_sname?AddrInfo.dli_sname:"_", ref,AddrInfo.dli_sname?RefInfo.dli_sname:"_");
#else
	DynMsg("Call %i to %p at %p\n", num++, OrigAddr, ref);
#endif
      HData.Addr = reinterpret_cast<uint32_t*>(ref + 1);
      HData.OrigVal = *reinterpret_cast<unsigned int*>(ref + 1);
      HookData.push_back(HData);
      hook = reinterpret_cast<FuncHook2_s*>(ref);
#ifdef WIN32
      VirtualProtect(reinterpret_cast<void*>(ref), 8, PAGE_EXECUTE_READWRITE, &Oldp);
#else
      MProtect_Ex(reinterpret_cast<void*>(ref), 1);
#endif
      hook->_jmp = 0xe8;
      hook->addr = reinterpret_cast<int>(NewAddr)-static_cast<int>(ref)-5;
#ifdef WIN32
      VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
#else
#endif
      ref = FindRef_Call(ref, reinterpret_cast<uint32_t>(OrigAddr));
   }

   ref = 0;
   ref = FindRef_Jmp(ref, reinterpret_cast<uint32_t>(OrigAddr));
   num = 1;
   while (ref)
   {
#ifndef _WIN32
   
      if (!dladdr(ref, &RefInfo))
      {
         memset(&RefInfo, 0, sizeof(RefInfo));
      }
      DynMsg("Jmp %i to 0x%p(%s) at %x(%s)\n", num++, OrigAddr, AddrInfo.dli_sname ? AddrInfo.dli_sname : "_", ref, AddrInfo.dli_sname ? RefInfo.dli_sname : "_");
#else
      DynMsg("Jmp %i to %p at %p\n", num++, OrigAddr, ref);
#endif
      HData.Addr = reinterpret_cast<uint32_t*>(ref + 1);
      HData.OrigVal = *reinterpret_cast<unsigned int*>(ref + 1);
      HookData.push_back(HData);
      hook = reinterpret_cast<FuncHook2_s*>(ref);
#ifdef WIN32
      VirtualProtect(reinterpret_cast<void*>(ref), 8, PAGE_EXECUTE_READWRITE, &Oldp);
#else
      MProtect_Ex(reinterpret_cast<void*>(ref), 1);
#endif
      hook->_jmp = 0xe9;
      hook->addr = reinterpret_cast<int>(NewAddr)-static_cast<int>(ref)-5;
#ifdef WIN32
      VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
#else
#endif
      ref = FindRef_Jmp(ref, reinterpret_cast<uint32_t>(OrigAddr));
   }

   /*
   ref = 0;
   ref = FindDataRef(ref, reinterpret_cast<uint32_t>(OrigAddr));
   num = 1;
   while (ref)
   {
      DynMsg("Ref %i to %p at %p vt=%i\n", num++, OrigAddr, ref, SearchVTable(reinterpret_cast<void*>(OrigAddr)));
      HData.Addr = reinterpret_cast<uint32_t*>(ref);
      HData.OrigVal = *reinterpret_cast<unsigned int*>(ref);
      HookData.push_back(HData);
      //hook = reinterpret_cast<FuncHook2_s*>(ref);
#ifdef WIN32
      VirtualProtect(reinterpret_cast<void*>(ref), 8, PAGE_EXECUTE_READWRITE, &Oldp);
#else
      MProtect_Ex(reinterpret_cast<void*>(ref), 1);
#endif
      *(reinterpret_cast<uint32_t*>(ref)) = reinterpret_cast<uint32_t>(NewAddr);
      //hook->_jmp = 0xe9;
      //hook->addr = reinterpret_cast<int>(NewAddr)-static_cast<int>(ref)-5;
#ifdef WIN32
      VirtualProtect(OrigAddr, 8, Oldp, &Oldp);
#else
#endif
      ref = FindDataRef(ref, reinterpret_cast<uint32_t>(OrigAddr));
   }
   */
   return HookData.size() - OldSize;
}

uint32_t CDynPatcher::HookVFunctionCall(void **VTable, void *FuncAddr, void *NewAddr)
{
   int OldSize = HookData.size();
   uint32_t VFuncOffset = GetVFuncOffset(VTable, FuncAddr);
   if (VFuncOffset < 0)
   {
      DynErr(false, "Unable to find function %p in vtable %p", FuncAddr, VTable);
      return 0;
   }
   return HookPointer(&VTable[VFuncOffset], NewAddr);
   return 0;
}



uint32_t CDynPatcher::GetVFuncOffset(void **VTable, void *FuncAddr)
{
   void *VFuncAddr;
   int i = 0;
   int ret=-1;
   VFuncAddr = VTable[i];
   while (ContainsAddress(VFuncAddr))
   {
      
      if (VFuncAddr == FuncAddr)
      {
         ret=i;
         printf("Vfunc [%i]=%p\n", i, VFuncAddr);
      }
      else
      {
         printf("Vfunc %i=%p\n", i, VFuncAddr);
      }
      i++;
      VFuncAddr = VTable[i];
   }
   return ret;
}


uint32_t CDynPatcher::HookPointer(void *Addr, void *NewValue)
{
#ifdef WIN32
   DWORD Oldp;
#endif
   
   uint32_t OrigValue = *reinterpret_cast<uint32_t*>(Addr);
   HookData_t HData;
   HData.Addr = reinterpret_cast<uint32_t*>(Addr);
   HData.OrigVal = *reinterpret_cast<uint32_t*>(Addr);
   HookData.push_back(HData);
#ifdef WIN32
   VirtualProtect(Addr, 8, PAGE_EXECUTE_READWRITE, &Oldp);
#else
   MProtect_Ex(Addr, 1);
#endif
   *reinterpret_cast<uint32_t*>(Addr) = reinterpret_cast<uint32_t>(NewValue);
#ifdef WIN32
   VirtualProtect(Addr, 8, Oldp, &Oldp);
#else
#endif
   return OrigValue;
}


void CDynPatcher::UnsetHooks()
{
#ifdef WIN32
   DWORD Oldp;
#endif
   for (auto i = HookData.begin(); i < HookData.end(); ++i)
   {
#ifdef WIN32
      VirtualProtect(reinterpret_cast<void*>((*i).Addr), 8, PAGE_EXECUTE_READWRITE, &Oldp);
#else
      MProtect_Ex(reinterpret_cast<void*>((*i).Addr), 1);
#endif
      *(*i).Addr = (*i).OrigVal;
#ifdef WIN32
      VirtualProtect((*i).Addr, 8, Oldp, &Oldp);
#else
#endif
   }

#ifdef WIN32
#ifdef PARSE_IMPORT_EXPORT
   for (auto i = ImportData.begin(); i < ImportData.end(); ++i)
   {
      (*i)->UnsetHooks();
   }
#endif
   //ImportData.clear();

/*
   for (auto i = ExportData.begin(); i < ExportData.end(); ++i)
   {
      if ((*i)->FuncAddr != reinterpret_cast<uint32_t>(vtr((*i)->pVFuncAddr)))
      {
         Msg("Export %s was hooked!\n", (*i)->FuncName);
         (*i)->pVFuncAddr = reinterpret_cast<uint32_t>(rtv((*i)->FuncAddr));
      }
   }
*/
#endif
}
#ifdef PARSE_IMPORT_EXPORT
void CDynPatcher::DeleteImportData()
{
   for (auto i = ImportData.begin(); i < ImportData.end(); ++i)
   {
      (*i)->UnsetHooks();
      delete (*i);
   }
   ImportData.clear();
}

CImportTable * CDynPatcher::GetImportData(const char *Library)
{
   for (auto i = ImportData.begin(); i < ImportData.end(); ++i)
   {
      if(!_stricmp((*i)->GetName(),Library))
         return (*i);
	  
   }
   return NULL;
}

#endif

uint32_t CDynPatcher::SearchVTable (void* address)
{
   void *vtAddr;
   void *FuncAddr;
   int sum;
   DynMsg("Vtable searching for %p",address);
   for (int i = 0; i < 0xFFF; ++i)
   {
      vtAddr = *reinterpret_cast<void**>(reinterpret_cast<uint32_t>(address)+i);
      if (IsRangeInRdata(reinterpret_cast<uint32_t>(vtAddr),4))
      {
         DynMsg("[%i] %p is in rdata", i, vtAddr);
         sum = 0;
         for (int j = 0; j <= 10; ++j)
         {
            FuncAddr = (reinterpret_cast<void**>(vtAddr))[j];
            if (IsRangeInCode(reinterpret_cast<uint32_t>(FuncAddr), 4))
            {
               DynMsg("[%i][%i] %p is in code", i, j, FuncAddr);
               sum++;
            }
            else
            {
               DynMsg("[%i][%i] %p is not in code", i, j, FuncAddr);
            }
         }

         if (sum > 5)
         {
            DynMsg("Virtual table offset=%i", i);
            return i;
         }
      }
      else
      {
         DynMsg("[%i] %p is not in rdata", i, vtAddr);
      }
   }

   DynMsg("Virtual table was not found. This should not happen");

   return -100;
}

