#ifdef _WIN32
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
#define MAX_PATH FILENAME_MAX
#endif

#include "CSectionData.h"
#include "CDynPatcher.h"

#define DebMsg(msg,...) Msg("[%s(%i)]"msg,__FUNCTION__,__LINE__,__VA_ARGS__)
CSectionData::CSectionData()
{
   this->start=0;
   this->Parent=0;
   this->end=0;
   this->Next=0;
   this->bValid=false;
   this->bEmpty=true;
}

CSectionData::CSectionData(uint32_t Start, uint32_t Size, CDynPatcher &Parent)
{
   this->start=Start;
   this->Parent=&Parent;
   this->end=this->start+Size;
   this->Next=0;
   if(Start&&Size)
   {
      bValid=true;
   }
   else
   {
      bValid=false;
   }
   this->bEmpty=false;
}

CSectionData::~CSectionData()
{
   if(Next)
      delete Next;

}

bool CSectionData::Add(uint32_t Start, uint32_t Size, CDynPatcher *pParent)
{
   if(bEmpty)
   {
      DynMsg("New: Start=%x Size=%x, pParent=%x ",Start,Size,pParent);
      this->start=Start;
      this->Parent=pParent;
      this->end=this->start+Size;
      this->Next=0;
      
      if(pParent&&Start&&Size)
      {
		  DynMsg("Valid %s\n", "");
         bValid=true;
      }
      else
      {
		  DynMsg("Invalid %s\n", "");
         bValid=false;
      }
      this->bEmpty=false;
      return bValid;
   }
   
   if(!this->Parent||(this->Parent&&pParent&&Parent!=pParent))
   {
      return false;
   }
   CSectionData *Sect=this;
   while(Sect->Next)
   {
      Sect=Sect->Next;
   }
   return Sect->Add(new CSectionData(Start,Size,*this->Parent));
}

bool CSectionData::Add(CSectionData *sData)
{
   if(this->Next)
   {
      return false;
   }
   if(sData->IsValid())
   {
      this->Next=sData;
      return true;
   }
   
   return false;
}


uint32_t CSectionData::FindRef(uint32_t StartAddr, uint32_t RefAddress, uint8_t PrefixValue, bool Relative) 
{
	#pragma pack(push ,1)
	struct prefix8ref_t 
   {
		uint8_t prefix;
		uint32_t Addr;
	};
	#pragma pack(pop)

	prefix8ref_t *CurInstr;

	if (StartAddr == 0)
		StartAddr = this->start;
	else
		StartAddr++;

	size_t EndAddr = this->end - sizeof(prefix8ref_t);
	while (StartAddr < EndAddr) 
	{
		CurInstr = (prefix8ref_t*) StartAddr;
		if (CurInstr->prefix == PrefixValue) 
		{
			if (!Relative) 
			{
				//ALERT(at_logged, "%s: InstrAddr=%x\n")
				if (CurInstr->Addr == RefAddress)
					return StartAddr;
			} 
			else 
			{
				if ( (StartAddr + 5 + CurInstr->Addr) == RefAddress)
					return StartAddr;
			}
		}
		StartAddr++;
	}
	return 0;
}

uint32_t CSectionData::FindRef(uint32_t StartAddr, uint32_t RefAddress, uint16_t PrefixValue, bool Relative) 
{
	#pragma pack(push ,1)
	struct prefix16ref_t 
   {
		uint16_t prefix;
		uint32_t Addr;
	};
	#pragma pack(pop)

	prefix16ref_t *CurInstr;

	if (StartAddr == 0)
		StartAddr = this->start;
	else
		StartAddr++;

	
	size_t EndAddr = this->end - sizeof(prefix16ref_t);

	while (StartAddr < EndAddr) 
   {
		CurInstr = (prefix16ref_t*) StartAddr;
		if (CurInstr->prefix == PrefixValue) 
      {
			if (!Relative) 
         {
				if (CurInstr->Addr == RefAddress)
					return StartAddr;
			} else 
         {
				if ( (StartAddr + 6 + CurInstr->Addr) == RefAddress)
					return StartAddr;
			}
		}
		StartAddr++;
	}
	return 0;
}


uint32_t CSectionData::FindRef_Mov(uint32_t StartAddr, uint32_t RefAddress)
{
    uint32_t addr;
    addr=FindRef(StartAddr, RefAddress, static_cast<uint8_t>(0xB8), false); //mov     eax, offset RefAddress
    if(addr)
    {
        return addr;
    }
    addr=FindRef(StartAddr, RefAddress, static_cast<uint8_t>(0xB9), false);//mov     ecx, offset RefAddress
    if(addr)
    {
        return addr;
    }
    
    return 0;
}


uint32_t CSectionData::FindRef_Push(uint32_t StartAddr, uint32_t RefAddress) 
{
	return FindRef(StartAddr, RefAddress, static_cast<uint8_t>(0x68), false);
}

uint32_t CSectionData::FindRef_Call(uint32_t StartAddr, uint32_t RefAddress)
{
   return FindRef(StartAddr, RefAddress, static_cast<uint8_t>(0xE8), true);
}

uint32_t CSectionData::FindRef_Jmp(uint32_t StartAddr, uint32_t RefAddress)
{
   return FindRef(StartAddr, RefAddress, static_cast<uint8_t>(0xE9), true);
}

bool CSectionData::IsRangeInSections(uint32_t Addr, uint32_t Size) 
{
	uint32_t Addr_End = Addr + Size - 1;
   	CSectionData *sdata=this;
	while (sdata) 
   	{
		if (Addr >= sdata->start && Addr_End <= sdata->end)
			return true;
		sdata = sdata->Next;
	}
	return false;
}


uint32_t CSectionData::FindJumpToPtr(uint32_t ptr_addr)
{
	uint32_t j_addr = 0;
	uint32_t tmp;

	/* Try search for "jmp [???]" instruction
		FF25 ???????? jmp [????????]
	*/

	j_addr = FindRef(j_addr, ptr_addr, static_cast<uint16_t>(0x25FF), false);
	if (j_addr) 
   {
		return j_addr;
	}

	/* If nothing found, try search "jmp [ebx+?]" 
		FFA3 ???????? jmp [ebx+??]
	*/

	tmp = ptr_addr - Parent->GetGlobalsBase();
   j_addr = FindRef(j_addr, tmp, static_cast<uint16_t>(0xA3FF), false);
	if (j_addr) 
   {
		return j_addr;
	}

	return 0;
}



uint32_t CSectionData::FindString(const char* str, uint32_t addr, bool FullMatch) 
{
	int slen = strlen(str);
	if (FullMatch)
		slen += 1;
	char* cs_end = (char*) (this->end - slen);
	char* cs = (char*) addr;
	
	if (cs >= cs_end)
		return NULL;

	while (memcmp(str, cs, slen)) 
   {
		if (cs >= cs_end)
			return NULL;
		cs++;
	}
	return (uint32_t)cs;
}

uint32_t CSectionData::FindDataRef(uint32_t RefAddr, uint32_t addr) 
{
	uint32_t* cs_end = (uint32_t*) (this->end - 4);
	uint32_t* cs = (uint32_t*) addr;
	if ((uint32_t)cs < this->start)
		cs = (uint32_t*)this->start;
	
	if (cs >= cs_end)
		return NULL;

	while (*cs != RefAddr) {
		if (cs >= cs_end)
			return NULL;
		cs = (uint32_t*) ((size_t)cs + 1);
	}
	return (uint32_t)cs;
}

bool CSectionData::Sort()
{
	//we need to sort sections (using bubble sorting)
	bool Have_Changes = true;
	while (Have_Changes) 
   {
		Have_Changes = false;
		CSectionData *prev = NULL;
		CSectionData *cur = this;
		while (cur) 
      {
			if (prev) 
         {
				if (prev->start > cur->start) 
            {
					size_t tmp;
					tmp = prev->start; prev->start = cur->start; cur->start = tmp;
					tmp = prev->end; prev->end = cur->end; cur->end = tmp;
					Have_Changes = true;
				}
			}
			prev = cur;
			cur = cur->Next;
		}
	}
   return true;
}


void CSectionData::Error(const char *File, const char *Func, int Line, bool IsCritical, char *Fmt, ...)
{
   static char Buff[0x1000];
   int len = 0;

   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "[CSectionData] %serror", IsCritical ? "critical" : "");
   if (File&&Func&&Line&&strlen(File) < MAX_PATH&&strlen(Func) < 300)
   {
      len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, " at %s(%s:%i)", GetFileName(File), Func, Line);
   }
   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, ":");
   va_list marker;
   if (!Fmt)
   {
      len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "(NO DESCRIPTION)\r\n");
   }
   else
   {
      va_start(marker, Fmt);
      len += _vsnprintf(&Buff[len], sizeof(Buff) - len - 1, Fmt, marker);
   }
   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "\r\n");
   printf("%s", Buff);
   if (IsCritical)
   {
#ifdef WIN32
      __asm{int 3};

      if (!IsDebuggerPresent())
      {
         exit(0);
      }
#else
      exit(0);
#endif
   }
}

void CSectionData::Message(const char *File, const char *Func, int Line, char *Fmt, ...)
{
   static char Buff[0x1000];
   int len = 0;

   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "[CSectionData]");
   if (File&&Func&&Line&&strlen(File) < MAX_PATH&&strlen(Func) < 300)
   {
      len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, " at %s(%s:%i)", GetFileName(File), Func, Line);
   }
   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, ":");
   va_list marker;
   if (!Fmt)
   {
      len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "(NO DESCRIPTION)\r\n");
   }
   else
   {
      va_start(marker, Fmt);
      len += _vsnprintf(&Buff[len], sizeof(Buff) - len - 1, Fmt, marker);
   }
   len += _snprintf(&Buff[len], sizeof(Buff) - len - 1, "\r\n");
   printf("%s", Buff);
}


const char* CSectionData::GetFileName(const char *fpath)
{
   int sl = strlen(fpath);
   const char *cp = fpath + sl;
   while (size_t(cp) > size_t(fpath))
   {
      if (*cp == '\\' || *cp == '/')
      {
         return cp + 1;
      }
      cp--;
   }
   return cp;
}
