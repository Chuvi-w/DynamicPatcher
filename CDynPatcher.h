#ifndef CDynPatcher_h__
#define CDynPatcher_h__
#include "CSectionData.h"
//#include "CImportTable.h"
#include "DynTypes.h"
#undef min
#undef max
#include <vector>
#define DynErr(crit,...) this->Error(__FILE__,__FUNCTION__,__LINE__,crit,__VA_ARGS__)
#define DynMsg(...) this->Message(__FILE__,__FUNCTION__,__LINE__,__VA_ARGS__)

class FindRef_Mov;
class CDynPatcher
{
public:
   CDynPatcher();
   ~CDynPatcher();
   bool Init(const wchar_t *LibName, bool ForceLoad = false);
   bool Init(const char *LibName,bool ForceLoad=false);
   bool Init(void *FuncAddr);
   template <typename T> 
   bool FindSymbol(const char* sName, T* pSym)
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
		DynMsg("Cant Resolve '%s'\n", sName);
		return false;
	}
   if(pSym)
	   *pSym = reinterpret_cast<T>(csym);
	return true;
}
   uint32_t GetGlobalsBase(){return GlobalsBase;}
   uint32_t FindString(uint32_t StartAddr, const char* str, bool FullMatch=true);
   uint32_t FindDataRef(uint32_t StartAddr, uint32_t RefAddr);
   uint32_t ScanForTemplate_Backward(const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect=NULL);
   uint32_t ScanForTemplate_Forward(const unsigned char* Templ, const unsigned char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect=NULL);
   uint32_t ScanForTemplate_Backward(const char* Templ, const char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect = NULL);
   uint32_t ScanForTemplate_Forward(const char* Templ, const char *Mask, int TemplSize, uint32_t Code_Start, uint32_t Code_Size, CSectionData *pLookupSect = NULL);
   uint32_t FindRef_Mov(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Push(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Call(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Jmp(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t HookFunctionCall(void *OrigAddr, void *NewAddr);
   uint32_t HookVFunctionCall(void **VTable, void *FuncAddr, void *NewAddr);
   //uint32_t HookVFunctionCall(void **VTable, void *FuncAddr, void *NewAddr);
   uint32_t GetVFuncOffset(void **Vtable, void *FuncAddr);
   uint32_t HookPointer(void *Addr, void *NewValue);
   bool     CloseLib();
   void     UnsetHooks();
   
   void* GetBaseHandler() {return DllHandler; }
   bool IsRangeInCode(uint32_t Addr, uint32_t Size)  {bool ret=code.IsRangeInSections(Addr, Size); return ret;}
   bool IsRangeInVdata(uint32_t Addr, uint32_t Size) {bool ret=vdata.IsRangeInSections(Addr, Size); return ret;}
   bool IsRangeInRdata(uint32_t Addr, uint32_t Size) {bool ret=rdata.IsRangeInSections(Addr, Size); return ret;}
   bool ContainsAddress(uint32_t Addr)
   {
	   return (Addr >= reinterpret_cast<uint32_t>(this->DllBase)) && (Addr < (reinterpret_cast<uint32_t>(this->DllBase) + this->DllSize));
   }
   bool ContainsAddress(void* Addr)
   {
	   return ContainsAddress(reinterpret_cast<uint32_t>(Addr));
   }
   uint32_t SearchVTable(void* address);
   CSectionData *GetRdata() {return &rdata; }
#ifdef PARSE_IMPORT_EXPORT
   CImportTable *GetImportData(const char *Library);
#endif
private:
   void Error(const char *File, const char *Func, int Line, bool IsCritical, char *Fmt, ...);
   void Message(const char *File, const char *Func, int Line, char *Fmt, ...);
   
#ifdef WIN32
   template <typename T>
   void* vtr(T addr)
   {
      if(!this->DllHandler)
         return 0;
      return reinterpret_cast<void*>(reinterpret_cast<uint32_t>(this->DllHandler)+reinterpret_cast<uint32_t>(reinterpret_cast<void*>(addr)));
   }
   template <typename R,typename T>
   R vtrt(T addr)
   {
      if(!this->DllHandler)
         return 0;
      return reinterpret_cast<R>(reinterpret_cast<uint32_t>(this->DllHandler)+reinterpret_cast<uint32_t>(reinterpret_cast<void*>(addr)));
   }
   template <typename T>
   void* rtv(T addr)
   {
      if (!this->DllHandler)
         return 0;
      return reinterpret_cast<void*>(reinterpret_cast<uint32_t>(reinterpret_cast<void*>(addr)) - reinterpret_cast<uint32_t>(this->DllHandler));
   }
   template <typename R, typename T>
   R rtvt(T addr)
   {
      if (!this->DllHandler)
         return 0;
      return reinterpret_cast<R>(reinterpret_cast<uint32_t>(reinterpret_cast<void*>(addr)) - reinterpret_cast<uint32_t>(this->DllHandler));
   }
   bool ParseGenericDllData_PE();
#else
   bool ParseGenericDllData_ELF(void* FileData, uint32_t FileSize);
   void* LocateLib(const char* libname);
   uint32_t GetBaseLen(void *baseAddress);
   bool MProtect_Ex(void *addr, int npages);
#endif
   bool LoadLib(const char *LibName, bool ForceLoad=false);
#ifdef PARSE_IMPORT_EXPORT
   void     DeleteImportData();
   
#endif

   
   
private:
   bool bSelfLoaded;
   void *DllHandler;
	void* DllBase;

   uint32_t DllSize;
	CSectionData code;
	CSectionData rdata;
	CSectionData vdata;

	uint32_t GlobalsBase;
#ifdef WIN32
#ifdef PARSE_IMPORT_EXPORT
   std::vector <CImportTable*> ImportData;
   typedef struct ExportData_s
   {
      const char *FuncName;
      uint32_t FuncAddr;
      uint32_t pVFuncAddr;
   }ExportData_t;
   std::vector <ExportData_t*> ExportData;
#endif
#else

	CSectionData sect_got;
	CSectionData sect_plt;
#endif
   typedef struct HookData_s
   {
      uint32_t *Addr;
      uint32_t OrigVal;
   }HookData_t;
   std::vector <HookData_t>HookData;
   char *szLibName;


      

};



#ifdef WIN32
#define FASTCALL __fastcall
#define THISCALL __thiscall
#define C_FUNC_FASTCALL(ret,Func,...) ret __fastcall Func(void *pThis,void *pVptr,__VA_ARGS__)
#define C_CALL_FASTCALL(Func,This,...) Func(reinterpret_cast<void*>(This),NULL,__VA_ARGS__)
#define C_TYPE_FASTCALL(ret, Class,Func,...) typedef ret(__fastcall *pfnF##Class##Func)(void *pThis, void *pVptr, ...);
#else
#define FASTCALL 
#define THISCALL
#define C_FUNC_FASTCALL(ret,Func,...) ret  Func(void *pThis,__VA_ARGS__)
#define C_CALL_FASTCALL(Func,This,...) Func(reinterpret_cast<void*>(This),__VA_ARGS__)
#define C_TYPE_FASTCALL(ret, Class,Func,...) typedef ret(*pfnF##Class##Func)(void *pThis,...);
#endif

#define C_FUNC_UNION(ret,Class,Func,...)\
C_TYPE_FASTCALL(ret,Class,Func,__VA_ARGS__);\
typedef ret (THISCALL Class::*pfnT##Class##Func)(__VA_ARGS__);\
union Class##Func##Data\
{\
   void             *v;\
   pfnT##Class##Func t;\
	pfnF##Class##Func f;\
};\


#endif // CDynPatcher_h__
