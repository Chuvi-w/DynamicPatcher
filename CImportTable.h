#ifndef CImportTable_h__
#define CImportTable_h__
#ifdef WIN32	//WINDOWS
#include <winnt.h>
#include <vector>
#include "DynTypes.h"
#include "CSectionData.h"
class CImportTable
{
public:
   ~CImportTable();
   BOOL ParseImportTable(void *DllBase, PIMAGE_IMPORT_DESCRIPTOR ImpDesc, CSectionData *rdata);
   void UnsetHooks();
   const char* GetName(){return const_cast<const char*>(Name);}
   BOOL HookFunction(const char *Name,void *NewAddr, void *OldAddr=NULL);
   void *GetOriginalAddr(const char *Name);
   BOOL UnsetFunctionHook(const char *Name);
private:
   void DeleteTable();
   typedef struct ImportInformation_s
   {
      BOOL ImpByName;
      WORD Ordinal;
      const char *FuncName;
      DWORD FuncAddr;
      DWORD *pFuncAddr;
   }ImportInformation_t;

   char *Name;
   int NumByName;
   int NumByOrdinal;
   std::vector <ImportInformation_t*> ImpInfo;
};
#endif
#endif // CImportTable_h__
