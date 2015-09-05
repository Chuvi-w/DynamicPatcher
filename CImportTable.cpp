//#include <stdafx.h>
#ifdef _WIN32	//WINDOWS
#include "CImportTable.h"






CImportTable::~CImportTable()
{
      DeleteTable();
}

BOOL CImportTable::ParseImportTable(void *DllBase, PIMAGE_IMPORT_DESCRIPTOR ImpDesc, CSectionData *rdata)
{
   if(!DllBase||!ImpDesc)
      return FALSE;

   NumByName=0;
   NumByOrdinal=0;
   DeleteTable();

   DWORD Base=reinterpret_cast<DWORD>(DllBase);
   PIMAGE_THUNK_DATA pThunkDataName = reinterpret_cast<PIMAGE_THUNK_DATA>(Base+ImpDesc->OriginalFirstThunk);
   PIMAGE_THUNK_DATA pThunkDataFunc = reinterpret_cast<PIMAGE_THUNK_DATA>(Base+ImpDesc->FirstThunk);
   ImportInformation_t *TmpImportInfo;

 
   Name=reinterpret_cast<char*>(Base +ImpDesc->Name);
   printf("Import :%s\n",Name);
   while(pThunkDataName->u1.AddressOfData)
   {
      TmpImportInfo=new ImportInformation_t;
      TmpImportInfo->FuncAddr=pThunkDataFunc->u1.Function;
      TmpImportInfo->pFuncAddr=reinterpret_cast<DWORD*>(&pThunkDataFunc->u1.Function);

      if(!IMAGE_SNAP_BY_ORDINAL(pThunkDataName->u1.Ordinal))
      {
         NumByName++;
         TmpImportInfo->ImpByName=TRUE;
         TmpImportInfo->FuncName=reinterpret_cast<char*>(reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(Base+pThunkDataName->u1.ForwarderString)->Name);
         if (reinterpret_cast<uint32_t>(TmpImportInfo->FuncName) < rdata->GetStart() || reinterpret_cast<uint32_t>(TmpImportInfo->FuncName) > rdata->GetEnd())
         {
            Msg(_T("Error: Import funcion name not in .rdata!\n"));
            delete TmpImportInfo;
            pThunkDataName++;
            pThunkDataFunc++;
            continue;
         }
         TmpImportInfo->Ordinal=0;
        // printf("\t%s = %x (%x)\n",TmpImportInfo->FuncName,TmpImportInfo->FuncAddr,TmpImportInfo->pFuncAddr);
      }
      else
      {
         NumByOrdinal++;
         TmpImportInfo->ImpByName=FALSE;
         TmpImportInfo->FuncName=0;
         TmpImportInfo->Ordinal=IMAGE_ORDINAL(pThunkDataName->u1.Ordinal);
         //printf("\t%i = %x (%x)\n",TmpImportInfo->Ordinal,TmpImportInfo->FuncAddr,TmpImportInfo->pFuncAddr);
      }
      ImpInfo.push_back(TmpImportInfo);  
      pThunkDataName++;
      pThunkDataFunc++;
   }
   if(NumByName&&NumByOrdinal)
   {

      printf("Wow!\n");
   }
   if (ImpInfo.size() == 0)
   {
      Msg(_T("Error: Import section corrupted\n"));
      return FALSE;
   }
   return TRUE;
}

void CImportTable::UnsetHooks()
{
   DWORD OldP;
   for(auto i=ImpInfo.begin();i<ImpInfo.end();++i)
   {
      if((*i)->FuncAddr!=*(*i)->pFuncAddr)
      {
         printf("Imp(%s::%s) was hooked!\n",Name,(*i)->FuncName);
         VirtualProtect((*i)->pFuncAddr,8,PAGE_EXECUTE_READWRITE,&OldP);
         *(*i)->pFuncAddr=(*i)->FuncAddr;
         VirtualProtect((*i)->pFuncAddr,8,OldP,&OldP);
      }
   }
}

void CImportTable::DeleteTable()
{
   UnsetHooks();
   for(auto i=ImpInfo.begin();i<ImpInfo.end();++i)
   {
      delete (*i);
   }

}

BOOL CImportTable::HookFunction(const char *Name,void *NewAddr, void *OrigAddr/*=NULL*/)
{
   if(!Name||!NewAddr)
      return FALSE;
DWORD OldP;
   for(auto i=ImpInfo.begin();i<ImpInfo.end();++i)
   {
      if(!_stricmp((*i)->FuncName,Name))
      {
         VirtualProtect((*i)->pFuncAddr,8,PAGE_EXECUTE_READWRITE,&OldP);
         *(*i)->pFuncAddr=reinterpret_cast<DWORD>(NewAddr);
         VirtualProtect((*i)->pFuncAddr,8,OldP,&OldP);
         if(OrigAddr)
         {
            OrigAddr=reinterpret_cast<void*>((*i)->FuncAddr);
         }
         return TRUE;
      }
   }
   return FALSE;
}

void * CImportTable::GetOriginalAddr(const char *Name)
{
   if(!Name)
      return FALSE;
   for(auto i=ImpInfo.begin();i<ImpInfo.end();++i)
   {
      if(!_stricmp((*i)->FuncName,Name))
      {
            return reinterpret_cast<void*>((*i)->FuncAddr);
      }
   }
   return NULL;
}

BOOL CImportTable::UnsetFunctionHook(const char *Name)
{
  if(!Name)
      return FALSE;
  DWORD OldP;
   for(auto i=ImpInfo.begin();i<ImpInfo.end();++i)
   {
      if(!_stricmp((*i)->FuncName,Name))
      {
         VirtualProtect((*i)->pFuncAddr,8,PAGE_EXECUTE_READWRITE,&OldP);
         *(*i)->pFuncAddr=(*i)->FuncAddr;
         VirtualProtect((*i)->pFuncAddr,8,OldP,&OldP);
         return TRUE;
      }
   }
   return FALSE;
}



#endif