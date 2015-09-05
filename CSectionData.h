#ifndef CSectionData_h__
#define CSectionData_h__

#include "DynTypes.h"


class CDynPatcher;

class CSectionData
{
public:
   CSectionData();
   CSectionData(uint32_t Start, uint32_t Size, CDynPatcher &Parent);
   ~CSectionData();
   bool Add(uint32_t Start, uint32_t Size, CDynPatcher *Parent=NULL);
   uint32_t GetStart(){return start;}
   uint32_t GetEnd(){return end;}
   bool IsValid(){return bValid;}
   bool IsEmpty(){return bEmpty;}
   CSectionData *GetNext(){return Next;}
   bool Sort();

   uint32_t FindRef(uint32_t StartAddr, uint32_t RefAddress, uint8_t PrefixValue, bool Relative);
   uint32_t FindRef(uint32_t StartAddr, uint32_t RefAddress, uint16_t PrefixValue, bool Relative);
   bool IsRangeInSections(uint32_t Addr, uint32_t Size);
   uint32_t FindRef_Mov(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Push(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Call(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindRef_Jmp(uint32_t StartAddr, uint32_t RefAddress);
   uint32_t FindJumpToPtr(uint32_t ptr_addr);
   uint32_t FindString(const char* str, uint32_t addr, bool FullMatch=true);
   uint32_t FindDataRef(uint32_t RefAddr, uint32_t addr);
   static const char* GetFileName(const char *fpath);
private:
   uint32_t start;
   uint32_t end;
   CSectionData *Next;
   CDynPatcher *Parent;
   bool bValid;
   bool bEmpty;

private:
   bool Add(CSectionData *sData);
   void Error(const char *File, const char *Func, int Line, bool IsCritical, char *Fmt, ...);
   void Message(const char *File, const char *Func, int Line, char *Fmt, ...);
};
#endif // CSectionData_h__
