#include "CoffObjectLoader.h"

#include <windows.h>
#include "Hunk.h"
#include "HunkList.h"
#include "Symbol.h"
#include "StringMisc.h"

#pragma pack ( push, 1 )
#define CV_SIGNATURE_C7         1L  // First explicit signature
#define CV_SIGNATURE_C11        2L  // C11 (vc5.x) 32-bit types
#define CV_SIGNATURE_C13        4L  // C13 (vc7.x) zero terminated names

#define CV_LINES_HAVE_COLUMNS 0x0001

typedef          long   CV_off32_t;

typedef struct SYMTYPE {
  unsigned short      reclen;     // Record length
  unsigned short      rectyp;     // Record type
  //char                data[CV_ZEROLEN];
} SYMTYPE;

struct CV_Line_t 
{
  unsigned long   offset;             // Offset to start of code bytes for line number
  unsigned long   linenumStart : 24;    // line where statement/expression starts
  unsigned long   deltaLineEnd : 7;     // delta to line where statement ends (optional)
  unsigned long   fStatement : 1;       // true if a statement linenumber, else an expression line num
};

enum CV_SourceChksum_t {
  CHKSUM_TYPE_NONE = 0,        // indicates no checksum is available
  CHKSUM_TYPE_MD5,
  CHKSUM_TYPE_SHA1,
  CHKSUM_TYPE_SHA_256,
};

typedef unsigned short CV_columnpos_t;    // byte offset in a source line

struct CV_Column_t 
{
  CV_columnpos_t offColumnStart;
  CV_columnpos_t offColumnEnd;
};

enum DEBUG_S_SUBSECTION_TYPE 
{
  DEBUG_S_IGNORE = 0x80000000,    // if this bit is set in a subsection type then ignore the subsection contents

  DEBUG_S_SYMBOLS = 0xf1,
  DEBUG_S_LINES,
  DEBUG_S_STRINGTABLE,
  DEBUG_S_FILECHKSMS,
  DEBUG_S_FRAMEDATA,
  DEBUG_S_INLINEELINES,
  DEBUG_S_CROSSSCOPEIMPORTS,
  DEBUG_S_CROSSSCOPEEXPORTS,

  DEBUG_S_IL_LINES,
  DEBUG_S_FUNC_MDTOKEN_MAP,
  DEBUG_S_TYPE_MDTOKEN_MAP,
  DEBUG_S_MERGED_ASSEMBLYINPUT,

  DEBUG_S_COFF_SYMBOL_RVA,
};

struct CV_DebugSSubsectionHeader_t 
{
  enum DEBUG_S_SUBSECTION_TYPE type;
  CV_off32_t                   cbLen;
};

struct CV_DebugSLinesHeader_t 
{
  CV_off32_t     offCon;
  unsigned short segCon;
  unsigned short flags;
  CV_off32_t     cbCon;
};

struct CV_DebugSLinesFileBlockHeader_t 
{
  CV_off32_t     offFile;
  CV_off32_t     nLines;
  CV_off32_t     cbBlock;
  // CV_Line_t      lines[nLines];
  // CV_Column_t    columns[nColumns];
};

//  Symbol definitions

typedef enum SYM_ENUM_e {
  S_COMPILE = 0x0001,  // Compile flags symbol
  S_REGISTER_16t = 0x0002,  // Register variable
  S_CONSTANT_16t = 0x0003,  // constant symbol
  S_UDT_16t = 0x0004,  // User defined type
  S_SSEARCH = 0x0005,  // Start Search
  S_END = 0x0006,  // Block, procedure, "with" or thunk end
  S_SKIP = 0x0007,  // Reserve symbol space in $$Symbols table
  S_CVRESERVE = 0x0008,  // Reserved symbol for CV internal use
  S_OBJNAME_ST = 0x0009,  // path to object file name
  S_ENDARG = 0x000a,  // end of argument/return list
  S_COBOLUDT_16t = 0x000b,  // special UDT for cobol that does not symbol pack
  S_MANYREG_16t = 0x000c,  // multiple register variable
  S_RETURN = 0x000d,  // return description symbol
  S_ENTRYTHIS = 0x000e,  // description of this pointer on entry

  S_BPREL16 = 0x0100,  // BP-relative
  S_LDATA16 = 0x0101,  // Module-local symbol
  S_GDATA16 = 0x0102,  // Global data symbol
  S_PUB16 = 0x0103,  // a public symbol
  S_LPROC16 = 0x0104,  // Local procedure start
  S_GPROC16 = 0x0105,  // Global procedure start
  S_THUNK16 = 0x0106,  // Thunk Start
  S_BLOCK16 = 0x0107,  // block start
  S_WITH16 = 0x0108,  // with start
  S_LABEL16 = 0x0109,  // code label
  S_CEXMODEL16 = 0x010a,  // change execution model
  S_VFTABLE16 = 0x010b,  // address of virtual function table
  S_REGREL16 = 0x010c,  // register relative address

  S_BPREL32_16t = 0x0200,  // BP-relative
  S_LDATA32_16t = 0x0201,  // Module-local symbol
  S_GDATA32_16t = 0x0202,  // Global data symbol
  S_PUB32_16t = 0x0203,  // a public symbol (CV internal reserved)
  S_LPROC32_16t = 0x0204,  // Local procedure start
  S_GPROC32_16t = 0x0205,  // Global procedure start
  S_THUNK32_ST = 0x0206,  // Thunk Start
  S_BLOCK32_ST = 0x0207,  // block start
  S_WITH32_ST = 0x0208,  // with start
  S_LABEL32_ST = 0x0209,  // code label
  S_CEXMODEL32 = 0x020a,  // change execution model
  S_VFTABLE32_16t = 0x020b,  // address of virtual function table
  S_REGREL32_16t = 0x020c,  // register relative address
  S_LTHREAD32_16t = 0x020d,  // local thread storage
  S_GTHREAD32_16t = 0x020e,  // global thread storage
  S_SLINK32 = 0x020f,  // static link for MIPS EH implementation

  S_LPROCMIPS_16t = 0x0300,  // Local procedure start
  S_GPROCMIPS_16t = 0x0301,  // Global procedure start

  // if these ref symbols have names following then the names are in ST format
  S_PROCREF_ST = 0x0400,  // Reference to a procedure
  S_DATAREF_ST = 0x0401,  // Reference to data
  S_ALIGN = 0x0402,  // Used for page alignment of symbols

  S_LPROCREF_ST = 0x0403,  // Local Reference to a procedure
  S_OEM = 0x0404,  // OEM defined symbol

  // sym records with 32-bit types embedded instead of 16-bit
  // all have 0x1000 bit set for easy identification
  // only do the 32-bit target versions since we don't really
  // care about 16-bit ones anymore.
  S_TI16_MAX = 0x1000,

  S_REGISTER_ST = 0x1001,  // Register variable
  S_CONSTANT_ST = 0x1002,  // constant symbol
  S_UDT_ST = 0x1003,  // User defined type
  S_COBOLUDT_ST = 0x1004,  // special UDT for cobol that does not symbol pack
  S_MANYREG_ST = 0x1005,  // multiple register variable
  S_BPREL32_ST = 0x1006,  // BP-relative
  S_LDATA32_ST = 0x1007,  // Module-local symbol
  S_GDATA32_ST = 0x1008,  // Global data symbol
  S_PUB32_ST = 0x1009,  // a public symbol (CV internal reserved)
  S_LPROC32_ST = 0x100a,  // Local procedure start
  S_GPROC32_ST = 0x100b,  // Global procedure start
  S_VFTABLE32 = 0x100c,  // address of virtual function table
  S_REGREL32_ST = 0x100d,  // register relative address
  S_LTHREAD32_ST = 0x100e,  // local thread storage
  S_GTHREAD32_ST = 0x100f,  // global thread storage

  S_LPROCMIPS_ST = 0x1010,  // Local procedure start
  S_GPROCMIPS_ST = 0x1011,  // Global procedure start

  S_FRAMEPROC = 0x1012,  // extra frame and proc information
  S_COMPILE2_ST = 0x1013,  // extended compile flags and info

  // new symbols necessary for 16-bit enumerates of IA64 registers
  // and IA64 specific symbols

  S_MANYREG2_ST = 0x1014,  // multiple register variable
  S_LPROCIA64_ST = 0x1015,  // Local procedure start (IA64)
  S_GPROCIA64_ST = 0x1016,  // Global procedure start (IA64)

  // Local symbols for IL
  S_LOCALSLOT_ST = 0x1017,  // local IL sym with field for local slot index
  S_PARAMSLOT_ST = 0x1018,  // local IL sym with field for parameter slot index

  S_ANNOTATION = 0x1019,  // Annotation string literals

  // symbols to support managed code debugging
  S_GMANPROC_ST = 0x101a,  // Global proc
  S_LMANPROC_ST = 0x101b,  // Local proc
  S_RESERVED1 = 0x101c,  // reserved
  S_RESERVED2 = 0x101d,  // reserved
  S_RESERVED3 = 0x101e,  // reserved
  S_RESERVED4 = 0x101f,  // reserved
  S_LMANDATA_ST = 0x1020,
  S_GMANDATA_ST = 0x1021,
  S_MANFRAMEREL_ST = 0x1022,
  S_MANREGISTER_ST = 0x1023,
  S_MANSLOT_ST = 0x1024,
  S_MANMANYREG_ST = 0x1025,
  S_MANREGREL_ST = 0x1026,
  S_MANMANYREG2_ST = 0x1027,
  S_MANTYPREF = 0x1028,  // Index for type referenced by name from metadata
  S_UNAMESPACE_ST = 0x1029,  // Using namespace

  // Symbols w/ SZ name fields. All name fields contain utf8 encoded strings.
  S_ST_MAX = 0x1100,  // starting point for SZ name symbols

  S_OBJNAME = 0x1101,  // path to object file name
  S_THUNK32 = 0x1102,  // Thunk Start
  S_BLOCK32 = 0x1103,  // block start
  S_WITH32 = 0x1104,  // with start
  S_LABEL32 = 0x1105,  // code label
  S_REGISTER = 0x1106,  // Register variable
  S_CONSTANT = 0x1107,  // constant symbol
  S_UDT = 0x1108,  // User defined type
  S_COBOLUDT = 0x1109,  // special UDT for cobol that does not symbol pack
  S_MANYREG = 0x110a,  // multiple register variable
  S_BPREL32 = 0x110b,  // BP-relative
  S_LDATA32 = 0x110c,  // Module-local symbol
  S_GDATA32 = 0x110d,  // Global data symbol
  S_PUB32 = 0x110e,  // a public symbol (CV internal reserved)
  S_LPROC32 = 0x110f,  // Local procedure start
  S_GPROC32 = 0x1110,  // Global procedure start
  S_REGREL32 = 0x1111,  // register relative address
  S_LTHREAD32 = 0x1112,  // local thread storage
  S_GTHREAD32 = 0x1113,  // global thread storage

  S_LPROCMIPS = 0x1114,  // Local procedure start
  S_GPROCMIPS = 0x1115,  // Global procedure start
  S_COMPILE2 = 0x1116,  // extended compile flags and info
  S_MANYREG2 = 0x1117,  // multiple register variable
  S_LPROCIA64 = 0x1118,  // Local procedure start (IA64)
  S_GPROCIA64 = 0x1119,  // Global procedure start (IA64)
  S_LOCALSLOT = 0x111a,  // local IL sym with field for local slot index
  S_SLOT = S_LOCALSLOT,  // alias for LOCALSLOT
  S_PARAMSLOT = 0x111b,  // local IL sym with field for parameter slot index

  // symbols to support managed code debugging
  S_LMANDATA = 0x111c,
  S_GMANDATA = 0x111d,
  S_MANFRAMEREL = 0x111e,
  S_MANREGISTER = 0x111f,
  S_MANSLOT = 0x1120,
  S_MANMANYREG = 0x1121,
  S_MANREGREL = 0x1122,
  S_MANMANYREG2 = 0x1123,
  S_UNAMESPACE = 0x1124,  // Using namespace

  // ref symbols with name fields
  S_PROCREF = 0x1125,  // Reference to a procedure
  S_DATAREF = 0x1126,  // Reference to data
  S_LPROCREF = 0x1127,  // Local Reference to a procedure
  S_ANNOTATIONREF = 0x1128,  // Reference to an S_ANNOTATION symbol
  S_TOKENREF = 0x1129,  // Reference to one of the many MANPROCSYM's

  // continuation of managed symbols
  S_GMANPROC = 0x112a,  // Global proc
  S_LMANPROC = 0x112b,  // Local proc

  // short, light-weight thunks
  S_TRAMPOLINE = 0x112c,  // trampoline thunks
  S_MANCONSTANT = 0x112d,  // constants with metadata type info

  // native attributed local/parms
  S_ATTR_FRAMEREL = 0x112e,  // relative to virtual frame ptr
  S_ATTR_REGISTER = 0x112f,  // stored in a register
  S_ATTR_REGREL = 0x1130,  // relative to register (alternate frame ptr)
  S_ATTR_MANYREG = 0x1131,  // stored in >1 register

  // Separated code (from the compiler) support
  S_SEPCODE = 0x1132,

  S_LOCAL_2005 = 0x1133,  // defines a local symbol in optimized code
  S_DEFRANGE_2005 = 0x1134,  // defines a single range of addresses in which symbol can be evaluated
  S_DEFRANGE2_2005 = 0x1135,  // defines ranges of addresses in which symbol can be evaluated

  S_SECTION = 0x1136,  // A COFF section in a PE executable
  S_COFFGROUP = 0x1137,  // A COFF group
  S_EXPORT = 0x1138,  // A export

  S_CALLSITEINFO = 0x1139,  // Indirect call site information
  S_FRAMECOOKIE = 0x113a,  // Security cookie information

  S_DISCARDED = 0x113b,  // Discarded by LINK /OPT:REF (experimental, see richards)

  S_COMPILE3 = 0x113c,  // Replacement for S_COMPILE2
  S_ENVBLOCK = 0x113d,  // Environment block split off from S_COMPILE2

  S_LOCAL = 0x113e,  // defines a local symbol in optimized code
  S_DEFRANGE = 0x113f,  // defines a single range of addresses in which symbol can be evaluated
  S_DEFRANGE_SUBFIELD = 0x1140,           // ranges for a subfield

  S_DEFRANGE_REGISTER = 0x1141,           // ranges for en-registered symbol
  S_DEFRANGE_FRAMEPOINTER_REL = 0x1142,   // range for stack symbol.
  S_DEFRANGE_SUBFIELD_REGISTER = 0x1143,  // ranges for en-registered field of symbol
  S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144, // range for stack symbol span valid full scope of function body, gap might apply.
  S_DEFRANGE_REGISTER_REL = 0x1145, // range for symbol address as register + offset.

  // S_PROC symbols that reference ID instead of type
  S_LPROC32_ID = 0x1146,
  S_GPROC32_ID = 0x1147,
  S_LPROCMIPS_ID = 0x1148,
  S_GPROCMIPS_ID = 0x1149,
  S_LPROCIA64_ID = 0x114a,
  S_GPROCIA64_ID = 0x114b,

  S_BUILDINFO = 0x114c, // build information.
  S_INLINESITE = 0x114d, // inlined function callsite.
  S_INLINESITE_END = 0x114e,
  S_PROC_ID_END = 0x114f,

  S_DEFRANGE_HLSL = 0x1150,
  S_GDATA_HLSL = 0x1151,
  S_LDATA_HLSL = 0x1152,

  S_FILESTATIC = 0x1153,

#if defined(CC_DP_CXX) && CC_DP_CXX

  S_LOCAL_DPC_GROUPSHARED = 0x1154, // DPC groupshared variable
  S_LPROC32_DPC = 0x1155, // DPC local procedure start
  S_LPROC32_DPC_ID = 0x1156,
  S_DEFRANGE_DPC_PTR_TAG = 0x1157, // DPC pointer tag definition range
  S_DPC_SYM_TAG_MAP = 0x1158, // DPC pointer tag value to symbol record map

#endif // CC_DP_CXX

  S_ARMSWITCHTABLE = 0x1159,
  S_CALLEES = 0x115a,
  S_CALLERS = 0x115b,
  S_POGODATA = 0x115c,
  S_INLINESITE2 = 0x115d,      // extended inline site information

  S_HEAPALLOCSITE = 0x115e,    // heap allocation site

  S_MOD_TYPEREF = 0x115f,      // only generated at link time

  S_REF_MINIPDB = 0x1160,      // only generated at link time for mini PDB
  S_PDBMAP = 0x1161,      // only generated at link time for mini PDB

  S_GDATA_HLSL32 = 0x1162,
  S_LDATA_HLSL32 = 0x1163,

  S_GDATA_HLSL32_EX = 0x1164,
  S_LDATA_HLSL32_EX = 0x1165,

  S_RECTYPE_MAX,               // one greater than last
  S_RECTYPE_LAST = S_RECTYPE_MAX - 1,
  S_RECTYPE_PAD = S_RECTYPE_MAX + 0x100 // Used *only* to verify symbol record types so that current PDB code can potentially read
  // future PDBs (assuming no format change, etc).

} SYM_ENUM_e;

typedef unsigned long   CV_tkn_t;
typedef unsigned long   CV_uoff32_t;
typedef unsigned long   CV_typ_t;

typedef struct CV_PROCFLAGS {
  union {
    unsigned char   bAll;
    unsigned char   grfAll;
    struct {
      unsigned char CV_PFLAG_NOFPO : 1; // frame pointer present
      unsigned char CV_PFLAG_INT : 1; // interrupt return
      unsigned char CV_PFLAG_FAR : 1; // far return
      unsigned char CV_PFLAG_NEVER : 1; // function does not return
      unsigned char CV_PFLAG_NOTREACHED : 1; // label isn't fallen into
      unsigned char CV_PFLAG_CUST_CALL : 1; // custom calling convention
      unsigned char CV_PFLAG_NOINLINE : 1; // function marked as noinline
      unsigned char CV_PFLAG_OPTDBGINFO : 1; // function has debug information for optimized code
    };
  };
} CV_PROCFLAGS;

typedef struct PROCSYM32 {
  unsigned short  reclen;     // Record length
  unsigned short  rectyp;     // S_GPROC32, S_LPROC32, S_GPROC32_ID, S_LPROC32_ID, S_LPROC32_DPC or S_LPROC32_DPC_ID
  unsigned long   pParent;    // pointer to the parent
  unsigned long   pEnd;       // pointer to this blocks end
  unsigned long   pNext;      // pointer to next symbol
  unsigned long   len;        // Proc length
  unsigned long   DbgStart;   // Debug start offset
  unsigned long   DbgEnd;     // Debug end offset
  CV_typ_t        typind;     // Type index or ID
  CV_uoff32_t     off;
  unsigned short  seg;
  CV_PROCFLAGS    flags;      // Proc flags
  unsigned char   name[1];    // Length-prefixed name
} PROCSYM32;

#pragma pack(pop)


using namespace std;

static int GetAlignmentBitsFromCharacteristics(int chars) {
	return max(((chars & 0x00F00000)>>20) - 1, 0);
}

static string GetSectionName(const IMAGE_SECTION_HEADER* section, const char* stringTable) {
	char tmp[9]; tmp[8] = 0;
	memcpy(tmp, section->Name, 8*sizeof(char));

	if(section->Name[0] == '/') {
		int offset = atoi(&tmp[1]);
		return string(&stringTable[offset]);
	} else {
		return tmp;
	}

}

static string GetSymbolName(const IMAGE_SYMBOL* symbol, const char* stringTable) {
	if(symbol->N.Name.Short == 0) {	// Long name
		return &stringTable[symbol->N.Name.Long];
	} else {	// Short name
		char tmp[9]; tmp[8] = 0;
		memcpy(tmp, symbol->N.ShortName, 8);
		return tmp;
	}
}

static string StripNumeral(const string& s) {
	int idx = (int)s.size()-1;
	while(idx >= 0 && s[idx] != '|') idx--;
	if (idx == 0) return s;
	return s.substr(0, idx);
}

CoffObjectLoader::~CoffObjectLoader() {
}

bool CoffObjectLoader::Clicks(const char* data, int size) const {
	//TODO: Implement a safer check
	return *(unsigned short*)data == IMAGE_FILE_MACHINE_I386;
}

std::vector<LineInfo> GetLineInfo(size_t cbTable, unsigned char* debugS, int ib)
{
  struct Header
  {
    DWORD  offCon;
    WORD   segCon;
    WORD   flags;
    DWORD  cbCon;
  };

  std::vector<LineInfo> result;

  Header header;
  memcpy(&header, debugS + ib, sizeof(header));
  ib += sizeof(header);

  DWORD offMac = header.offCon + header.cbCon;

  bool fHasColumn = false;

  if (header.flags & CV_LINES_HAVE_COLUMNS)
    fHasColumn = true;

  bool fFirst = true;
  cbTable -= sizeof(header);

  while (cbTable > 0) 
  {
    struct FileBlock 
    {
      DWORD fileid;
      DWORD nLines;
      DWORD cbFileBlock;
    };

    FileBlock fileblock;
    memcpy(&fileblock, debugS + ib, sizeof(fileblock));
    ib += sizeof(FileBlock);

    LineInfo outLine;
    outLine.fileID = fileblock.fileid;

    cbTable -= fileblock.cbFileBlock;
    fileblock.cbFileBlock -= sizeof(fileblock);

    // Check whether file block size makes sense to the number of line records

    DWORD cbLineInfo = fileblock.nLines * (sizeof(CV_Line_t) + (fHasColumn ? sizeof(CV_Column_t) : 0));

    // Read in all line records and column records if any

    CV_Line_t* pLines = (CV_Line_t*)malloc(sizeof(CV_Line_t) * fileblock.nLines);

    memcpy(pLines, debugS + ib, sizeof(CV_Line_t)* fileblock.nLines);
    ib += sizeof(CV_Line_t) * fileblock.nLines;

    CV_Column_t* pColumns = NULL;

    if (fHasColumn) 
    {
      pColumns = (CV_Column_t*)malloc(sizeof(CV_Column_t) * fileblock.nLines);
      memcpy(pColumns, debugS + ib, sizeof(CV_Column_t)* fileblock.nLines);
      ib += sizeof(CV_Column_t) * fileblock.nLines;
    }

    DWORD clinesOutofBounds = 0;
    unsigned i;

    for (i = 0; i < fileblock.nLines; i++) 
    {
      CV_Line_t line = *(pLines + i);

      bool fSpecialLine = false;

      if ((line.linenumStart == 0xfeefee) || (line.linenumStart == 0xf00f00)) {
        fSpecialLine = true;
      }

      if (!fSpecialLine)
      {
        outLine.lineNumber = line.linenumStart;
        outLine.startOffset = line.offset + header.offCon;
        result.emplace_back(outLine);
      }

      if (fHasColumn) 
      {
        CV_Column_t column = *(pColumns + i);

        if (column.offColumnEnd != 0) 
        {
/*
          StdOutPrintf(L"  %5u:%-5u-%5u:%-5u %08X",
            line.linenumStart,
            column.offColumnStart,
            line.linenumStart + line.deltaLineEnd,
            column.offColumnEnd,
            line.offset + header.offCon);
*/
        }
        else 
        {
/*
          StdOutPrintf(fSpecialLine
            ? L"  %x:%-5u            %08X"
            : L"  %5u:%-5u            %08X",
            line.linenumStart,
            column.offColumnStart,
            line.offset + header.offCon);
*/
        }
      }
      else 
      {
/*
        StdOutPrintf(fSpecialLine ? L"  %x %08X" : L"  %5u %08X",
          line.linenumStart,
          line.offset + header.offCon);
*/
      }

      if ((line.offset + header.offCon) >= offMac) {
        clinesOutofBounds++;
      }
    }

    free(pLines);

    if (fHasColumn) 
      free(pColumns);
  }

  return result;
}

std::map<int,int> GetFilenameStringMap(size_t cb, unsigned char* debugS, int ib)
{
#pragma pack(push, 1)
  struct FileData {
    DWORD offstFileName;
    BYTE  cbChecksum;
    BYTE  ChecksumType;
  };
#pragma pack(pop)

  std::map<int, int> fileStringMap;

  size_t cbBlob = cb;

  while (cb >= sizeof(FileData))
  {
    FileData filedata;
    memcpy(&filedata, debugS + ib, sizeof(filedata));
    ib += sizeof(filedata);
    
    fileStringMap[(int)(cbBlob - cb)] = (int)filedata.offstFileName;

    cb -= sizeof(filedata);

    BYTE checksum[255];

    size_t cbChecksum = min(filedata.cbChecksum, sizeof(checksum));

    if (cbChecksum != 0) 
    {
      ib += (int)cbChecksum;
      cb -= cbChecksum;
    }

    size_t  cbExtra = (cbChecksum + sizeof(filedata)) % 4;

    if (cbExtra != 0) 
    {
      size_t cbFiller = 4 - cbExtra;
      ib += (int)cbFiller;
      cb -= cbFiller;
    }
  }

  return fileStringMap;
}

std::string GetFirstSymbolNameHACK(size_t cbSymSeg, DWORD ibInitial, unsigned char* debugS, int ib)
{
  BYTE SymBuf[65536];
  SYMTYPE* pSymType = (SYMTYPE*)SymBuf;

  //DWORD ibSym = ibInitial;

  while (cbSymSeg > 0) 
  {
    // Read record length
    memcpy(SymBuf, debugS + ib, 2);
    ib += 2;

    int cbRec = pSymType->reclen;

    if ((DWORD)(cbRec + 2) > cbSymSeg) 
    {
/*
      StdOutPrintf(L"cbSymSeg: %d\tcbRec: %d\tRecType: 0x%X\n", cbSymSeg, cbRec, pSymType->rectyp);
      Fatal(L"Overran end of symbol table");
*/
    }

    cbSymSeg -= cbRec + sizeof(pSymType->reclen);

    memcpy(SymBuf + 2, debugS + ib, (size_t)pSymType->reclen);
    ib += pSymType->reclen;

    if (pSymType->rectyp == S_GPROC32_ID)
    {
      auto data = (PROCSYM32*)(SymBuf);
      return std::string((char*)data->name);
    }

    //printf("Symbol record: %x\n", pSymType->rectyp);


/*
    if (!fStatics)
    {
      DumpOneSymC7(NULL, SymBuf, ibSym);
    }
    else 
    {
      switch (pSymType->rectyp) 
      {
      case S_GDATA32_ST:
      case S_LDATA32_ST:
      case S_GDATA16:
      case S_LDATA16:
      case S_GDATA32:
      case S_LDATA32:
      case S_GDATA32_16t:
      case S_LDATA32_16t:
        DumpOneSymC7(NULL, SymBuf, ibSym);
        break;
      }
    }
*/

    //ibSym += pSymType->reclen + sizeof(pSymType->reclen);
  }

  return "";
}

std::vector<LineInfo> GetLineInfo(const IMAGE_SECTION_HEADER& secHdr, unsigned char* debugS, std::map<int, int>& filenameStringMap, std::string& debugStringTable, std::string& hack_firstFunctionName )
{
  std::vector<LineInfo> result;
  bool fNoCvSig = false;
  DWORD sig;
  bool fUtf8Symbols = false;

  DWORD ib = 0;

  if (!fNoCvSig)
  {
    sig = ((DWORD*)debugS)[0];

    switch (sig)
    {
    case CV_SIGNATURE_C7:
    case CV_SIGNATURE_C11:
      fNoCvSig = true;
      fUtf8Symbols = false;
      break;

    case CV_SIGNATURE_C13:
      fUtf8Symbols = true;
      break;

    default:
      break;
    }
    //Fatal(L"Bad signature on .debug$S section");

    ib = sizeof(DWORD);
  }

  while (ib < secHdr.SizeOfRawData)
  {
    DWORD subSectionType;
    DWORD subSectionSize;

    // subsection

    if (fUtf8Symbols)
    {
      if ((ib & 3) != 0)
      {
        subSectionSize = 4 - (ib & 3);
        ib += subSectionSize;
      }

      if (ib == secHdr.SizeOfRawData)
        break;

      subSectionType = ((DWORD*)(debugS + ib))[0];
      subSectionSize = ((DWORD*)(debugS + ib))[1];

      ib += 2 * sizeof(DWORD);

      if (subSectionSize == 0)
        subSectionSize = secHdr.SizeOfRawData - ib;
    }
    else 
    {
      subSectionType = DEBUG_S_SYMBOLS;
      subSectionSize = secHdr.SizeOfRawData - ib;
    }

    switch (subSectionType)
    {
    case DEBUG_S_SYMBOLS:
      hack_firstFunctionName = GetFirstSymbolNameHACK(subSectionSize, 0, debugS, ib);
    break;
    case DEBUG_S_LINES:
      result = GetLineInfo(subSectionSize, debugS, ib);
    break;
    case DEBUG_S_STRINGTABLE:
    debugStringTable = std::string((char*)(debugS + ib), subSectionSize);
    break;
    case DEBUG_S_FILECHKSMS:
      filenameStringMap = GetFilenameStringMap(subSectionSize, debugS, ib);
    break;
    }

    ib += subSectionSize;
  }

  return result;
}

struct SymbolLineInfo
{
  std::string fileName;
  std::string functionName;
  std::vector<LineInfo> lines;
};

HunkList* CoffObjectLoader::Load(const char* data, int size, const char* module) {
	const char* ptr = data;

	// Header
	const IMAGE_FILE_HEADER* header = (const IMAGE_FILE_HEADER*)ptr;
	ptr += sizeof(IMAGE_FILE_HEADER);

	// Symbol table pointer
	const IMAGE_SYMBOL* symbolTable = (const IMAGE_SYMBOL*)(data + header->PointerToSymbolTable);
	const char* stringTable = (const char*)symbolTable + header->NumberOfSymbols*sizeof(IMAGE_SYMBOL);

	// Section headers
	const IMAGE_SECTION_HEADER* sectionHeaders = (const IMAGE_SECTION_HEADER*)ptr;

	HunkList* hunklist = new HunkList;
	Hunk* constantsHunk;
	{
		char hunkName[1000];
		sprintf_s(hunkName, 1000, "c[%s]!constants", module);
		constantsHunk = new Hunk(hunkName, 0, 0, 1, 0, 0);
	}

  std::map<int, int> filenameStringMap;
  std::string debugStringTable;
  std::vector<SymbolLineInfo> lineData;

	// Load sections
	for(int i = 0; i < header->NumberOfSections; i++) {
		string sectionName = GetSectionName(&sectionHeaders[i], stringTable);
		int chars = sectionHeaders[i].Characteristics;
		char hunkName[1000];
		sprintf_s(hunkName, 1000, "h[%s](%d)!%s", module, i, sectionName.c_str());
		unsigned int flags = 0;
		if(chars & IMAGE_SCN_CNT_CODE)
			flags |= HUNK_IS_CODE;
		if(chars & IMAGE_SCN_MEM_WRITE)
			flags |= HUNK_IS_WRITEABLE;
		bool isInitialized = (chars & IMAGE_SCN_CNT_INITIALIZED_DATA || 
								chars & IMAGE_SCN_CNT_CODE);
		Hunk* hunk = new Hunk(hunkName, data+sectionHeaders[i].PointerToRawData,	// Data pointer
								flags, GetAlignmentBitsFromCharacteristics(chars),	// Alignment
								isInitialized ? sectionHeaders[i].SizeOfRawData : 0,
								sectionHeaders[i].SizeOfRawData);	// Virtual size
		hunklist->AddHunkBack(hunk);

		if (sectionName == ".debug$S")
		{
      std::string hack_functionName;
      auto lines = GetLineInfo(sectionHeaders[i], (unsigned char*)hunk->GetPtr(), filenameStringMap, debugStringTable, hack_functionName);
      if (hack_functionName.size() && lines.size())
      {
        SymbolLineInfo info;
        info.fileName = debugStringTable.data() + filenameStringMap[lines[0].fileID];
        info.functionName = hack_functionName;
        info.lines = lines;
        lineData.emplace_back(info);
      }
    }

		// Relocations
		const IMAGE_RELOCATION* relocs = (const IMAGE_RELOCATION*) (data + sectionHeaders[i].PointerToRelocations);
		int nRelocs = sectionHeaders[i].PointerToRelocations ? sectionHeaders[i].NumberOfRelocations : 0;
		for(int j = 0; j < nRelocs; j++) {
			Relocation r;
			int symbolIndex = relocs[j].SymbolTableIndex;
			const IMAGE_SYMBOL* symbol = &symbolTable[symbolIndex];
			string symbolName = GetSymbolName(symbol, stringTable);
			if(symbol->StorageClass == IMAGE_SYM_CLASS_STATIC || 
				symbol->StorageClass == IMAGE_SYM_CLASS_LABEL) {	// Local symbol reference
				// Construct local name
				char name[1000];
				sprintf_s(name, 1000, "l[%s(%d)]!%s", module, symbolIndex, symbolName.c_str());
				r.symbolname = name;
			} else {
				r.symbolname = symbolName;
			}
			r.offset = relocs[j].VirtualAddress;

      //printf("%x %s %s\n", r.offset, r.objectname.data(), r.symbolname.data());

			switch(relocs[j].Type) {
				case IMAGE_REL_I386_DIR32NB:
				case IMAGE_REL_I386_DIR32:
					r.type = RELOCTYPE_ABS32;
					break;
				case IMAGE_REL_I386_REL32:
					r.type = RELOCTYPE_REL32;
			}
			r.objectname = StripNumeral(StripPath(module));
			
			hunk->AddRelocation(r);
		}
	}

	// Symbols
	for(int i = 0; i < (int)header->NumberOfSymbols; i++) {
		const IMAGE_SYMBOL* sym = &symbolTable[i];

    Symbol* s = new Symbol(GetSymbolName(sym, stringTable).c_str(), sym->Value, SYMBOL_IS_RELOCATEABLE, 0);
    //printf("%s - %x\n", s->name.data(), (((unsigned char*)sym) - (unsigned char*)symbolTable));

		// Skip unknown symbol types
		if(sym->StorageClass != IMAGE_SYM_CLASS_EXTERNAL &&
			sym->StorageClass != IMAGE_SYM_CLASS_STATIC &&
			sym->StorageClass != IMAGE_SYM_CLASS_LABEL &&
			sym->StorageClass != IMAGE_SYM_CLASS_WEAK_EXTERNAL) {
				i += sym->NumberOfAuxSymbols;
				continue;
		}


		if(sym->SectionNumber > 0) {
			s->hunk = (*hunklist)[sym->SectionNumber-1];

      for (int x = 0; x < lineData.size(); x++)
      {
        // HACK HACK HACKITY HACK
        if (strstr(s->name.data(), lineData[x].functionName.data()) > 0)
        {
          s->lines = lineData[x].lines;
          s->sourceFile = lineData[x].fileName;
          lineData.erase(lineData.begin() + x);
          break;
        }
      }

			if(sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->Type == 0x20 && sym->NumberOfAuxSymbols > 0) {	// Function definition
				const IMAGE_AUX_SYMBOL* aux = (const IMAGE_AUX_SYMBOL*) (sym+1);
				s->flags |= SYMBOL_IS_FUNCTION;
				s->size = aux->Sym.Misc.TotalSize;
			}

			if(sym->StorageClass == IMAGE_SYM_CLASS_STATIC ||	// Perform name mangling on local symbols
				sym->StorageClass == IMAGE_SYM_CLASS_LABEL) {

        s->friendlyName = s->name;

				char symname[1000];
				sprintf_s(symname, 1000, "l[%s(%d)]!%s", module, i, s->name.c_str());
				s->name = symname;
				s->flags |= SYMBOL_IS_LOCAL;
				if(sym->StorageClass == IMAGE_SYM_CLASS_STATIC && sym->NumberOfAuxSymbols == 1) {
					s->flags |= SYMBOL_IS_SECTION;
					s->miscString = module;
				}
			}
			s->hunk->AddSymbol(s);
		} else if(sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->Value > 0) {
			// Create an uninitialised hunk
			char hunkName[1000];
			sprintf_s(hunkName, 1000, "u[%s]!%s", module, s->name.c_str());
			Hunk* uninitHunk = new Hunk(hunkName, NULL, HUNK_IS_WRITEABLE, 1, 0, s->value);
			s->hunk = uninitHunk;
			s->value = 0;
			uninitHunk->AddSymbol(s);
			hunklist->AddHunkBack(uninitHunk);
		} else if(sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL && sym->Value == 0) {
			// Weak external
			const IMAGE_AUX_SYMBOL* aux = (const IMAGE_AUX_SYMBOL*) (sym+1);
			s->secondaryName = GetSymbolName(&symbolTable[aux->Sym.TagIndex], stringTable);
			s->hunk = constantsHunk;
			s->flags = 0;
			s->hunk->AddSymbol(s);
		} else if(sym->SectionNumber == -1) {	// Constant symbol
			s->hunk = constantsHunk;
			s->flags = 0;
			s->hunk->AddSymbol(s);
		} else {
			// Ignore unknown symbol type
			delete s;
		}
		

		i += sym->NumberOfAuxSymbols;	// Skip aux symbols
	}

	// Trim hunks
	hunklist->AddHunkBack(constantsHunk);
	hunklist->Trim();

	return hunklist;
}