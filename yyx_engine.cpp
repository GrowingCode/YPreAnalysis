#include "yyx_engine.h"
#include <dr_api.h>

std::map<std::string, std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>> taint_meta = {
	{"add",{ {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"or", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}} } },
	{"sbb", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"and", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}} } },
	{"sub", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"xor", { {0,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}} } },
	{"cmp", {} },//0dst 2src
	{"inc", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"dec", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"push", { {1,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}} } },// {0,{{1,InstructionTaintType::ByteToAtOrPrevBytes}}} xsp must not be tainted. 
	{"pop", { {0,{{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}} },// ,{1,{0}} actually, xsp must not be tainted. 
	{"imul", { {0,{{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}} } },
	{"jb", {} },
	{"jnb", {} },
	{"jz", {} },
	{"jnz", {} },
	{"jbe",{} },
	{"jnbe", {} },
	{"js", {} },
	{"jns", {} },
	{"jl", {} },
	{"jnl", {} },
	{"jle", {} },
	{"jnle", {} },
	{"call", {} },
	{"jmp", {} },
	{"jmp", {} },
	{"jmp", {} },
	{"mov", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}} },
	{"test", {} },//0dst 2src
	// mostly for position taint but can be taken as normal taint, should judge reg_use_in_mem not src mem itself. 
	{"lea", {{-1,{}}} },// {0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}
	{"xchg", {{0,{{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}},{1,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}} },
	{"cwde", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"cdq", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"ret", {} },
	{"syscall", {} },//2dst 0src
	{"cmovb", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnb", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovz", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnz", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovbe", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnbe", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovs", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovns", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovl", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnl", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovle", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"cmovnle", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"punpcklbw", {{0,{{0,DstSrcOpndTaintType::ByteToOddHalfIndexByte},{1,DstSrcOpndTaintType::ByteToEvenHalfIndexByte}}}} },
	{"punpcklqdq", {{0,{{0,DstSrcOpndTaintType::QWordToOddHalfIndexQWord},{1,DstSrcOpndTaintType::QWordToEvenHalfIndexQWord}}}} },
	{"movd", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movq", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movdqu", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"movdqa", {{0,{{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}} },
	{"jb", {}},
	{"jb",{}},
	{"jnb",{}},
	{"jz",{}},
	{"jnz",{}},
	{"jbe",{}},
	{"jnbe",{}},
	{"js",{}},
	{"jns",{}},
	{"jl",{}},
	{"jnl",{}},
	{"jle",{}},
	{"jnle",{}},
	{"setb",{}},
	{"setnb",{}},
	{"setz",{}},
	{"setnz",{}},
	{"setnbe",{}},
	{"setns",{}},
	{"setnle",{}},
	{"cpuid",{}},
	{"bt",{}},
	{"bts",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},// bit position taint, but can be considered as value tainted. 
	{"cmpxchg",{{-1,{}}, {0,{{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}, {1,{{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"btr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},// bit position taint, but can be considered as value tainted. 
	{"movzx",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersUntaint}}}}},
	{"bsf",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"bsr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"movsx",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}}},
	{"xadd",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}, {1,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"psrldq",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"rol",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"ror",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"shl",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"shr",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"sar",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"not",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"neg",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"mul",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"div",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"idiv",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes},{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"cmpxchg8b",{{-1,{}}, {0, {{3,DstSrcOpndTaintType::ByteToByteOthersNotChange},{4,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}, {1, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}, {2, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"lfence",{}},
	{"prefetchw",{}},
	{"movups",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"movss",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"movsd",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"movhps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"movaps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"comiss",{}},
	{"xorps",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}}},
	{"rep stos",{{-1, {}}, {0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}, {1, {{1,DstSrcOpndTaintType::ByteToAllBytes},{2,DstSrcOpndTaintType::ByteToAllBytes}}}, {2, {{2,DstSrcOpndTaintType::ByteToAllBytes}}}} },
	{"movsxd",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersSignExtend}}}} },
	{"xgetbv",{{0, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}, {1, {{0,DstSrcOpndTaintType::ByteToAllBytes}}}}},
	{"vmovdqu",{{0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}} },
	{"vzeroupper",{}},
	{"vinsertf128",{{-1,{}}, {0, {{0,DstSrcOpndTaintType::ByteToByteOthersNotChange},{1,DstSrcOpndTaintType::ByteToByteOthersNotChange}}}} },
	{"rdrand",{}},
};



