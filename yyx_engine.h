#pragma once

#include <stdint.h>
#include <map>
#include <vector>
#include <string>

enum DstSrcOpndTaintType {
	ByteToAllBytes, // most arith instructions use this type. 
	//	ByteToAtOrPrevBytes, 
	ByteToByteOthersNotChange, // mostly for mov series. 
	ByteToByteOthersUntaint, // mostly for movzx series. 
	ByteToByteOthersSignExtend,
	ByteToEvenHalfIndexByte,
	ByteToOddHalfIndexByte,
	QWordToEvenHalfIndexQWord,
	QWordToOddHalfIndexQWord,

	InstructionExecutedConditional,// for movd, movq, cmpxchg, others should be untainted or ignored should be condtioned on opnd type. 

};

extern std::map<std::string, std::map<int, std::vector<std::pair<int, DstSrcOpndTaintType>>>> taint_meta;


