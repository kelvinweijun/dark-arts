#pragma once

// Minimal Beacon API declarations for BOF testing.
// These match the Cobalt Strike / BOF standard API conventions.

// Data parser opaque type (implementation is on the Go side)
typedef struct _dataparser DataParser;

// BeaconDataParse initializes the data parser.
// native signature: void BeaconDataParse(DataParser **parser, char *buffer, int length)
extern void BeaconDataParse(DataParser **parser, char *buffer, int length);

// BeaconDataExtract extracts raw bytes of the given size from the parser.
// native signature: char *BeaconDataExtract(DataParser *parser, int size)
extern char *BeaconDataExtract(DataParser *parser, int size);

// BeaconDataInt extracts an int32 from the parser.
// native signature: int BeaconDataInt(DataParser *parser)
extern int BeaconDataInt(DataParser *parser);

// BeaconDataShort extracts an int16 from the parser.
// native signature: short BeaconDataShort(DataParser *parser)
extern short BeaconDataShort(DataParser *parser);

// BeaconDataLength returns the remaining length.
// native signature: int BeaconDataLength(DataParser *parser)
extern int BeaconDataLength(DataParser *parser);

// BeaconOutput sends raw output to the beacon.
// native signature: void BeaconOutput(int type, char *data, int length)
extern void BeaconOutput(int type, char *data, int length);

// BeaconPrintf sends formatted output to the beacon.
// native signature (variadic): void BeaconPrintf(int type, const char *fmt, ...)
// NOTE: MSVC will generate an indirect call via import thunks for variadic functions.
extern void __cdecl BeaconPrintf(int type, const char *fmt, ...);

// BOF entry point convention: void go(char *args, int length)
// args is a packed buffer of [uint16 len][bytes...] pairs.
