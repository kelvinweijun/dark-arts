#include "beacon.h"

// BOF test: exercises all Beacon APIs in sequence.
// Each API call writes a known value to a global variable.
//
// Argument packing (CS-standard layout):
//   int32: 42       -> BeaconDataInt
//   int16: 5943     -> BeaconDataShort
//                     BeaconDataLength returns remaining (no consumption)
//   bytes: "ABCD"   -> BeaconDataExtract

volatile int g_beacon_data_int_result = 0;
volatile short g_beacon_data_short_result = 0;
volatile int g_beacon_data_length_result = 0;
volatile char g_beacon_extract_result[4] = {0, 0, 0, 0};
volatile int g_beacon_output_called = 0;
volatile int g_beacon_printf_called = 0;
volatile int g_beacon_parse_called = 0;

// Simple checksum of all results
__declspec(noinline) int compute_checksum(void) {
    int sum = 0;
    sum += g_beacon_data_int_result;
    sum += (int)g_beacon_data_short_result;
    sum += g_beacon_data_length_result;
    sum += g_beacon_extract_result[0];
    sum += g_beacon_extract_result[1];
    sum += g_beacon_extract_result[2];
    sum += g_beacon_extract_result[3];
    sum += g_beacon_output_called * 100;
    sum += g_beacon_printf_called * 1000;
    sum += g_beacon_parse_called * 10000;
    return sum;
}

void go(char *args, int length) {
    DataParser *parser = 0;

    // Build test data buffer:
    // [int32: 42][int16: 5943][bytes: "ABCD"]
    char testdata[10];
    // int32: 42 (little-endian)
    testdata[0] = 0x2a;
    testdata[1] = 0x00;
    testdata[2] = 0x00;
    testdata[3] = 0x00;
    // int16: 5943 (little-endian) = 0x1737
    testdata[4] = 0x37;
    testdata[5] = 0x17;
    // raw bytes: "ABCD"
    testdata[6] = 0x41; // A
    testdata[7] = 0x42; // B
    testdata[8] = 0x43; // C
    testdata[9] = 0x44; // D

    // 1. BeaconDataParse - initialize parser
    BeaconDataParse(&parser, testdata, sizeof(testdata));
    if (parser != 0) {
        g_beacon_parse_called = 1;
    }

    // 2. BeaconDataInt - extract int32 (should be 42)
    g_beacon_data_int_result = BeaconDataInt(parser);

    // 3. BeaconDataShort - extract int16 (should be 5943)
    g_beacon_data_short_result = BeaconDataShort(parser);

    // 4. BeaconDataLength - returns remaining bytes (CS standard), no offset advance
    //    After Int(4) + Short(2), offset=6, buffer=10, remaining=4
    g_beacon_data_length_result = BeaconDataLength(parser);

    // 5. BeaconDataExtract - extract 4 bytes (should be "ABCD")
    char *extracted = BeaconDataExtract(parser, 4);
    if (extracted != 0) {
        g_beacon_extract_result[0] = extracted[0]; // A
        g_beacon_extract_result[1] = extracted[1]; // B
        g_beacon_extract_result[2] = extracted[2]; // C
        g_beacon_extract_result[3] = extracted[3]; // D
    }

    // 6. BeaconOutput - send raw output
    char output_msg[] = {'H', 'i', '\0'};
    BeaconOutput(0, output_msg, 2);
    g_beacon_output_called = 1;

    // 7. BeaconPrintf - send formatted output
    BeaconPrintf(0, "Test %d", 42);
    g_beacon_printf_called = 1;

    // Return checksum value.
    // Expected: 42 + 5943 + 4 + 65 + 66 + 67 + 68 + 100 + 1000 + 10000 = 17355
    int checksum = compute_checksum();
    (void)checksum;
}
