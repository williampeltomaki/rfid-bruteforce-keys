#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9 
#define SS_PIN 10 

MFRC522 mfrc522(SS_PIN, RST_PIN);

#define NR_KNOWN_KEYS 17

byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // 00 00 00 00 00 00
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // d3 f7 d3 f7 d3 f7
    {0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0}, // a0 b0 c0 d0 e0 f0
    {0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1}, // a1 b1 c1 d1 e1 f1
    {0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97}, // 71 4c 5c 88 6e 97
    {0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f}, // 58 7e e5 f9 35 0f
    {0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91}, // a0 47 8c c3 90 91
    {0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6}, // 53 3c b6 c7 23 f6
    {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9}, // 8f d0 a4 f2 56 e9
    {0x73, 0x8f, 0x9a, 0x43, 0x50, 0x22}, // 73 8f 9a 43 50 22
};

void setup() {
    Serial.begin(9600);     
    while (!Serial);        
    SPI.begin();
    mfrc522.PCD_Init();
 
    Serial.println(F("Try to discover Mifare classic keys..."));
}

void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

bool try_key(byte block, MFRC522::MIFARE_Key *key) {
    byte buffer[18];
    MFRC522::StatusCode status;

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) return false;

    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);

    if (status == MFRC522::STATUS_OK) {
        Serial.println();
        if((block + 4) % 4 == 0) {
            byte sector = ((block + 4) / 4) - 1;
            Serial.print(F("---------------------------- sector "));
            Serial.print(sector);
            Serial.print(F(" -----------------------------------"));
        };
        Serial.println();

        Serial.print(F("Success with key:"));
        dump_byte_array((*key).keyByte, MFRC522::MF_KEY_SIZE);
        Serial.println();

        Serial.print(F("Block ")); Serial.print(block); Serial.print(F(":"));
        dump_byte_array(buffer, 16);

        return true;
    }

    Serial.println();
    return false;
}

void bruteforce() {
    byte blockNumber = getBlockNumber();

    MFRC522::MIFARE_Key key;
    for(byte block = 0; block < blockNumber; block++){
        for(byte k = 0; k < NR_KNOWN_KEYS; k++){
            for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
                key.keyByte[i] = knownKeys[k][i];
            }

            if(try_key(block, &key)) break;
            if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) break;
        }

        if(block == blockNumber - 1) {
            Serial.println();
            Serial.println("Finishing...");
        }
    }
}

byte getBlockNumber(){
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    if(piccType == MFRC522::PICC_TYPE_MIFARE_1K) return 64;
    if(piccType == MFRC522::PICC_TYPE_MIFARE_4K) return 256;
}

void loop() {
    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) return;

    bruteforce();

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();
}
