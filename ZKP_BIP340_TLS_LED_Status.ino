#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <PubSubClient.h>
#include <string.h>

#include "ZkpSecp256k1.h"
#include "mbedtls/sha256.h"


// ============================================================
// ESP32 BIP340 IoT SECURITY CLIENT
// ============================================================
//
// Authentication:
//
// ESP32
//   |
//   | sih/auth/request
//   v
// Gateway
//   |
//   | sih/auth/challenge
//   v
// ESP32
//   |
//   | SHA256("SIH-ZKP-v1" + DEVICE_ID + challenge)
//   | BIP340 sign
//   |
//   | sih/auth/response
//   v
// Gateway
//   |
//   | BIP340 verify
//   |
//   | sih/security/status
//   v
// ESP32
//
// SECURE      -> GREEN LED
// SUSPICIOUS  -> YELLOW LED
// COMPROMISED -> RED LED
// RESTRICTED  -> YELLOW LED
// ISOLATED    -> RED LED
//
// MQTT TCP: 1883
// TLS: DISABLED
// Authentication interval: 30 seconds
// ============================================================


// ============================================================
// WIFI
// ============================================================

const char* WIFI_SSID = "";//name

const char* WIFI_PASSWORD =
    "";//your password


// ============================================================
// MQTT
// ============================================================

const char* MQTT_SERVER =
    "";

const uint16_t MQTT_PORT =
    1883;

const char* MQTT_USERNAME =
    "";

const char* MQTT_PASSWORD =
    "";


// ============================================================
// DEVICE
// ============================================================

const char* DEVICE_ID =
    "ESP32-E5856C";


// ============================================================
// ATTACK SIMULATION
//
// false = normal authentication
// true  = deliberately corrupt signature
// ============================================================

bool SIMULATE_ATTACK = false;


// ============================================================
// AUTHENTICATION INTERVAL
// ============================================================

const unsigned long AUTH_INTERVAL =
    10000UL;


// ============================================================
// MQTT RETRY
// ============================================================

const unsigned long MQTT_RETRY_INTERVAL =
    3000UL;


// ============================================================
// LED PINS
// ============================================================

#define LED_GREEN  23
#define LED_YELLOW 22
#define LED_RED    21
#define BUZZER_PIN 19

// ============================================================
// MQTT TOPICS
// ============================================================

const char* STATUS_TOPIC =
    "sih/security/status";

const char* CONTROL_TOPIC =
    "sih/security/control";

const char* REQUEST_TOPIC =
    "sih/auth/request";

const char* CHALLENGE_TOPIC =
    "sih/auth/challenge";

const char* RESPONSE_TOPIC =
    "sih/auth/response";


// ============================================================
// BIP340 SECRET KEY
// ============================================================

const char* SECRET_HEX =
    "";


// ============================================================
// GLOBAL OBJECTS
// ============================================================

WiFiClient wifiClient;

PubSubClient mqtt(
    wifiClient
);

secp256k1_context* ctx =
    nullptr;


// ============================================================
// SECURITY STATES
// ============================================================

enum SecurityState
{
    SECURE,
    SUSPICIOUS,
    COMPROMISED,
    RESTRICTED,
    ISOLATED
};


// ============================================================
// GLOBAL STATE
// ============================================================

SecurityState currentSecurityState =
    SUSPICIOUS;

bool authenticationInProgress =
    false;

//bool attackAlarmTriggered = false;    

bool authenticatedSession =
    false;

unsigned long lastAuthentication =
    0;

unsigned long lastMQTTAttempt =
    0;


// ============================================================
// FUNCTION PROTOTYPES
// ============================================================

void connectWiFi();

bool connectMQTT();

void maintainMQTT();

void startAuthentication();

void mqttCallback(
    char* topic,
    byte* payload,
    unsigned int length
);

void processChallenge(
    const String& message
);

void handleSecurityStatus(
    const String& message
);

void handleControlCommand(
    const String& message
);

void setSecurityState(
    SecurityState state
);

void setSecurityLEDs(
    bool green,
    bool yellow,
    bool red
);
void triggerAttackAlert();
void stopBuzzer();

// ============================================================
// BUZZER ALERT
// ============================================================

void triggerAttackAlert()
{
    //if(attackAlarmTriggered)
     //   return;

    //attackAlarmTriggered = true;

    Serial.println("BUZZER ALERT: ATTACK DETECTED");

    for(int i = 0; i < 5; i++)
    {
        digitalWrite(BUZZER_PIN, HIGH);
        delay(200);

        digitalWrite(BUZZER_PIN, LOW);
        delay(200);
    }
}


void stopBuzzer()
{
    digitalWrite(
        BUZZER_PIN,
        LOW
    );
}

String getJsonValue(
    const String& json,
    const char* key
);

bool hexToBytes(
    const char* hex,
    uint8_t* output,
    size_t length
);

bool isHexCharacter(
    char c
);

void printHex(
    const uint8_t* data,
    size_t length
);

bool createBIP340Message(
    const uint8_t* challenge,
    size_t challengeLength,
    const char* deviceId,
    uint8_t* output
);


// ============================================================
// LED CONTROL
// ============================================================

void setSecurityLEDs(
    bool green,
    bool yellow,
    bool red
)
{
    digitalWrite(
        LED_GREEN,
        green ? HIGH : LOW
    );

    digitalWrite(
        LED_YELLOW,
        yellow ? HIGH : LOW
    );

    digitalWrite(
        LED_RED,
        red ? HIGH : LOW
    );
}


// ============================================================
// SECURITY STATE
// ============================================================

void setSecurityState(
    SecurityState state
)
{
    currentSecurityState =
        state;

    switch (state)
    {
        case SECURE:

            setSecurityLEDs(
                true,
                false,
                false
            );
           // attackAlarmTriggered = false;

            Serial.println(
                "SECURITY STATE: SECURE"
            );

            Serial.println(
                "GREEN LED: ON"
            );

             Serial.println(
        "BUZZER: OFF"
    );

            break;


        case SUSPICIOUS:

            setSecurityLEDs(
                false,
                true,
                false
            );

            Serial.println(
                "SECURITY STATE: SUSPICIOUS"
            );

            Serial.println(
                "YELLOW LED: ON"
            );

            break;


        case COMPROMISED:

            setSecurityLEDs(
                false,
                false,
                true
            );
            triggerAttackAlert();

            Serial.println(
                "SECURITY STATE: COMPROMISED"
            );

            Serial.println(
                "RED LED: ON"
            );

            break;


        case RESTRICTED:

            setSecurityLEDs(
                false,
                true,
                false
            );

            Serial.println(
                "SECURITY STATE: RESTRICTED"
            );

            Serial.println(
                "YELLOW LED: ON"
            );

            break;


        case ISOLATED:

            setSecurityLEDs(
                false,
                false,
                true
            );
            triggerAttackAlert();

            Serial.println(
                "SECURITY STATE: ISOLATED"
            );

            Serial.println(
                "RED LED: ON"
            );

            break;
    }
}


// ============================================================
// JSON VALUE EXTRACTION
// ============================================================

String getJsonValue(
    const String& json,
    const char* key
)
{
    String searchKey =
        "\"";

    searchKey += key;
    searchKey += "\"";


    int keyPosition =
        json.indexOf(
            searchKey
        );


    if (keyPosition < 0)
    {
        return "";
    }


    int colonPosition =
        json.indexOf(
            ':',
            keyPosition +
            searchKey.length()
        );


    if (colonPosition < 0)
    {
        return "";
    }


    int firstQuote =
        json.indexOf(
            '"',
            colonPosition + 1
        );


    if (firstQuote < 0)
    {
        return "";
    }


    int secondQuote =
        json.indexOf(
            '"',
            firstQuote + 1
        );


    if (secondQuote < 0)
    {
        return "";
    }


    return json.substring(
        firstQuote + 1,
        secondQuote
    );
}


// ============================================================
// HEX CHARACTER
// ============================================================

bool isHexCharacter(
    char c
)
{
    return
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F');
}


// ============================================================
// HEX -> BYTES
// ============================================================

bool hexToBytes(
    const char* hex,
    uint8_t* output,
    size_t length
)
{
    if (
        hex == nullptr ||
        output == nullptr
    )
    {
        return false;
    }


    for (
        size_t i = 0;
        i < length;
        i++
    )
    {
        char high =
            hex[i * 2];

        char low =
            hex[i * 2 + 1];


        if (
            !isHexCharacter(high) ||
            !isHexCharacter(low)
        )
        {
            return false;
        }


        uint8_t highValue;
        uint8_t lowValue;


        if (
            high >= '0' &&
            high <= '9'
        )
        {
            highValue =
                high - '0';
        }
        else if (
            high >= 'a' &&
            high <= 'f'
        )
        {
            highValue =
                high - 'a' + 10;
        }
        else
        {
            highValue =
                high - 'A' + 10;
        }


        if (
            low >= '0' &&
            low <= '9'
        )
        {
            lowValue =
                low - '0';
        }
        else if (
            low >= 'a' &&
            low <= 'f'
        )
        {
            lowValue =
                low - 'a' + 10;
        }
        else
        {
            lowValue =
                low - 'A' + 10;
        }


        output[i] =
            (highValue << 4) |
            lowValue;
    }


    return true;
}


// ============================================================
// PRINT HEX
// ============================================================

void printHex(
    const uint8_t* data,
    size_t length
)
{
    for (
        size_t i = 0;
        i < length;
        i++
    )
    {
        if (
            data[i] < 16
        )
        {
            Serial.print(
                "0"
            );
        }


        Serial.print(
            data[i],
            HEX
        );
    }


    Serial.println();
}


// ============================================================
// CREATE EXACT MESSAGE FOR BIP340
//
// MUST MATCH GATEWAY:
//
// hashlib.sha256(
//     b"SIH-ZKP-v1"
//     + device_id.encode("utf-8")
//     + challenge
// ).digest()
//
// ESP32 performs:
//
// SHA256(
//     "SIH-ZKP-v1"
//     + DEVICE_ID
//     + 32-byte challenge
// )
//
// Result = exactly 32 bytes.
//
// That 32-byte result is passed to zkp_sign().
// ============================================================

bool createBIP340Message(
    const uint8_t* challenge,
    size_t challengeLength,
    const char* deviceId,
    uint8_t* output
)
{
    if (
        challenge == nullptr ||
        deviceId == nullptr ||
        output == nullptr
    )
    {
        return false;
    }


    const char* domain =
        "SIH-ZKP-v1";


    mbedtls_sha256_context sha;

    mbedtls_sha256_init(
        &sha
    );


    // Start SHA-256

    if (
        mbedtls_sha256_starts(
            &sha,
            0
        ) != 0
    )
    {
        mbedtls_sha256_free(
            &sha
        );

        return false;
    }


    // Add domain

    if (
        mbedtls_sha256_update(
            &sha,
            (const unsigned char*)domain,
            strlen(domain)
        ) != 0
    )
    {
        mbedtls_sha256_free(
            &sha
        );

        return false;
    }


    // Add DEVICE_ID

    if (
        mbedtls_sha256_update(
            &sha,
            (const unsigned char*)deviceId,
            strlen(deviceId)
        ) != 0
    )
    {
        mbedtls_sha256_free(
            &sha
        );

        return false;
    }


    // Add 32-byte challenge

    if (
        mbedtls_sha256_update(
            &sha,
            challenge,
            challengeLength
        ) != 0
    )
    {
        mbedtls_sha256_free(
            &sha
        );

        return false;
    }


    // Final SHA-256

    if (
        mbedtls_sha256_finish(
            &sha,
            output
        ) != 0
    )
    {
        mbedtls_sha256_free(
            &sha
        );

        return false;
    }


    mbedtls_sha256_free(
        &sha
    );


    return true;
}


// ============================================================
// START AUTHENTICATION
// ============================================================

void startAuthentication()
{
    if (
        !mqtt.connected()
    )
    {
        Serial.println(
            "Authentication waiting for MQTT."
        );

        return;
    }


    if (
        authenticationInProgress
    )
    {
        return;
    }


    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "AUTHENTICATION REQUEST"
    );

    Serial.println(
        "================================"
    );


    authenticatedSession =
        false;


    authenticationInProgress =
        true;


    setSecurityState(
        SUSPICIOUS
    );


    char requestPayload[160];


    int written =
        snprintf(
            requestPayload,
            sizeof(requestPayload),
            "{\"device_id\":\"%s\"}",
            DEVICE_ID
        );


    if (
        written < 0 ||
        written >=
        (int)sizeof(requestPayload)
    )
    {
        Serial.println(
            "ERROR: request payload too large."
        );

        authenticationInProgress =
            false;

        return;
    }


    if (
        mqtt.publish(
            REQUEST_TOPIC,
            requestPayload
        )
    )
    {
        Serial.println(
            "Authentication request sent."
        );


        Serial.print(
            "Device: "
        );


        Serial.println(
            DEVICE_ID
        );


        lastAuthentication =
            millis();
    }
    else
    {
        Serial.println(
            "Authentication request failed."
        );


        authenticationInProgress =
            false;
    }
}


// ============================================================
// PROCESS CHALLENGE
// ============================================================

void processChallenge(
    const String& message
)
{
    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "BIP340 CHALLENGE RECEIVED"
    );

    Serial.println(
        "================================"
    );


    Serial.print(
        "Gateway message: "
    );


    Serial.println(
        message
    );


    // ========================================================
    // DEVICE ID
    // ========================================================

    String challengeDevice =
        getJsonValue(
            message,
            "device_id"
        );


    if (
        challengeDevice.length() > 0 &&
        challengeDevice != DEVICE_ID
    )
    {
        Serial.println(
            "Challenge is for another device."
        );

        return;
    }


    // ========================================================
    // EXTRACT CHALLENGE
    // ========================================================

    String challengeString =
        getJsonValue(
            message,
            "challenge"
        );


    challengeString.trim();


    if (
        challengeString.length() == 0
    )
    {
        Serial.println(
            "ERROR: challenge field not found."
        );


        authenticationInProgress =
            false;


        setSecurityState(
            SUSPICIOUS
        );


        return;
    }


    Serial.print(
        "Extracted challenge: "
    );


    Serial.println(
        challengeString
    );


    // ========================================================
    // CHECK 64 HEX CHARACTERS
    // ========================================================

    if (
        challengeString.length() != 64
    )
    {
        Serial.print(
            "ERROR: challenge length = "
        );


        Serial.println(
            challengeString.length()
        );


        Serial.println(
            "Expected exactly 64 hexadecimal characters."
        );


        authenticationInProgress =
            false;


        setSecurityState(
            SUSPICIOUS
        );


        return;
    }


    // ========================================================
    // CHECK HEX
    // ========================================================

    for (
        unsigned int i = 0;
        i < challengeString.length();
        i++
    )
    {
        if (
            !isHexCharacter(
                challengeString[i]
            )
        )
        {
            Serial.println(
                "ERROR: challenge contains non-hex characters."
            );


            authenticationInProgress =
                false;


            setSecurityState(
                SUSPICIOUS
            );


            return;
        }
    }


    // ========================================================
    // CONVERT CHALLENGE
    // ========================================================

    uint8_t challenge[32];


    if (
        !hexToBytes(
            challengeString.c_str(),
            challenge,
            32
        )
    )
    {
        Serial.println(
            "ERROR: challenge conversion failed."
        );


        authenticationInProgress =
            false;


        setSecurityState(
            SUSPICIOUS
        );


        return;
    }


    Serial.print(
        "Challenge bytes: "
    );


    printHex(
        challenge,
        32
    );


    // ========================================================
    // SECRET
    // ========================================================

    uint8_t secret[32];


    if (
        !hexToBytes(
            SECRET_HEX,
            secret,
            32
        )
    )
    {
        Serial.println(
            "ERROR: secret conversion failed."
        );


        authenticationInProgress =
            false;


        authenticatedSession =
            false;


        setSecurityState(
            COMPROMISED
        );


        return;
    }


    // ========================================================
    // CREATE EXACT GATEWAY MESSAGE
    // ========================================================

    uint8_t messageHash[32];


    Serial.println();

    Serial.println(
        "Creating exact BIP340 message..."
    );


    if (
        !createBIP340Message(
            challenge,
            32,
            DEVICE_ID,
            messageHash
        )
    )
    {
        Serial.println(
            "ERROR: BIP340 message creation failed."
        );


        authenticationInProgress =
            false;


        authenticatedSession =
            false;


        setSecurityState(
            COMPROMISED
        );


        return;
    }


    Serial.print(
        "Message hash: "
    );


    printHex(
        messageHash,
        32
    );


    // ========================================================
    // BIP340 SIGNATURE
    // ========================================================

    uint8_t signature[64];


    Serial.println();

    Serial.println(
        "Signing message with BIP340..."
    );


    if (
        !zkp_sign(
            ctx,
            signature,
            messageHash,
            secret
        )
    )
    {
        Serial.println(
            "ERROR: BIP340 signing failed."
        );


        authenticationInProgress =
            false;


        authenticatedSession =
            false;


        setSecurityState(
            COMPROMISED
        );


        return;
    }


    Serial.println(
        "BIP340 signing: SUCCESS"
    );


    // ========================================================
    // SIGNATURE -> HEX
    // ========================================================

    char signatureHex[129];


    for (
        int i = 0;
        i < 64;
        i++
    )
    {
        snprintf(
            &signatureHex[i * 2],
            3,
            "%02X",
            signature[i]
        );
    }


    signatureHex[128] =
        '\0';


    Serial.print(
        "Signature: "
    );


    Serial.println(
        signatureHex
    );


    // ========================================================
    // ATTACK SIMULATION
    // ========================================================

    if (
        SIMULATE_ATTACK
    )
    {
        Serial.println();

        Serial.println(
            "================================"
        );

        Serial.println(
            "SIMULATED ATTACK"
        );

        Serial.println(
            "================================"
        );


        if (
            signatureHex[0] == 'A'
        )
        {
            signatureHex[0] =
                'B';
        }
        else
        {
            signatureHex[0] =
                'A';
        }


        Serial.println(
            "Signature intentionally modified."
        );


        Serial.print(
            "Modified signature: "
        );


        Serial.println(
            signatureHex
        );
    }


    // ========================================================
    // RESPONSE JSON
    // ========================================================

    char responsePayload[256];


    int written =
        snprintf(
            responsePayload,
            sizeof(responsePayload),
            "{\"device_id\":\"%s\",\"signature\":\"%s\"}",
            DEVICE_ID,
            signatureHex
        );


    if (
        written < 0 ||
        written >=
        (int)sizeof(responsePayload)
    )
    {
        Serial.println(
            "ERROR: response payload too large."
        );


        authenticationInProgress =
            false;


        return;
    }


    // ========================================================
    // SEND SIGNATURE
    // ========================================================

    Serial.println();

    Serial.println(
        "Sending BIP340 signature to Gateway..."
    );


    if (
        mqtt.publish(
            RESPONSE_TOPIC,
            responsePayload
        )
    )
    {
        Serial.println(
            "Signature sent successfully."
        );


        Serial.println(
            "Waiting for Gateway verification..."
        );
    }
    else
    {
        Serial.println(
            "ERROR: signature transmission failed."
        );


        authenticationInProgress =
            false;


        authenticatedSession =
            false;


        setSecurityState(
            SUSPICIOUS
        );
    }
}


// ============================================================
// SECURITY STATUS
//
// IMPORTANT:
//
// Gateway sends:
//
// {
//   "device_id": "...",
//   "state": "SECURE",
//   "risk_score": 0
// }
//
// Therefore we read "state", NOT "status".
// ============================================================

void handleSecurityStatus(
    const String& message
)
{
    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "SECURITY STATUS RECEIVED"
    );

    Serial.println(
        "================================"
    );


    Serial.print(
        "Gateway status message: "
    );


    Serial.println(
        message
    );


    // ========================================================
    // IMPORTANT FIX:
    // Gateway uses "state"
    // ========================================================

    String status =
        getJsonValue(
            message,
            "state"
        );


    status.trim();

    status.toUpperCase();


    Serial.print(
        "Gateway security state: "
    );


    Serial.println(
        status
    );


    // ========================================================
    // SECURE
    // ========================================================

    if (
        status == "SECURE" ||
        status == "AUTHENTICATED" ||
        status == "ALLOW"
    )
    {
        authenticatedSession =
            true;


        authenticationInProgress =
            false;


        setSecurityState(
            SECURE
        );


        Serial.println();

        Serial.println(
            "================================"
        );

        Serial.println(
            "AUTHENTICATION SUCCESSFUL"
        );

        Serial.println(
            "DEVICE AUTHENTICATED"
        );

        Serial.println(
            "GREEN LED: ON"
        );

        Serial.println(
            "================================"
        );


        return;
    }


    // ========================================================
    // SUSPICIOUS
    // ========================================================

    if (
        status == "SUSPICIOUS"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            SUSPICIOUS
        );


        return;
    }


    // ========================================================
    // COMPROMISED
    // ========================================================

    if (
        status == "COMPROMISED"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            COMPROMISED
        );


        return;
    }


    // ========================================================
    // RESTRICTED
    // ========================================================

    if (
        status == "RESTRICTED" ||
        status == "RESTRICT"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            RESTRICTED
        );


        return;
    }


    // ========================================================
    // ISOLATED
    // ========================================================

    if (
        status == "ISOLATED" ||
        status == "QUARANTINE"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            ISOLATED
        );


        return;
    }


    Serial.println(
        "Unknown security state."
    );
}


// ============================================================
// SECURITY CONTROL
// ============================================================

void handleControlCommand(
    const String& message
)
{
    String deviceId =
        getJsonValue(
            message,
            "device_id"
        );


    String action =
        getJsonValue(
            message,
            "action"
        );


    action.trim();

    action.toUpperCase();


    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "SECURITY CONTROL"
    );

    Serial.println(
        "================================"
    );


    Serial.print(
        "Device: "
    );

    Serial.println(
        deviceId
    );


    Serial.print(
        "Action: "
    );

    Serial.println(
        action
    );


    // ========================================================
    // IGNORE OTHER DEVICE
    // ========================================================

    if (
        deviceId.length() > 0 &&
        deviceId != DEVICE_ID
    )
    {
        Serial.println(
            "Command belongs to another device."
        );

        return;
    }


    // ========================================================
    // ISOLATE
    // ========================================================

    if (
        action == "ISOLATE" ||
        action == "QUARANTINE"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            ISOLATED
        );


        return;
    }


    // ========================================================
    // RESTRICT
    // ========================================================

    if (
        action == "RESTRICT"
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        setSecurityState(
            RESTRICTED
        );


        return;
    }


    // ========================================================
    // RESTORE / ALLOW
    // ========================================================

    if (
        action == "ALLOW" ||
        action == "RESTORE"
    )
    {
        Serial.println(
            "Restore requested."
        );


        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        startAuthentication();


        return;
    }


    Serial.println(
        "Unknown control command."
    );
}


// ============================================================
// MQTT CALLBACK
// ============================================================

void mqttCallback(
    char* topic,
    byte* payload,
    unsigned int length
)
{
    String message;


    message.reserve(
        length + 1
    );


    for (
        unsigned int i = 0;
        i < length;
        i++
    )
    {
        message +=
            (char)payload[i];
    }


    // ========================================================
    // CHALLENGE
    // ========================================================

    if (
        strcmp(
            topic,
            CHALLENGE_TOPIC
        ) == 0
    )
    {
        processChallenge(
            message
        );

        return;
    }


    // ========================================================
    // SECURITY STATUS
    // ========================================================

    if (
        strcmp(
            topic,
            STATUS_TOPIC
        ) == 0
    )
    {
        handleSecurityStatus(
            message
        );

        return;
    }


    // ========================================================
    // SECURITY CONTROL
    // ========================================================

    if (
        strcmp(
            topic,
            CONTROL_TOPIC
        ) == 0
    )
    {
        handleControlCommand(
            message
        );

        return;
    }
}


// ============================================================
// WIFI CONNECTION
// ============================================================

void connectWiFi()
{
    if (
        WiFi.status() ==
        WL_CONNECTED
    )
    {
        return;
    }


    Serial.println();

    Serial.println(
        "Connecting WiFi..."
    );


    WiFi.mode(
        WIFI_STA
    );


    WiFi.begin(
        WIFI_SSID,
        WIFI_PASSWORD
    );


    unsigned long start =
        millis();


    while (
        WiFi.status() != WL_CONNECTED &&
        millis() - start < 15000UL
    )
    {
        delay(250);

        Serial.print(
            "."
        );
    }


    Serial.println();


    if (
        WiFi.status() ==
        WL_CONNECTED
    )
    {
        Serial.println(
            "WiFi connected!"
        );


        Serial.print(
            "ESP32 IP: "
        );


        Serial.println(
            WiFi.localIP()
        );


        Serial.print(
            "Gateway: "
        );


        Serial.println(
            WiFi.gatewayIP()
        );
    }
    else
    {
        Serial.println(
            "WiFi connection failed."
        );
    }
}


// ============================================================
// MQTT CONNECTION
// ============================================================

bool connectMQTT()
{
    if (
        mqtt.connected()
    )
    {
        return true;
    }


    Serial.println();

    Serial.println(
        "================================"
    );

    Serial.println(
        "Connecting MQTT..."
    );

    Serial.println(
        "================================"
    );


    Serial.print(
        "Broker: "
    );


    Serial.print(
        MQTT_SERVER
    );


    Serial.print(
        ":"
    );


    Serial.println(
        MQTT_PORT
    );


    Serial.println(
        "Transport: MQTT/TCP"
    );


    Serial.println(
        "TLS: DISABLED"
    );


    // ========================================================
    // TCP TEST
    // ========================================================

    Serial.println(
        "Testing broker connection..."
    );


    WiFiClient testClient;


    if (
        testClient.connect(
            MQTT_SERVER,
            MQTT_PORT
        )
    )
    {
        Serial.println(
            "Broker TCP connection: OK"
        );


        testClient.stop();
    }
    else
    {
        Serial.println(
            "Broker TCP connection FAILED."
        );


        return false;
    }


    // ========================================================
    // MQTT CONNECT
    // ========================================================

    bool connected =
        mqtt.connect(
            DEVICE_ID,
            MQTT_USERNAME,
            MQTT_PASSWORD
        );


    if (
        !connected
    )
    {
        Serial.print(
            "MQTT failed, state="
        );


        Serial.println(
            mqtt.state()
        );


        return false;
    }


    Serial.println(
        "MQTT connected!"
    );


    // ========================================================
    // SUBSCRIPTIONS
    // ========================================================

    bool challengeOK =
        mqtt.subscribe(
            CHALLENGE_TOPIC
        );


    bool statusOK =
        mqtt.subscribe(
            STATUS_TOPIC
        );


    bool controlOK =
        mqtt.subscribe(
            CONTROL_TOPIC
        );


    Serial.print(
        "Challenge subscription: "
    );


    Serial.println(
        challengeOK ?
        "OK" :
        "FAILED"
    );


    Serial.print(
        "Status subscription: "
    );


    Serial.println(
        statusOK ?
        "OK" :
        "FAILED"
    );


    Serial.print(
        "Control subscription: "
    );


    Serial.println(
        controlOK ?
        "OK" :
        "FAILED"
    );


    Serial.println(
        "MQTT ready."
    );


    // ========================================================
    // RESET AUTH STATE
    // ========================================================

    authenticatedSession =
        false;


    authenticationInProgress =
        false;


    // ========================================================
    // START AUTHENTICATION
    // ========================================================

    startAuthentication();


    return true;
}


// ============================================================
// MQTT MAINTENANCE
// ============================================================

void maintainMQTT()
{
    if (
        WiFi.status() != WL_CONNECTED
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        if (
            currentSecurityState !=
            SUSPICIOUS
        )
        {
            setSecurityState(
                SUSPICIOUS
            );
        }


        connectWiFi();


        return;
    }


    if (
        mqtt.connected()
    )
    {
        return;
    }


    if (
        millis() -
        lastMQTTAttempt <
        MQTT_RETRY_INTERVAL
    )
    {
        return;
    }


    lastMQTTAttempt =
        millis();


    Serial.println();

    Serial.println(
        "Trying MQTT again..."
    );


    connectMQTT();
}


// ============================================================
// SETUP
// ============================================================

void setup()
{
    // ========================================================
    // LED
    // ========================================================

    pinMode(
        LED_GREEN,
        OUTPUT
    );


    pinMode(
        LED_YELLOW,
        OUTPUT
    );


    pinMode(
        LED_RED,
        OUTPUT
    );

    pinMode(
    BUZZER_PIN,
    OUTPUT
);

stopBuzzer();


    setSecurityLEDs(
        false,
        false,
        false
    );


    // ========================================================
    // SERIAL
    // ========================================================

    Serial.begin(
        115200
    );


    delay(
        1000
    );


    Serial.println();

    Serial.println(
        "========================================"
    );


    Serial.println(
        " ESP32 BIP340 IOT SECURITY CLIENT"
    );


    Serial.println(
        "========================================"
    );


    Serial.print(
        "Device ID: "
    );


    Serial.println(
        DEVICE_ID
    );


    Serial.println(
        "Authentication interval: 10 seconds"
    );


    Serial.println(
        "MQTT: TCP / 1883"
    );


    Serial.println(
        "TLS: DISABLED"
    );


    Serial.println(
        "========================================"
    );


    setSecurityState(
        SUSPICIOUS
    );


    // ========================================================
    // SECP256K1 CONTEXT
    // ========================================================

    ctx =
        secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN
        );


    if (
        ctx == nullptr
    )
    {
        Serial.println(
            "ERROR: secp256k1 context creation failed."
        );


        setSecurityState(
            COMPROMISED
        );


        return;
    }


    Serial.println(
        "secp256k1 context: OK"
    );


    // ========================================================
    // WIFI
    // ========================================================

    connectWiFi();


    // ========================================================
    // MQTT CONFIG
    // ========================================================

    mqtt.setServer(
        MQTT_SERVER,
        MQTT_PORT
    );


    mqtt.setCallback(
        mqttCallback
    );


    mqtt.setBufferSize(
        512
    );


    mqtt.setKeepAlive(
        30
    );


    // ========================================================
    // INITIAL MQTT
    // ========================================================

    connectMQTT();


    lastAuthentication =
        millis();
}


// ============================================================
// LOOP
// ============================================================

void loop()
{
    // ========================================================
    // WIFI
    // ========================================================

    if (
        WiFi.status() != WL_CONNECTED
    )
    {
        authenticatedSession =
            false;


        authenticationInProgress =
            false;


        if (
            currentSecurityState !=
            SUSPICIOUS
        )
        {
            setSecurityState(
                SUSPICIOUS
            );
        }


        connectWiFi();
    }


    // ========================================================
    // MQTT
    // ========================================================

    maintainMQTT();


    // ========================================================
    // MQTT PROCESSING
    // ========================================================

    if (
        mqtt.connected()
    )
    {
        mqtt.loop();
    }


    // ========================================================
    // 30 SECOND AUTHENTICATION
    // ========================================================

    if (
        mqtt.connected() &&
        !authenticationInProgress &&
        millis() - lastAuthentication >=
        AUTH_INTERVAL
    )
    {
        Serial.println();

        Serial.println(
            "================================"
        );


        Serial.println(
            "10 SECOND AUTHENTICATION"
        );


        Serial.println(
            "Requesting new BIP340 challenge..."
        );


        Serial.println(
            "================================"
        );


        authenticatedSession =
            false;


        startAuthentication();
    }


    // ========================================================
    // SMALL DELAY
    // ========================================================

    delay(
        5
    );
}
