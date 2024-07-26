// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

#include "secret_keys.h"

// Hardware Imports
#include "inc/hw_memmap.h"     // Peripheral Base Addresses
#include "inc/hw_types.h"      // Boolean type
#include "inc/tm4c123gh6pm.h"  // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"      // FLASH API
#include "driverlib/interrupt.h"  // Interrupt API
#include "driverlib/sysctl.h"     // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "driverlib/uart.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
void error(void);
void decrypt_firmware(void);
void uart_write_unsigned_short(uint8_t, uint16_t);
void finalize_firmware(void);
void check_firmware_version(void);
void set_firmware_metadata(void);

// General constants
#define FW_VERSION_LEN 2
#define FW_SIZE_LEN 2
#define INITIAL_METADATA_LEN 4

// Firmware Constants
#define METADATA_BASE 0xFC00  // base address of version and firmware size in Flash
#define FW_BASE 0x10000       // base address of firmware in Flash
#define FW_TEMP_BASE 0x20000
#define FW_TEMP_VERSION_ADDR 0x20000
#define FW_TEMP_SIZE_ADDR (FW_TEMP_VERSION_ADDR + FW_VERSION_LEN)
#define FW_TEMP_REL_MSG_ADDR (FW_TEMP_SIZE_ADDR + FW_SIZE_LEN + *(uint16_t *)FW_TEMP_SIZE_ADDR)
#define FW_VERSION_ADDR 0x3FC00
#define FW_REL_MSG_ADDR 0x3FC02

#define FW_DEBUG_ADDR 0x3FFFF
#define __FW_IS_DEBUG ((*((uint8_t *)FW_DEBUG_ADDR) & 0x01) == 0x0)
#define DEBUG_BYTE 0xFE
#define DEFAULT_BYTE 0xFF

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')
#define FRAME_LEN 256

uint32_t encrypted_fw_size = 0;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {
  // Enable the GPIO port that is used for the on-board LED.
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

  // Check if the peripheral access is enabled.
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
  }

  // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
  // enable the GPIO pin for digital function.
  GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

  // Turn on the green LED
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

  // Wait
  SysCtlDelay(SysCtlClockGet() * 2);

  // Turn off the green LED
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

int main(void) {
  // Enable the GPIO port that is used for the on-board LED.
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

  // Check if the peripheral access is enabled.
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
  }

  // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
  // enable the GPIO pin for digital function.
  GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

  // debug_delay_led();

  initialize_uarts(UART0);

  uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

  int resp;
  while (1) {
    uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

    if (instruction == UPDATE) {
      uart_write_str(UART0, "U");
      load_firmware();
      decrypt_firmware();
      check_firmware_version();
      set_firmware_metadata();
      finalize_firmware();
      uart_write_str(UART0, "Loaded new firmware.\n");
      nl(UART0);
      while (UARTBusy(UART0_BASE)) {
      };
    } else if (instruction == BOOT) {
      uart_write_str(UART0, "B");
      uart_write_str(UART0, "Booting firmware...\n");
      while (UARTBusy(UART0_BASE)) {
      };
      boot_firmware();
    }
  }
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void) {
  uint16_t frame_length;
  int resp;
  int data_index = 0;
  uint32_t page_addr = FW_TEMP_BASE;
  while (1) {
    ((uint8_t *)&frame_length)[0] = uart_read(UART0, BLOCKING, &resp);
    ((uint8_t *)&frame_length)[1] = uart_read(UART0, BLOCKING, &resp);

    if (frame_length == 0) {
      uart_write(UART0, OK);
      while (UARTBusy(UART0_BASE)) {
      };
      break;
    }

    if (frame_length != FRAME_LEN) {
      error();
    }
    for (int i = 0; i < frame_length; i++) {
      data[data_index++] = uart_read(UART0, BLOCKING, &resp);
      encrypted_fw_size++;
    }
    if (data_index == FLASH_PAGESIZE) {
      if (program_flash((void *)page_addr, data, FLASH_PAGESIZE) != 0) {
        error();
      }
      data_index = 0;
      page_addr += FLASH_PAGESIZE;
      if (page_addr - FW_TEMP_BASE > MAX_CHUNK_NO * FLASH_PAGESIZE) {
        error();
      }
    }
    uart_write(UART0, OK);
    while (UARTBusy(UART0_BASE)) {
    };
  }
  if (data_index != 0) {
    if (program_flash((void *)page_addr, data, data_index) != 0) {
      error();
    }
  }
  encrypted_fw_size -= *(uint8_t*)(FW_TEMP_BASE+encrypted_fw_size-1);
}

void error(void) {
  uart_write(UART0, ERROR);
  while (UARTBusy(UART0_BASE)) {
  };
  SysCtlReset();
}

void decrypt_firmware(void) {
  uint8_t aes_key[AES_KEY_SIZE] = AES_KEY;
  uint32_t firmware_size = encrypted_fw_size - AES_IV_SIZE;
  Aes aes_cbc;

  // Initalize the AES module
  wc_AesInit(&aes_cbc, NULL, INVALID_DEVID);

  // Set the AES key
  wc_AesSetKey(&aes_cbc, aes_key, AES_KEY_SIZE, (byte *)FW_TEMP_BASE, AES_DECRYPTION);

  // Decrypt the data in 1kB chunks
  uint8_t *block_addr = (uint8_t *)FW_TEMP_BASE;
  for (int i = 0; i < firmware_size / BLOCK_SIZE; i++) {
    // Set the initial value of IV
    wc_AesSetIV(&aes_cbc, block_addr);

    // Decrypt the firmware
    if (wc_AesCbcDecrypt(&aes_cbc, data, (byte *)((uint32_t)block_addr + AES_IV_SIZE), BLOCK_SIZE) != 0) {
      SysCtlReset();
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, BLOCK_SIZE) != 0) {
      SysCtlReset();
    }
    block_addr += BLOCK_SIZE;
  }

  // Decrypt last, incomplete block
  uint32_t last_block_size = firmware_size % BLOCK_SIZE;
  if (last_block_size > 0) {
    // Set the initial value of IV
    wc_AesSetIV(&aes_cbc, block_addr);

    // Decrypt the firmware
    if (wc_AesCbcDecrypt(&aes_cbc, data, (byte *)((uint32_t)block_addr + AES_IV_SIZE), last_block_size) != 0) {
      SysCtlReset();
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, last_block_size) != 0) {
      SysCtlReset();
    }
  }

  // Delete AES key from memory
  // memset(aes_key, 0xFF, AES_KEY_SIZE);
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void *page_addr, unsigned char *data, unsigned int data_len) {
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase((uint32_t)page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE) {
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;

    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, (uint32_t)page_addr, num_full_bytes);
    if (ret != 0) {
      return ret;
    }

    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++) {
      word = (word >> 8) | (data[num_full_bytes + i] << 24);  // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++) {
      word = (word >> 8) | 0xFF000000;
    }

    // Program word
    return FlashProgram(&word, (uint32_t)page_addr + num_full_bytes, 4);
  } else {
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, (uint32_t)page_addr, data_len);
  }
}

void boot_firmware(void) {
  // Check if firmware loaded
  int fw_present = 0;
  for (uint8_t *i = (uint8_t *)FW_BASE; i < (uint8_t *)FW_BASE + 20; i++) {
    if (*i != 0xFF) {
      fw_present = 1;
    }
  }

  if (!fw_present) {
    uart_write_str(UART0, "No firmware loaded.\n");
    SysCtlReset();  // Reset device
    return;
  }

  // Write the firmware version
  uart_write_str(UART0, "Firmware version: ");
  if (!__FW_IS_DEBUG) {
    uart_write_unsigned_short(UART0, *(uint16_t *)FW_VERSION_ADDR);
  } else {
    uart_write_str(UART0, "0 (DEBUG MODE)");
  }
  nl(UART0);

  // Write release message
  uart_write_str(UART0, (char *)FW_REL_MSG_ADDR);
  nl(UART0);

  while (UARTBusy(UART0_BASE)) {
  };

  // Boot the firmware
  __asm(
      "LDR R0,=0x10001\n\t"
      "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t *start, uint32_t len) {
  for (uint8_t *cursor = start; cursor < (start + len); cursor += 1) {
    uint8_t data = *((uint8_t *)cursor);
    uint8_t right_nibble = data & 0xF;
    uint8_t left_nibble = (data >> 4) & 0xF;
    char byte_str[3];
    if (right_nibble > 9) {
      right_nibble += 0x37;
    } else {
      right_nibble += 0x30;
    }
    byte_str[1] = right_nibble;
    if (left_nibble > 9) {
      left_nibble += 0x37;
    } else {
      left_nibble += 0x30;
    }
    byte_str[0] = left_nibble;
    byte_str[2] = '\0';

    uart_write_str(uart, byte_str);
    uart_write_str(uart, " ");
  }
}

/*
 * Write an unsigned short to the UART.
 */
void uart_write_unsigned_short(uint8_t uart, uint16_t num) {
  // 0 is the execption since it is all 0s
  if (num == 0) {
    uart_write_str(uart, "0");
    return;
  }

  // Longest unsigned short is 5 characters
  char str[6] = "00000";

  // Fill in the string
  int curr = 4;
  while (num > 0) {
    str[curr] = (char)((num % 10) + '0');
    num /= 10;
    curr--;
  }

  // Remove leading zeros
  char *start = str;
  while (*start == '0') {
    start++;
  }

  // Write the string
  uart_write_str(uart, start);
}

// Take the firmware and write it to the final firmware location in flash where it will be booted from
// This should only be called after the firmware is loaded, decrypted, and verified, and the version number has been checked
void finalize_firmware(void) {
  uint32_t firmware_size = (uint32_t)(*(uint16_t *)FW_TEMP_SIZE_ADDR);

  uint32_t blocks = firmware_size / FLASH_PAGESIZE;
  if (firmware_size % FLASH_PAGESIZE != 0) {
    blocks++;
  }
  int ret = 0;
  for (uint32_t i = 0; i < blocks; i++) {
    ret += program_flash((void *)(FW_BASE + i * FLASH_PAGESIZE), (uint8_t *)(FW_TEMP_BASE + 4 + i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }
  if (ret != 0) {
    for (uint32_t i = 0; i < blocks; i++) {
      FlashErase(FW_BASE + i * FLASH_PAGESIZE);
    }
    SysCtlReset();
  }
}

// Check the firmware version to see if it is >= the last version
// If it is 0 just let it go through
// If it is less than the last version, reset the device
void check_firmware_version(void) {
  uint16_t ver = *(uint16_t *)FW_TEMP_VERSION_ADDR;
  uint16_t last_ver = *(uint16_t *)FW_VERSION_ADDR;

  if (ver == 0 || ver >= last_ver) {
    return;
  } else if (ver < last_ver) {
    SysCtlReset();
  }
}

// Sets the firmware metadata to the appropriate addresses and variables
// This should only be called after the firmware is loaded, decrypted, and verified, and the version number has been checked
void set_firmware_metadata(void) {
  uint16_t version = *(uint16_t *)(FW_TEMP_VERSION_ADDR);
  uint32_t fw_release_message_size = 1;
  for (uint8_t *addr = (uint8_t *)FW_TEMP_REL_MSG_ADDR; *addr != '\0'; addr++, fw_release_message_size++) {
    if (fw_release_message_size >= MAX_MSG_LEN) {
      // No null terminator so string is messed up, so something is wrong
      SysCtlReset();
    }
  }

  bool is_debug = (version == 0);

  if (is_debug) {
    memcpy(data, (uint8_t *)FW_VERSION_ADDR, FW_VERSION_LEN);
    data[1023] = DEBUG_BYTE;
  } else {
    memcpy(data, (uint8_t *)FW_TEMP_BASE, FW_VERSION_LEN);
    data[1023] = DEFAULT_BYTE;
  }
  memcpy(data + FW_VERSION_LEN, (uint8_t *)FW_TEMP_REL_MSG_ADDR, fw_release_message_size);

  // Write the metadata to permanent location in flash
  if (program_flash((void *)FW_VERSION_ADDR, data, FLASH_PAGESIZE) != 0) {
    SysCtlReset();
  }
}
