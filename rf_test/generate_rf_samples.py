#!/usr/bin/env python3
sample_bits = []

def tx_byte(val):
    sample_bits.append(0) # start bit
    for i in range(8):
        sample_bits.append((val >> i) & 1) # b0
    sample_bits.append(1) # stop bit

def tx_bytes(buff):
    for a in buff:
        tx_byte(a)

sample_bits += [1] * (1024 * 8)

# this change the rf channel to ch.3
# uart_input = bytearray(b'\xac\x65\xc3' + (b'\x00' * 0x7d) + b'\xf0\x00')
# uart_input[3 + 0] = 0x21 #must match some magic hardcoded in fw. Probably seperate out by different groups
# uart_input[3 + 1] = 0x0c #must match some magic hardcoded in fw

# uart_input[3 + 2] = 1 # command group 1 - rf, 2 - ??, 3 - ??, 6 - ??, 7 - mostly LED command 8 - ??
# uart_input[3 + 3] = 0x19 # change channel plan command
# uart_input[3 + 4] = 0x13
# uart_input[3 + 5] = 0
# uart_input[3 + 10] = 1 # channel plan 
# uart_input[3 + 11] = 0x29

# this change led state - work
uart_input = bytearray(b'\xac\x65\xc3' + (b'\x00' * 0x7d) + b'\xf0\x00')
uart_input[3 + 0] = 0x21 #must match some magic hardcoded in fw. Probably seperate out by different groups
uart_input[3 + 1] = 0x0c #must match some magic hardcoded in fw

uart_input[3 + 2] = 7 # command group 1 - rf, 2 - ??, 3 - ??, 6 - ??, 7 - mostly LED command 8 - ??
uart_input[3 + 3] = 0x37 # change led group color - value at index: R[17], G[18], B[19]
                    # 0x72 - change all led to white
                    # 0x80 - turn inner on - donnu how to change color yet
                    # 0x81 - turn inner off

uart_input[3 + 8] = 1 # brightness

uart_input[3 + 11] = 0x29 # not sure what this for? :(

uart_input[3 + 17] = 255 # R
uart_input[3 + 18] = 0 # G
uart_input[3 + 19] = 0 # B

uart_input[3 + 0x75] = 0 # led state
    # 0x02 - outside ring on, inner ring off
    # 0x03 - outside ring off, inner ring on
    # 0x04 - outside ring on, inner ring no change
    # 0x05 - outside ring no change, inner ring on
    # other - everything on


tx_bytes(uart_input)
sample_bits += [1] * (1024 * 8)


def convert_bits_to_byte(buff):
    out = []
    for i in range(0, len(buff), 8):
        b = 0
        for j in range(8):
            if i + (7-j) >= len(buff):
                b |= 1 << j
            else:
                b |= buff[i + (7-j)] << j
        out.append(b)
    return bytes(out)

out = convert_bits_to_byte(sample_bits)
open("/tmp/rf_test.bin", 'wb').write(out)
