from unicorn import *
from unicorn.arm_const import *
import struct
from capstone import *
from capstone.arm import *
from keystone import *

FW_ADDRESS = 0x26000
FW_SIZE = 0x20000

def hexdump(src, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hex_) > 24:
            hex_ = '{} {}'.format(hex_[:24], hex_[24:])
        printable = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        print('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))

print("Emulate candybong RF parser")

# Initialize emulator in thumb mode
mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
md.detail = True

def asm2byte(asm):
    (t, _) = ks.asm(asm)
    return bytes(t)

# map firmware region for this emulation
mu.mem_map(FW_ADDRESS, FW_SIZE)

# map sram region
mu.mem_map(0x20000000, 0x10000)

# map trap region
mu.mem_map(0xdead0000, 4096)
mu.mem_write(0xdead0000, asm2byte("b .") * 128)

# write machine code to be emulated to memory
fw_bin = open('../../candybong/firmware/v3/nordic_tw3_230206_V1_3_RF447_9_OTA.bin', 'rb').read()
mu.mem_write(FW_ADDRESS, fw_bin)

# craft app_uart_evt_t for argument
mu.mem_write(0x20001000, b'\x00\x00\x00\x00\x00')

# initialize machine registers
mu.reg_write(UC_ARM_REG_SP, 0x2000B8B8)

uart_input = bytearray(b'\xac\x65\xc3' + (b'\x03' * 0x7d) + b'\xf0\x00')

uart_input[3 + 0] = 0xff #must match some magic hardcoded in fw. Probably seperate out by different groups
uart_input[3 + 1] = 0xff #must match some magic hardcoded in fw

uart_input[3 + 2] = 7 # command group 1 - rf, 2 - ??, 3 - ??, 6 - ??, 7 - mostly LED command 8 - ??
uart_input[3 + 3] = 0x37 # change led group color

uart_input[3 + 8] = 10 # brightness


uart_input[3 + 11] = 0x29 # not sure what this for? :(

uart_input[3 + 17] = 255 # R
uart_input[3 + 18] = 0 # G
uart_input[3 + 19] = 0 # B

uart_input[3 + 0x75] = 0 # led state

uart_read_pos = 0

# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

c2u_reg = {
    ARM_REG_R0: UC_ARM_REG_R0,
    ARM_REG_R1: UC_ARM_REG_R1,
    ARM_REG_R2: UC_ARM_REG_R2,
    ARM_REG_R3: UC_ARM_REG_R3,
    ARM_REG_R4: UC_ARM_REG_R4,
    ARM_REG_R5: UC_ARM_REG_R5,
    ARM_REG_R6: UC_ARM_REG_R6,
    ARM_REG_R7: UC_ARM_REG_R7,
    ARM_REG_R8: UC_ARM_REG_R8,
    ARM_REG_R9: UC_ARM_REG_R9,
    ARM_REG_R10: UC_ARM_REG_R10,
    ARM_REG_R11: UC_ARM_REG_R11,
    ARM_REG_R12: UC_ARM_REG_R12,
    ARM_REG_SP: UC_ARM_REG_SP,
    ARM_REG_LR: UC_ARM_REG_LR,
    ARM_REG_PC: UC_ARM_REG_PC,
}

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
    code = uc.mem_read(address, size)
    for insn in md.disasm(code, address):
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if len(insn.operands) > 0:
            c = -1
            for o in insn.operands:
                c += 1
                if o.type == ARM_OP_REG:
                    print("\t\toperands[%u].type: REG: [%s] = 0x%08x" %
                        (c, insn.reg_name(o.value.reg), uc.reg_read(c2u_reg[o.value.reg])))


def hook_uart_get(uc, address, size, user_data):
    global uart_read_pos, uart_input
    r0 = uc.reg_read(UC_ARM_REG_R0)

    val = uart_input[uart_read_pos]
    uart_read_pos += 1
    mu.mem_write(r0, bytes({val}))
    #print(f"app_uart_get() called r0: {r0:x}")

def hook_parse_rf_packet(uc, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    print(">>> R0 = 0x%x" %r0)
    print(">>> R1 = 0x%x" %r1)
    print(f'[+] inside prase_rf_packet() at 0x{address:x}')
    buf = uc.mem_read(r0, r1)
    hexdump(buf)

def hook_switch_led(uc, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    print(f'[+] called switch_led_power(0x{r0:x})')

def hook_set_led(uc, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    r3 = mu.reg_read(UC_ARM_REG_R3)
    sp = mu.reg_read(UC_ARM_REG_SP)
    sp_arg0 = struct.unpack('<I', mu.mem_read(sp, 4))[0]
    print(f'[+] called set_led_color(r = 0x{r0:x},g = 0x{r1:x}, b = 0x{r2:x}, w = 0x{r3:x}, position = {sp_arg0})')

def check_uart_state(uc):
    d = mu.mem_read(0x20002ae4, 1)
    v = struct.unpack('B', d)[0]
    print(f"Uart state: {v}")
    return v

def hook_update_led_color(uc, address, size, user_data):
    print("[+] hook_update_led_color() called")

def hook_system_reset(uc, address, size, user_data):
    raise Exception("system reset called")

# tracing all basic blocks with customized callback
#u.hook_add(UC_HOOK_BLOCK, hook_block)

# tracing one instruction at ADDRESS with customized callback
#mu.hook_add(UC_HOOK_CODE, hook_code, begin=FW_ADDRESS, end=FW_ADDRESS+FW_SIZE)
# trace only parser
mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x37434, end=0x3819c)

# hook app_uart_get()
mu.hook_add(UC_HOOK_CODE, hook_uart_get, begin=0x2e02c, end=0x2e02c)
mu.mem_write(0x2e02c, asm2byte("bx lr"))

# hook switch_led_power()
mu.hook_add(UC_HOOK_CODE, hook_switch_led, begin=0x31678, end=0x31678)
mu.mem_write(0x31678, asm2byte("bx lr"))

# hook set_led_color(uint r,uint g,uint b,uint w,int position)
mu.hook_add(UC_HOOK_CODE, hook_set_led, begin=0x316f0, end=0x316f0)
mu.mem_write(0x316f0, asm2byte("bx lr"))

# hook  rf_update_led_color(void)
mu.hook_add(UC_HOOK_CODE, hook_update_led_color, begin=0x28880, end=0x28880)
mu.mem_write(0x28880, asm2byte("bx lr"))

mu.hook_add(UC_HOOK_CODE, hook_system_reset, begin=0x27dcc, end=0x27dcc)
mu.mem_write(0x27dcc, asm2byte("bx lr"))

#mu.hook_add(UC_HOOK_CODE, hook_parse_rf_packet, begin=0x37434, end=0x37434)


# call setup_rf_parameters()
mu.emu_start(0x30620 | 1, 0x30646)

def run():
    mu.reg_write(UC_ARM_REG_R0, 0x20001000)

    try:
        # emulate UART hander code
        mu.emu_start(0x3ae0c | 1, 0x3ae70)
    except UcError as e:
        print("ERROR: %s" % e)
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        pc = mu.reg_read(UC_ARM_REG_PC)
        print(">>> R0 = 0x%x" %r0)
        print(">>> R1 = 0x%x" %r1)
        print(">>> PC = 0x%x" %pc)
        raise(e)

while(1):
    if uart_read_pos >= len(uart_input):
        print("Input ran out. Stop")
        break
    run()
    s = check_uart_state(mu)
    if s == 0:
        print("Something go wrong. State reset")
        input("wait......")

print(">>> Emulation done.")