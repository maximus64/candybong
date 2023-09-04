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

print("Emulate candybong BLE parser")

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

# map Peri region
mu.mem_map(0x40000000, 0x10000)

# map trap region
mu.mem_map(0xdead0000, 4096)
mu.mem_write(0xdead0000, asm2byte("b .") * 128)

# write machine code to be emulated to memory
fw_bin = open('../../candybong/firmware/v3/nordic_tw3_230206_V1_3_RF447_9_OTA.bin', 'rb').read()
mu.mem_write(FW_ADDRESS, fw_bin)


# initialize machine registers
mu.reg_write(UC_ARM_REG_SP, 0x2000B8B8)

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

def hook_get_now(uc, address, size, user_data):
    print("[+] get_now() called - just return 0x55555555 0xaaaaaaaa for now")
    uc.reg_write(UC_ARM_REG_R0, 0x55555555)
    uc.reg_write(UC_ARM_REG_R1, 0xaaaaaaaa)

def hook_schedule_led_command_opcode(uc, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    lr = mu.reg_read(UC_ARM_REG_LR)
    print(f'[+] called schedule_led_command_opcode(0x{r0:x}) - lr: 0x{lr:x}')

def hook_ble_uart_write(uc, address, size, user_data):
    r0 = mu.reg_read(UC_ARM_REG_R0)
    r1 = mu.reg_read(UC_ARM_REG_R1)
    r2 = mu.reg_read(UC_ARM_REG_R2)
    buf_len = struct.unpack('<I', mu.mem_read(r2, 4))[0]
    print(f'[+] called ble_uart_write(ctx: 0x{r0:x}, buff: 0x{r1:x}, plength: *0x{r2:x} = 0x{buf_len:x})')

    buf = mu.mem_read(r1, buf_len)
    hexdump(buf)
    
    uc.reg_write(UC_ARM_REG_R0, 0)

# tracing all basic blocks with customized callback
#u.hook_add(UC_HOOK_BLOCK, hook_block)

# tracing one instruction at ADDRESS with customized callback
#mu.hook_add(UC_HOOK_CODE, hook_code, begin=FW_ADDRESS, end=FW_ADDRESS+FW_SIZE)
# trace only parser
mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x37434, end=0x3819c)

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

mu.hook_add(UC_HOOK_CODE, hook_get_now, begin=0x312e8, end=0x312e8)
mu.mem_write(0x312e8, asm2byte("bx lr"))

mu.hook_add(UC_HOOK_CODE, hook_schedule_led_command_opcode, begin=0x3a300, end=0x3a300)
mu.mem_write(0x3a300, asm2byte("bx lr"))

mu.hook_add(UC_HOOK_CODE, hook_ble_uart_write, begin=0x2ed10, end=0x2ed10)
mu.mem_write(0x2ed10, asm2byte("bx lr"))


#mu.hook_add(UC_HOOK_CODE, hook_parse_rf_packet, begin=0x37434, end=0x37434)


def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" \
                %(address, size, value))
    else:   # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" \
                %(address, size))

# intercept memory events
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access, begin=0x40000000, end=0x40010000)

def setup_rf_parameters():
    print("[+] call setup_rf_parameters()")
    mu.reg_write(UC_ARM_REG_LR, 0xdead0000)
    mu.emu_start(0x30620 | 1, 0xdead0000)
    print("[+] setup_rf_parameters() - done")


def nus_data_handler(buf):
    mu.mem_write(0x20002000, buf)
    d = struct.pack("<B" + ('x' * 15) + "II" , 
        0, #BLE_NUS_EVT_RX_DATA
        0x20002000, #buffer address
        len(buf)
    )
    mu.mem_write(0x20001000, d)

    mu.reg_write(UC_ARM_REG_LR, 0xdead0000)
    mu.reg_write(UC_ARM_REG_R0, 0x20001000)

    try:
        # emulate BLE handler code
        print(f"[+] call nus_data_handler({repr(buf)})")
        mu.emu_start(0x35dc0 | 1, 0xdead0000)
    except UcError as e:
        print("ERROR: %s" % e)
        r0 = mu.reg_read(UC_ARM_REG_R0)
        r1 = mu.reg_read(UC_ARM_REG_R1)
        pc = mu.reg_read(UC_ARM_REG_PC)
        lr = mu.reg_read(UC_ARM_REG_LR)
        print(">>> R0 = 0x%x" %r0)
        print(">>> R1 = 0x%x" %r1)
        print(">>> PC = 0x%x" %pc)
        print(">>> LR = 0x%x" %lr)
        raise(e)


setup_rf_parameters()

#hack 
#set max packet size value in SRAM don't know where this get setup
mu.mem_write(0x20002b28, struct.pack("<I", 247))

#mu.hook_add(UC_HOOK_CODE, hook_code, begin=FW_ADDRESS, end=FW_ADDRESS+FW_SIZE)

# nus_data_handler(b'@dfu') #enter def mode
#ff 14 00 [01 to 09] [Speed]
#nus_data_handler(b'\xff\x14\x00\x01\x10')  #schedule_led_command_opcode(0x15)
#nus_data_handler(b'\xff\x14\x00\x02\x10')  #schedule_led_command_opcode(0x16)
#nus_data_handler(b'\xff\x14\x00\x03\x10')  #schedule_led_command_opcode(0x0) - turn led off
#nus_data_handler(b'\xff\x14\x00\x04\x10')  #schedule_led_command_opcode(0x17)
#nus_data_handler(b'\xff\x14\x00\x05\x10')  #schedule_led_command_opcode(0x10)
#nus_data_handler(b'\xff\x14\x00\x06\x10')  #schedule_led_command_opcode(0x18)
#nus_data_handler(b'\xff\x14\x00\x07\x10' + b'\x55' * 33)  #set all rgb 0 then schedule_led_command_opcode(0xb1) - switch all led off
#nus_data_handler(b'\xff\x14\x00\x08\x10')  #set led half green half orange then schedule_led_command_opcode(0xb2) - weird color
#nus_data_handler(b'\xff\x14\x00\x09\x10')  # call set twice preset

# nus_data_handler(b'\xff\x15\x00\x10\xff')  #schedule_led_command_opcode(0x1)
# nus_data_handler(b'\xff\x15\x00\x10\xff')
# nus_data_handler(b'\xff\x15\x00\x10\x01')

#nus_data_handler(b'\xff\xe2\x00\x55\x66\x77\x10') #called schedule_led_command_opcode(0x2)
#nus_data_handler(b'\xff\xe3\x00\x55\x66\x77\x10') #schedule_led_command_opcode(0x3)

#nus_data_handler(b'\xff\xe4\x00\x00\x00\x00\x10') #schedule_led_command_opcode(0xc)

nus_data_handler(b'\xff\xe6\x00\xff\xee\xdd\x10') # schedule_led_command_opcode(0x1) solid color

#nus_data_handler(b'\xff\xe7\x03\xff' + b'\x55'*30) # schedule_led_command_opcode(0xb8) # weir hue speed 0
                                                   # schedule_led_command_opcode(0xba) speed 1
                                                   # schedule_led_command_opcode(0xbb) speed 2
                                                   # schedule_led_command_opcode(0xbc) speed 3

#nus_data_handler(b'\xff\xe9'  ) # checksum and echo

#nus_data_handler(b'\xff\xef\x00\xff') # ???????? 

# max packet size ~ 521 bytes