OP_LOAD_IMM = 0x10
OP_XOR = 0x20
OP_ADD = 0x21
OP_SUB = 0x22
OP_ROL = 0x23
OP_ROR = 0x24
OP_MOV = 0x25
OP_LOAD_MEM = 0x30
OP_STORE_MEM = 0x31
OP_JNZ = 0x40
OP_HALT = 0xFF


def rol8(value, amount):
    amount &= 7

    if amount == 0:
        return value & 0xff

    return (
        ((value << amount) |
         (value >> (8 - amount)))
        & 0xff
    )


def ror8(value, amount):
    amount &= 7

    if amount == 0:
        return value & 0xff

    return (
        ((value >> amount) |
         (value << (8 - amount)))
        & 0xff
    )


def execute(program, memory=None):
    registers = [0] * 8

    if memory is None:
        memory = bytearray(256)
    else:
        memory = bytearray(memory)

    pc = 0
    steps = 0

    while pc < len(program):

        steps += 1

        if steps > 10000:
            raise RuntimeError("VM instruction limit exceeded")

        opcode = program[pc]
        pc += 1

        if opcode == OP_LOAD_IMM:
            reg = program[pc]
            value = program[pc + 1]
            pc += 2

            registers[reg & 7] = value

        elif opcode == OP_XOR:
            dst = program[pc]
            src = program[pc + 1]
            pc += 2

            registers[dst & 7] ^= registers[src & 7]

        elif opcode == OP_ADD:
            dst = program[pc]
            src = program[pc + 1]
            pc += 2

            registers[dst & 7] = (
                registers[dst & 7] +
                registers[src & 7]
            ) & 0xff

        elif opcode == OP_SUB:
            dst = program[pc]
            src = program[pc + 1]
            pc += 2

            registers[dst & 7] = (
                registers[dst & 7] -
                registers[src & 7]
            ) & 0xff

        elif opcode == OP_ROL:
            reg = program[pc]
            amount = program[pc + 1]
            pc += 2

            registers[reg & 7] = rol8(
                registers[reg & 7],
                amount
            )

        elif opcode == OP_ROR:
            reg = program[pc]
            amount = program[pc + 1]
            pc += 2

            registers[reg & 7] = ror8(
                registers[reg & 7],
                amount
            )

        elif opcode == OP_MOV:
            dst = program[pc]
            src = program[pc + 1]
            pc += 2

            registers[dst & 7] = registers[src & 7]

        elif opcode == OP_LOAD_MEM:
            reg = program[pc]
            address = program[pc + 1]
            pc += 2

            registers[reg & 7] = memory[address]

        elif opcode == OP_STORE_MEM:
            reg = program[pc]
            address = program[pc + 1]
            pc += 2

            memory[address] = registers[reg & 7]

        elif opcode == OP_JNZ:
            reg = program[pc]
            offset = program[pc + 1]
            pc += 2

            if registers[reg & 7] != 0:
                if offset >= 128:
                    offset -= 256

                pc += offset

        elif opcode == OP_HALT:
            break

        else:
            raise ValueError(
                f"Unknown opcode: {opcode:#x} at {pc - 1:#x}"
            )

    return registers
