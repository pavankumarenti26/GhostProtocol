from vm import (
    execute,
    OP_LOAD_IMM,
    OP_XOR,
    OP_ADD,
    OP_ROL,
    OP_HALT,
)


program = bytes([
    # R0 = 0x2A
    OP_LOAD_IMM, 0, 0x2A,

    # R1 = 0x15
    OP_LOAD_IMM, 1, 0x15,

    # R0 = R0 XOR R1
    OP_XOR, 0, 1,

    # R0 = R0 + R1
    OP_ADD, 0, 1,

    # Rotate R0 left by 3
    OP_ROL, 0, 3,

    # Stop
    OP_HALT,
])


registers = execute(program)

print("Registers:")

for i, value in enumerate(registers):
    print(f"R{i} = {value:02x}")
