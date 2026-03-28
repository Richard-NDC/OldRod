
using System;
using System.Linq;
using AsmResolver.IO;
using OldRod.Core.Architecture;

namespace OldRod.Core.Disassembly
{
    public class InstructionDecoder
    {
        private readonly VMConstants _constants;
        private BinaryStreamReader _reader;

        public InstructionDecoder(VMConstants constants, BinaryStreamReader reader)
            : this(constants, reader, 0)
        {
        }
        
        public InstructionDecoder(VMConstants constants, BinaryStreamReader reader, uint key)
        {
            _constants = constants;
            _reader = reader;
            CurrentKey = key;
        }

        public ulong ReaderOffset 
        {
            get => _reader.Offset;
            set => _reader.Offset = value;
        }

        public uint CurrentKey
        {
            get;
            set;
        }
        
        public byte? SMCTrampolineKey
        {
            get;
            set;
        }

        public ILInstruction ReadNextInstruction()
        {
            int offset = (int) _reader.Offset;
            var opcode = ReadNextOpCode();
            var operand = ReadNextOperand(opcode.OperandType);
            return new ILInstruction(offset, opcode, operand);
        }
        
        public ILInstruction ReadNextInstruction(byte smcTrampolineKey)
        {
            SMCTrampolineKey = smcTrampolineKey;
            var instruction = ReadNextInstruction();
            SMCTrampolineKey = null;
            return instruction;
        }
        
        public bool TryReadNextInstruction(out ILInstruction instruction)
        {
            int offset = (int) _reader.Offset;
            if (TryReadNextOpCode(out var opcode) && TryReadNextOperand(opcode.OperandType, out var operand))
            {
                instruction = new ILInstruction(offset, opcode, operand);
                return true;
            }

            instruction = null;
            return false;
        }

        private byte ReadByte()
        {
            uint key = CurrentKey;
            byte rawValue = _reader.ReadByte();
            
            if (SMCTrampolineKey.HasValue)
                rawValue ^= SMCTrampolineKey.Value;

            byte b = (byte) (rawValue ^ key);
            key = key * _constants.KeyScalar + b;
            CurrentKey = key;
            return b;
        }

        public byte ReadNonEncryptedByte() 
        {
            return _reader.ReadByte();
        }

        private ILOpCode ReadNextOpCode()
        {
            long offset = (long) _reader.Offset;

            if (TryReadNextOpCode(out var opcode))
                return opcode;
            
            throw new DisassemblyException($"Byte at offset {offset:X4} not recognized as a valid opcode.");
        }

        private bool TryReadNextOpCode(out ILOpCode opCode) 
        {
            byte b = ReadByte();
            ReadByte();

            if (!_constants.OpCodes.TryGetValue(b, out var mappedOpCode)) 
            {
                opCode = default;
                return false;
            }

            opCode = ILOpCodes.All[(int)mappedOpCode];
            return true;
        }

        private bool TryReadRegister(out VMRegisters register)
        {
            return _constants.Registers.TryGetValue(ReadByte(), out register);
        }

        private bool TryReadRegister(out VMRegisters register, out byte rawRegister)
        {
            rawRegister = ReadByte();
            return _constants.Registers.TryGetValue(rawRegister, out register);
        }

        private uint ReadDword()
        {
            return ReadByte()
                   | ((uint) ReadByte() << 8)
                   | ((uint) ReadByte() << 16)
                   | ((uint) ReadByte() << 24);
        }

        private ulong ReadQword()
        {
            return ReadByte()
                   | ((ulong) ReadByte() << 8)
                   | ((ulong) ReadByte() << 16)
                   | ((ulong) ReadByte() << 24)
                   | ((ulong) ReadByte() << 32)
                   | ((ulong) ReadByte() << 40)
                   | ((ulong) ReadByte() << 48)
                   | ((ulong) ReadByte() << 56);
        }

        private object ReadNextOperand(ILOperandType operandType) 
        {
            if (operandType == ILOperandType.Register)
            {
                if (TryReadRegister(out var register, out var rawRegister))
                    return register;

                string knownRegisters = string.Join(", ",
                    _constants.Registers.OrderBy(x => x.Key).Select(x => $"0x{x.Key:X2}->{x.Value}"));
                throw new DisassemblyException(
                    $"Failed to read Register operand 0x{rawRegister:X2} at stream offset {_reader.Offset - 1:X4}. " +
                    $"Known register encodings: [{knownRegisters}]");
            }

            if (TryReadNextOperand(operandType, out object operand))
                return operand;
            throw new DisassemblyException($"Failed to read {operandType} operand!");
        }
        
        private bool TryReadNextOperand(ILOperandType operandType, out object operand)
        {
            operand = null;
            switch (operandType)
            {
                case ILOperandType.None:
                    return true;
                case ILOperandType.Register:
                    if (TryReadRegister(out var register))
                    {
                        operand = register;
                        return true;
                    }
                    return false;
                case ILOperandType.ImmediateDword:
                    operand = ReadDword();
                    return true;
                case ILOperandType.ImmediateQword:
                    operand = ReadQword();
                    return true;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }
}
