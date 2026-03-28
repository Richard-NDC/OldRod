// Project OldRod - A KoiVM devirtualisation utility.
// Copyright (C) 2019 Washi
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using OldRod.Core.Architecture;

namespace OldRod.Pipeline.Stages.ConstantsResolution
{
    public class ConstantsResolutionStage : IStage
    {
        private sealed class ParsedConstantsTable
        {
            public IDictionary<FieldDefinition, byte> Values
            {
                get;
            } = new Dictionary<FieldDefinition, byte>();

            public IList<KeyValuePair<FieldDefinition, byte>> OrderedValues
            {
                get;
            } = new List<KeyValuePair<FieldDefinition, byte>>();
        }

        private const string Tag = "ConstantsResolver";

        public string Name => "Constants resolution stage";

        public void Run(DevirtualisationContext context)
        {
            if (context.Options.OverrideConstants)
            {
                context.Logger.Debug(Tag, "Using pre-defined constants.");
                context.Constants = context.Options.Constants;
            }
            else
            {
                context.Logger.Debug(Tag, "Attempting to auto-detect constants...");
                context.Constants = AutoDetectConstants(context);
            }

            context.Logger.Debug(Tag, "Attempting to extract key scalar value...");
            context.Constants.KeyScalar = FindKeyScalarValue(context);
        }

        private VMConstants AutoDetectConstants(DevirtualisationContext context)
        {
            bool rename = context.Options.RenameSymbols;

            var constants = new VMConstants();
            var fields = FindConstantFieldsAndValues(context);

            foreach (var field in fields.Values)
                constants.ConstantFields.Add(field.Key, field.Value);

            KeyValuePair<FieldDefinition, byte>[] sortedFields;
            // TODO:
            // We assume that the constants appear in the same order as they were defined in the original source code.
            // This means the metadata tokens of the fields are also in increasing order. However, this could cause
            // problems when a fork of the obfuscation tool is made which scrambles the order.  A more robust way of
            // matching should be done that is order agnostic.
            try
            {
                sortedFields = BuildOrderedConstantSequence(context, fields.OrderedValues);
            }
            catch (DevirtualisationException ex)
            {
                context.Logger.Warning(Tag, ex.Message + " Falling back to metadata token order.");
                sortedFields = BuildOrderedConstantSequence(context,
                    fields.Values.OrderBy(x => x.Key.MetadataToken.ToUInt32()));
            }

            int currentIndex = 0;

            context.Logger.Debug2(Tag, "Resolving register mapping...");
            for (int i = 0; i < (int) VMRegisters.Max; i++, currentIndex++)
            {
                constants.Registers.Add(sortedFields[currentIndex].Value, (VMRegisters) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "REG_" + (VMRegisters) i;
            }

            context.Logger.Debug2(Tag, "Resolving flag mapping...");
            for (int i = 1; i < (int) VMFlags.Max; i <<= 1, currentIndex++)
            {
                constants.Flags.Add(sortedFields[currentIndex].Value, (VMFlags) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "FLAG_" + (VMFlags) i;
            }

            context.Logger.Debug2(Tag, "Resolving opcode mapping...");
            for (int i = 0; i < (int) ILCode.Max; i++, currentIndex++)
            {
                constants.OpCodes.Add(sortedFields[currentIndex].Value, (ILCode) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "OPCODE_" + (ILCode) i;
            }

            context.Logger.Debug2(Tag, "Resolving vmcall mapping...");
            for (int i = 0; i < (int) VMCalls.Max; i++, currentIndex++)
            {
                constants.VMCalls.Add(sortedFields[currentIndex].Value, (VMCalls) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "VMCALL_" + (VMCalls) i;
            }

            context.Logger.Debug2(Tag, "Resolving helper init ID...");
            if (rename)
                sortedFields[currentIndex].Key.Name = "HELPER_INIT";
            constants.HelperInit = sortedFields[currentIndex++].Value;

            context.Logger.Debug2(Tag, "Resolving ECall mapping...");
            for (int i = 0; i < 4; i++, currentIndex++)
            {
                constants.ECallOpCodes.Add(sortedFields[currentIndex].Value, (VMECallOpCode) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "ECALL_" + (VMECallOpCode) i;
            }

            context.Logger.Debug2(Tag, "Resolving function signature flags...");
            sortedFields[currentIndex].Key.Name = "FLAG_INSTANCE";
            constants.FlagInstance = sortedFields[currentIndex++].Value;

            context.Logger.Debug2(Tag, "Resolving exception handler types...");
            for (int i = 0; i < (int) EHType.Max; i++, currentIndex++)
            {
                constants.EHTypes.Add(sortedFields[currentIndex].Value, (EHType) i);
                if (rename)
                    sortedFields[currentIndex].Key.Name = "EH_" + (EHType) i;
            }

            return constants;
        }

        private ParsedConstantsTable FindConstantFieldsAndValues(DevirtualisationContext context)
        {
            context.Logger.Debug(Tag, "Locating constants type...");
            var constantsType = LocateConstantsType(context);
            if (constantsType == null)
                throw new DevirtualisationException("Could not locate constants type!");
            context.Logger.Debug(Tag, $"Found constants type ({constantsType.MetadataToken}).");

            if (context.Options.RenameSymbols)
            {
                constantsType.Namespace = "KoiVM.Runtime.Dynamic";
                constantsType.Name = "Constants";
            }
            
            context.Logger.Debug(Tag, $"Resolving constants table...");
            return ParseConstantValues(constantsType);
        }

        private static TypeDefinition LocateConstantsType(DevirtualisationContext context)
        {
            TypeDefinition constantsType = null;
            
            if (context.Options.OverrideVMConstantsToken)
            {
                context.Logger.Debug(Tag, $"Using token {context.Options.VMConstantsToken} for constants type.");
                constantsType = (TypeDefinition) context.RuntimeModule.LookupMember(context.Options.VMConstantsToken.Value);
            }
            else
            {
                // Constants type contains a lot of public static byte fields, and only those byte fields. 
                // Therefore we pattern match on this signature, by finding the type with the most public
                // static byte fields.
                // It is unlikely that any other type has that many byte fields, although it is possible.
                // This could be improved later on.
                int max = 0;
                int minimumRequiredConstants = GetRequiredConstantCount();

                foreach (var type in context.RuntimeModule.Assembly.Modules[0].GetAllTypes())
                {
                    if (type.Fields.Count < minimumRequiredConstants)
                    // Optimisation: Check first count of all fields. We need at least the amount of opcodes of fields. 
                        continue;
                    // Count public static byte fields.

                    if (!TryParseConstantValues(type, out var parsedConstants))
                        continue;

                    int byteFields = parsedConstants.Values.Count;
                    if (byteFields >= minimumRequiredConstants && max < byteFields)
                    {
                        constantsType = type;
                        max = byteFields;
                    }
                }
            }

            return constantsType;
        }

        private static bool TryParseConstantValues(TypeDefinition constantsType, out ParsedConstantsTable result)
        {
            try
            // .cctor initialises the fields using a repetition of the following sequence:
            //
            //     ldnull
            //     ldc.i4 x
            //     stfld constantfield
            //
            // We can simply go over each instruction and "emulate" the ldc.i4 and stfld instructions.
            {
                result = ParseConstantValues(constantsType);
                return true;
            }
            catch (DevirtualisationException)
            {
                result = null;
                return false;
            }
        }

        private static ParsedConstantsTable ParseConstantValues(TypeDefinition constantsType)
        {

            var result = new ParsedConstantsTable();
            var cctor = constantsType.GetStaticConstructor();
            if (cctor?.CilMethodBody == null)
                throw new DevirtualisationException("Specified constants type does not have a static constructor.");

            var referencedFields = GetReferencedFieldsOutsideTypeInitializer(constantsType);
            bool filterUnusedFields = referencedFields.Count > 0;

            byte nextValue = 0;
            foreach (var instruction in cctor.CilMethodBody.Instructions)
            {
                if (instruction.IsLdcI4())
                    nextValue = (byte) instruction.GetLdcI4Constant();
                else if ((instruction.OpCode.Code == CilCode.Stfld || instruction.OpCode.Code == CilCode.Stsfld)
                         && instruction.Operand is FieldDefinition field
                         && field.IsPublic
                         && field.IsStatic
                         && field.Signature.FieldType.IsTypeOf("System", "Byte"))
                {
                    if (!result.Values.ContainsKey(field)
                        && (!filterUnusedFields || referencedFields.Contains(field)))
                        result.OrderedValues.Add(new KeyValuePair<FieldDefinition, byte>(field, nextValue));

                    result.Values[field] = nextValue;
                }
            }

            return result;
        }

        private static ISet<FieldDefinition> GetReferencedFieldsOutsideTypeInitializer(TypeDefinition constantsType)
        {
            var result = new HashSet<FieldDefinition>();
            var typeInitializer = constantsType.GetStaticConstructor();
            var module = constantsType.Module?.Assembly?.Modules[0];
            if (module == null)
                return result;

            foreach (var type in module.GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (method == typeInitializer || method.CilMethodBody == null)
                        continue;

                    foreach (var instruction in method.CilMethodBody.Instructions)
                    {
                        if (instruction.Operand is FieldDefinition fieldDefinition)
                        {
                            if (fieldDefinition.DeclaringType == constantsType)
                                result.Add(fieldDefinition);
                        }
                        else if (instruction.Operand is MemberReference memberReference)
                        {
                            if (!memberReference.IsField)
                                continue;

                            var resolvedField = memberReference.Resolve() as FieldDefinition;
                            if (resolvedField?.DeclaringType == constantsType)
                                result.Add(resolvedField);
                        }
                        else if (instruction.Operand is IFieldDescriptor fieldDescriptor)
                        {
                            var resolvedField = fieldDescriptor.Resolve();
                            if (resolvedField?.DeclaringType == constantsType)
                                result.Add(resolvedField);
                        }
                    }
                }
            }

            return result;
        }

        private static KeyValuePair<FieldDefinition, byte>[] BuildOrderedConstantSequence(
            DevirtualisationContext context,
            IEnumerable<KeyValuePair<FieldDefinition, byte>> source)
        {
            var orderedFields = source.ToArray();
            var result = new List<KeyValuePair<FieldDefinition, byte>>(GetRequiredConstantCount());
            int currentIndex = 0;

            CollectDistinctEntries(context, "register", orderedFields, ref currentIndex, result, (int) VMRegisters.Max);
            CollectDistinctEntries(context, "flag", orderedFields, ref currentIndex, result, GetFlagCount(), IsPowerOfTwo);
            CollectDistinctEntries(context, "opcode", orderedFields, ref currentIndex, result, (int) ILCode.Max);
            CollectDistinctEntries(context, "vmcall", orderedFields, ref currentIndex, result, (int) VMCalls.Max);
            CollectSingleEntry("helper init", orderedFields, ref currentIndex, result);
            CollectDistinctEntries(context, "ecall", orderedFields, ref currentIndex, result, 4);
            CollectSingleEntry("flag instance", orderedFields, ref currentIndex, result, IsPowerOfTwo);
            CollectDistinctEntries(context, "exception handler", orderedFields, ref currentIndex, result, (int) EHType.Max);

            return result.ToArray();
        }

        private static void CollectDistinctEntries(
            DevirtualisationContext context,
            string groupName,
            IReadOnlyList<KeyValuePair<FieldDefinition, byte>> orderedFields,
            ref int currentIndex,
            ICollection<KeyValuePair<FieldDefinition, byte>> target,
            int requiredCount,
            Func<byte, bool> predicate = null)
        {
            var seen = new HashSet<byte>();

            while (seen.Count < requiredCount)
            {
                if (currentIndex >= orderedFields.Count)
                {
                    throw new DevirtualisationException(
                        $"Could not resolve the {groupName} mapping from the constants table. " +
                        "The table likely contains unsupported junk constants.");
                }

                var entry = orderedFields[currentIndex++];
                if (predicate != null && !predicate(entry.Value))
                {
                    context.Logger.Debug2(Tag,
                        $"Skipping {groupName} constant candidate 0x{entry.Value:X2} because it does not match the expected pattern.");
                    continue;
                }

                if (!seen.Add(entry.Value))
                {
                    context.Logger.Debug2(Tag, $"Skipping duplicate {groupName} constant value 0x{entry.Value:X2}.");
                    continue;
                }

                target.Add(entry);
            }
        }

        private static void CollectSingleEntry(
            string groupName,
            IReadOnlyList<KeyValuePair<FieldDefinition, byte>> orderedFields,
            ref int currentIndex,
            ICollection<KeyValuePair<FieldDefinition, byte>> target,
            Func<byte, bool> predicate = null)
        {
            while (true)
            {
                if (currentIndex >= orderedFields.Count)
                {
                    throw new DevirtualisationException(
                        $"Could not resolve the {groupName} value from the constants table. " +
                        "The table likely contains unsupported junk constants.");
                }

                var entry = orderedFields[currentIndex++];
                if (predicate != null && !predicate(entry.Value))
                    continue;

                target.Add(entry);
                return;
            }
        }

        private static int GetRequiredConstantCount()
        {
            return (int) VMRegisters.Max
                   + GetFlagCount()
                   + (int) ILCode.Max
                   + (int) VMCalls.Max
                   + 1
                   + 4
                   + 1
                   + (int) EHType.Max;
        }

        private static int GetFlagCount()
        {
            int flagCount = 0;
            for (int i = 1; i < (int) VMFlags.Max; i <<= 1)
                flagCount++;
            return flagCount;
        }

        private static bool IsPowerOfTwo(byte value)
        {
            return value != 0 && (value & (value - 1)) == 0;
        }

        private static uint FindKeyScalarValue(DevirtualisationContext context)
        {
            uint detectedValue = FindKeyScalarValueFromVmContext(context);
            int detectedScore = ScoreKeyScalar(context, detectedValue);

            context.Logger.Debug(Tag,
                $"Key scalar candidate {detectedValue} scored {detectedScore} during stream validation.");

            uint bestValue = detectedValue;
            int bestScore = detectedScore;

            for (uint candidate = 1; candidate <= byte.MaxValue; candidate++)
            {
                int score = ScoreKeyScalar(context, candidate);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestValue = candidate;
                }
            }

            if (bestValue != detectedValue)
            {
                context.Logger.Warning(Tag,
                    $"VMContext heuristic suggested key scalar {detectedValue}, but stream validation selected {bestValue}.");
            }
            else
            {
                context.Logger.Debug(Tag,
                    $"Stream validation confirmed key scalar {bestValue}.");
            }

            return bestValue;
        }

        private static uint FindKeyScalarValueFromVmContext(DevirtualisationContext context)
        {
            context.Logger.Debug(Tag, "Locating VMContext type...");
            var vmCtxType = LocateVmContextType(context);
            if (vmCtxType is null) 
            {
                context.Logger.Warning(Tag, "Could not locate VMContext type, using default scalar value!");
                return 7;
            }
            context.Logger.Debug(Tag, $"Found VMContext type ({vmCtxType.MetadataToken}).");
            
            if (context.Options.RenameSymbols)
            {
                vmCtxType.Namespace = "KoiVM.Runtime.Execution";
                vmCtxType.Name = "VMContext";
            }

            var readByteMethod = vmCtxType.Methods.First(x => x.Signature.ReturnType.IsTypeOf("System", "Byte"));

            if (context.Options.RenameSymbols)
                readByteMethod.Name = "ReadByte";
            
            var instructions = readByteMethod.CilMethodBody.Instructions;
            for (int i = 0; i < instructions.Count; i++) 
            {
                var instr = instructions[i];
                if (i + 1 < instructions.Count
                    && instr.IsLdcI4()
                    && instructions[i + 1].OpCode.Code == CilCode.Mul)
                    return (uint)instr.GetLdcI4Constant();
            }

            context.Logger.Warning(Tag, "Could not locate scalar value, using default!");
            return 7;
        }

        private static int ScoreKeyScalar(DevirtualisationContext context, uint keyScalar)
        {
            int score = 0;

            foreach (var export in context.KoiStream.Exports.Values
                         .Where(x => !x.IsSignatureOnly)
                         .Take(16))
            {
                score += ScoreFunctionPrefix(context, export.EntrypointAddress, export.EntryKey, keyScalar);
            }

            return score;
        }

        private static int ScoreFunctionPrefix(
            DevirtualisationContext context,
            uint entrypoint,
            uint entryKey,
            uint keyScalar)
        {
            ulong streamSize = (ulong) context.KoiStream.Contents.GetPhysicalSize();
            if (entrypoint >= streamSize)
                return 0;

            var reader = context.KoiStream.Contents.CreateReader();
            reader.Offset = entrypoint;

            uint key = entryKey;
            int decodedInstructions = 0;

            for (int i = 0; i < 8; i++)
            {
                if (!TryReadOpCode(context, ref reader, ref key, keyScalar, out var opcode))
                    break;

                if (!TrySkipOperand(context, ref reader, ref key, keyScalar, opcode.OperandType, streamSize))
                    break;

                decodedInstructions++;
            }

            return decodedInstructions;
        }

        private static bool TryReadOpCode(
            DevirtualisationContext context,
            ref AsmResolver.IO.BinaryStreamReader reader,
            ref uint key,
            uint keyScalar,
            out ILOpCode opCode)
        {
            opCode = default;

            ulong streamSize = (ulong) context.KoiStream.Contents.GetPhysicalSize();
            if (reader.Offset + 2UL > streamSize)
                return false;

            byte rawOpCode = DecryptByte(reader.ReadByte(), ref key, keyScalar);
            DecryptByte(reader.ReadByte(), ref key, keyScalar);

            if (!context.Constants.OpCodes.TryGetValue(rawOpCode, out var mappedOpCode))
                return false;

            opCode = ILOpCodes.All[(int) mappedOpCode];
            return true;
        }

        private static bool TrySkipOperand(
            DevirtualisationContext context,
            ref AsmResolver.IO.BinaryStreamReader reader,
            ref uint key,
            uint keyScalar,
            ILOperandType operandType,
            ulong streamSize)
        {
            int operandSize;
            switch (operandType)
            {
                case ILOperandType.None:
                    return true;
                case ILOperandType.Register:
                    if (reader.Offset + 1UL > streamSize)
                        return false;

                    byte rawRegister = DecryptByte(reader.ReadByte(), ref key, keyScalar);
                    return context.Constants.Registers.ContainsKey(rawRegister);
                case ILOperandType.ImmediateDword:
                    operandSize = 4;
                    break;
                case ILOperandType.ImmediateQword:
                    operandSize = 8;
                    break;
                default:
                    return false;
            }

            if (reader.Offset + (ulong) operandSize > streamSize)
                return false;

            for (int i = 0; i < operandSize; i++)
                DecryptByte(reader.ReadByte(), ref key, keyScalar);

            return true;
        }

        private static byte DecryptByte(byte encryptedByte, ref uint key, uint keyScalar)
        {
            byte b = (byte) (encryptedByte ^ key);
            key = key * keyScalar + b;
            return b;
        }

        private static TypeDefinition LocateVmContextType(DevirtualisationContext context) 
        {
            if (context.Options.OverrideVMContextToken)
            {
                context.Logger.Debug(Tag, $"Using token {context.Options.VMContextToken} for constants type.");
                return (TypeDefinition)context.RuntimeModule.LookupMember(context.Options.VMContextToken.Value);
            }
            
            for (int i = 0; i < context.RuntimeModule.TopLevelTypes.Count; i++) 
            {
                var type = context.RuntimeModule.TopLevelTypes[i];
                if (type.IsAbstract)
                    continue;
                if (type.Methods.Count < 2)
                    continue;
                if (type.Fields.Count < 5)
                    continue;
                if (type.Methods.Count(x => x.IsPublic && x.Signature.ReturnType.IsTypeOf("System", "Byte")) != 1)
                    continue;
                if (type.Fields.Count(x => x.IsPublic && x.IsInitOnly && x.Signature.FieldType is SzArrayTypeSignature) != 1)
                    continue;

                int foundArrays = 0;
                int foundLists = 0;
                for (int j = 0; j < type.Fields.Count; j++) 
                {
                    var field = type.Fields[j];
                    if (field.IsPublic && field.IsInitOnly) 
                    {
                        if (field.Signature.FieldType is GenericInstanceTypeSignature genericSig &&
                            genericSig.GenericType.IsTypeOf("System.Collections.Generic", "List`1"))
                            foundLists++;

                        if (field.Signature.FieldType is SzArrayTypeSignature arraySig && arraySig.BaseType.IsValueType)
                            foundArrays++;
                    }
                }

                if (foundArrays != 1 || foundLists != 2)
                    continue;

                return type;
            }

            return null;
        }
    }
}
