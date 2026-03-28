
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables;
using OldRod.Core.Architecture;
using OldRod.Core.Disassembly.Inference;

namespace OldRod.Pipeline.Stages.VMMethodDetection
{
    public class VMMethodDetectionStage : IStage
    {
        private static readonly SignatureComparer Comparer = new SignatureComparer(SignatureComparisonFlags.VersionAgnostic);

        public const string Tag = "VMMethodDetection";
        
        public string Name => "Virtualised method detection stage";

        public void Run(DevirtualisationContext context)
        {

            if (!context.Options.NoExportMapping)
                context.VMEntryInfo = ExtractVMEntryInfo(context);
            
            ConvertFunctionSignatures(context);
            
            if (context.Options.NoExportMapping)
            {
                context.Logger.Debug(Tag, "Not mapping methods to physical methods.");
            }
            else
            {
                context.Logger.Debug(Tag, "Mapping methods to physical methods...");
                MapVMExportsToMethods(context);
            }

            if (context.Options.RenameSymbols)
            {
                context.VMEntryInfo.VMEntryType.Namespace = "KoiVM.Runtime";
                context.VMEntryInfo.VMEntryType.Name = "VMEntry";
                context.VMEntryInfo.RunMethod1.Name = "Run";
                context.VMEntryInfo.RunMethod2.Name = "Run";
            }
        }

        private VMEntryInfo ExtractVMEntryInfo(DevirtualisationContext context)
        {
            if (context.Options.OverrideVMEntryToken)
            {
                
                context.Logger.Debug(Tag, $"Using token {context.Options.VMEntryToken} for VMEntry type.");
                var type = (TypeDefinition) context.RuntimeModule.LookupMember(context.Options.VMEntryToken.Value);
                var info = TryExtractVMEntryInfoFromType(context, type);
                if (info == null)
                {
                    throw new DevirtualisationException(
                        $"Type {type.MetadataToken} ({type}) does not match the signature of the VMEntry type.");
                }

                return info;
            }
            else
            {
                
                context.Logger.Debug(Tag, "Searching for VMEntry type...");
                var info = SearchVMEntryType(context);
                
                if (info == null)
                    throw new DevirtualisationException("Could not detect VMEntry type.");
                
                context.Logger.Debug(Tag, $"Detected VMEntry type ({info.VMEntryType.MetadataToken})");
                return info;
            }
        }

        private VMEntryInfo SearchVMEntryType(DevirtualisationContext context)
        {
            foreach (var type in context.RuntimeModule.Assembly.Modules[0].GetAllTypes())
            {
                var info = TryExtractVMEntryInfoFromType(context, type);
                if (info != null)
                    return info;
            }

            return null;
        }

        private static bool TryGetExtraParameterCount(MethodDefinition method, ICollection<string> expectedTypes,
            out int extraParameterCount)
        {
            if (method.Signature == null)
            {
                extraParameterCount = 0;
                return false;
            }

            expectedTypes = new List<string>(expectedTypes);
            extraParameterCount = 0;

            foreach (var parameter in method.Signature.ParameterTypes)
            {
                string typeFullName = parameter.FullName;

                if (expectedTypes.Contains(typeFullName))
                {
                    expectedTypes.Remove(typeFullName);
                }
                else
                {
                    extraParameterCount++;
                }
            }

            return expectedTypes.Count == 0;
        }

        private static bool IsPreferredVmEntryMethodName(string name)
        {
            return name == "Run" || name == "Call";
        }

        private static MethodDefinition FindBestMatchingMethod(TypeDefinition type, ICollection<string> expectedTypes,
            string returnTypeNamespace, string returnTypeName)
        {
            MethodDefinition bestMethod = null;
            int bestExtraParameterCount = int.MaxValue;
            int bestPriority = int.MinValue;
            bool bestHasExpectedReturnType = false;

            foreach (var method in type.Methods)
            {
                if (!method.IsStatic)
                    continue;

                if (!TryGetExtraParameterCount(method, expectedTypes, out int extraParameterCount))
                    continue;

                bool hasExpectedReturnType = method.Signature.ReturnType.IsTypeOf(returnTypeNamespace, returnTypeName);
                int priority = 0;

                if (method.IsPublic)
                    priority += 4;
                else if (method.IsAssembly)
                    priority += 2;

                if (IsPreferredVmEntryMethodName(method.Name))
                    priority += 1;

                if (bestMethod == null
                    || (hasExpectedReturnType && !bestHasExpectedReturnType)
                    || (hasExpectedReturnType == bestHasExpectedReturnType
                        && (extraParameterCount < bestExtraParameterCount
                            || (extraParameterCount == bestExtraParameterCount && priority > bestPriority))))
                {
                    bestMethod = method;
                    bestExtraParameterCount = extraParameterCount;
                    bestPriority = priority;
                    bestHasExpectedReturnType = hasExpectedReturnType;
                }
            }

            return bestMethod;
        }

        private VMEntryInfo TryExtractVMEntryInfoFromType(DevirtualisationContext context, TypeDefinition type)
        {
            var info = new VMEntryInfo
            {
                VMEntryType = type
            };

            info.RunMethod1 = FindBestMatchingMethod(type, context.Options.Run1ExpectedTypes, "System", "Object");
            info.RunMethod2 = FindBestMatchingMethod(type, context.Options.Run2ExpectedTypes, "System", "Void");

            if (info.RunMethod1 == null || info.RunMethod2 == null)
                return null;
            
            return info;
        }

        private void ConvertFunctionSignatures(DevirtualisationContext context)
        {
            foreach (var entry in context.KoiStream.Exports.Where(x => !x.Value.IsSignatureOnly))
            {
                context.Logger.Debug(Tag, $"Converting VM signature of export {entry.Key} to method signature...");
                context.VirtualisedMethods.Add(
                    new VirtualisedMethod(new VMFunction(entry.Value.EntrypointAddress, entry.Value.EntryKey), entry.Key,
                        entry.Value)
                    {
                        MethodSignature = VMSignatureToMethodSignature(context, entry.Value.Signature)
                    });
            }
        }

        private void MapVMExportsToMethods(DevirtualisationContext context)
        {
            int matchedMethods = 0;
            
            foreach (var type in context.TargetModule.Assembly.Modules[0].GetAllTypes())
            {
                foreach (var method in type.Methods)
                {
                    if (!context.Options.SelectedMethods.Contains(method.MetadataToken.Rid))
                        continue;
                    
                    var matchingVmMethods = GetMatchingVirtualisedMethods(context, method);

                    if (matchingVmMethods.Count > 0
                        && method.CilMethodBody != null
                        && TryExtractExportTypeFromMethodBody(context, method.CilMethodBody, out int exportId))
                    {
                        context.Logger.Debug(Tag, $"Detected call to export {exportId} in {method}.");
                        var vmMethod = matchingVmMethods.FirstOrDefault(x => x.ExportId == exportId);
                        if (vmMethod != null)
                            vmMethod.CallerMethod = method;
                        else
                            context.Logger.Debug(Tag, $"Ignoring call to export {exportId} in {method}.");
                        matchedMethods++;
                    }
                }
            }
                
            
            
            if (matchedMethods < context.VirtualisedMethods.Count - 1)
            {
                context.Logger.Warning(Tag, $"Not all VM exports were mapped to physical method definitions "
                                            + $"({matchedMethods} out of {context.VirtualisedMethods.Count} were mapped). "
                                            + "Dummies will be added to the assembly for the remaining exports.");
            }
        }

        private bool TryExtractExportTypeFromMethodBody(DevirtualisationContext context, CilMethodBody methodBody, out int exportId)
        {
            exportId = 0;

            var instructions = methodBody.Instructions;
            var runCall = instructions.FirstOrDefault(x =>
                x.OpCode.Code == CilCode.Call
                && x.Operand is IMethodDefOrRef methodOperand
                && (Comparer.Equals(context.VMEntryInfo.RunMethod1, methodOperand)
                    || Comparer.Equals(context.VMEntryInfo.RunMethod2, methodOperand)
                ));
            
            if (runCall != null)
            {   
                
                
                var stack = new Stack<StackValue>();
                foreach (var instr in instructions)
                {
                    if (instr.Offset == runCall.Offset)
                    {
                        
                        int argCount = instr.GetStackPopCount(methodBody);
                        for (int i = 0; i < argCount; i++)
                        {
                            var value = stack.Pop();
                            if (TryInferExportId(value, out exportId))
                            {
                                return true;
                            }
                        }
                        
                        return false;
                    }

                    if (instr.IsLdcI4())
                    {
                        stack.Push(StackValue.FromInteger(instr.GetLdcI4Constant()));
                    }
                    else if (instr.OpCode.Code == CilCode.Ldstr)
                    {
                        stack.Push(StackValue.FromString(instr.Operand?.ToString()));
                    }
                    else
                    {
                        for (int i = 0; i < instr.GetStackPopCount(methodBody); i++)
                            stack.Pop();
                        for (int i = 0; i < instr.GetStackPushCount(); i++)
                            stack.Push(StackValue.Unknown);
                    }
                }
            }

            return false;
        }

        private static bool TryInferExportId(StackValue value, out int exportId)
        {
            if (value.Integer.HasValue)
            {
                exportId = value.Integer.Value;
                return true;
            }

            if (!string.IsNullOrEmpty(value.String))
            {
                if (int.TryParse(value.String, NumberStyles.Integer, CultureInfo.InvariantCulture, out exportId))
                    return true;

                try
                {
                    string decodedString = Encoding.UTF8.GetString(Convert.FromBase64String(value.String));
                    if (int.TryParse(decodedString, NumberStyles.Integer, CultureInfo.InvariantCulture, out exportId))
                        return true;
                }
                catch (FormatException)
                {
                }
            }

            exportId = 0;
            return false;
        }

        private ICollection<VirtualisedMethod> GetMatchingVirtualisedMethods(
            DevirtualisationContext context,
            MethodDefinition methodToMatch)
        {
            var matches = new List<VirtualisedMethod>();
            
            foreach (var vmMethod in context.VirtualisedMethods.Where(x => x.CallerMethod == null))
            {
                if (Comparer.Equals(methodToMatch.Signature, vmMethod.MethodSignature))
                    matches.Add(vmMethod);
            }

            return matches;
        }

        private MethodSignature VMSignatureToMethodSignature(DevirtualisationContext context, VMFunctionSignature signature)
        {
            var module = context.TargetModule;
            
            var returnType = ((ITypeDescriptor) module.LookupMember(signature.ReturnToken)).ToTypeSignature();
            var parameterTypes = signature.ParameterTokens
                .Select(x => ((ITypeDescriptor) module.LookupMember(x)).ToTypeSignature());

            var hasThis = (signature.Flags & context.Constants.FlagInstance) != 0;

            return new MethodSignature(
                hasThis ? CallingConventionAttributes.HasThis : 0,
                returnType,
                parameterTypes.Skip(hasThis ? 1 : 0));
        }

        private readonly struct StackValue
        {
            private StackValue(int? integer, string @string)
            {
                Integer = integer;
                String = @string;
            }

            public static StackValue Unknown => new StackValue(null, null);

            public int? Integer
            {
                get;
            }

            public string String
            {
                get;
            }

            public static StackValue FromInteger(int value)
            {
                return new StackValue(value, null);
            }

            public static StackValue FromString(string value)
            {
                return new StackValue(null, value);
            }
        }

    }
}
