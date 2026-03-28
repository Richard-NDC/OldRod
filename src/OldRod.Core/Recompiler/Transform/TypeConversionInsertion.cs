
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.DotNet.Metadata.Tables.Rows;
using OldRod.Core.Ast.Cil;

namespace OldRod.Core.Recompiler.Transform
{
    public class TypeConversionInsertion : ChangeAwareCilAstTransform
    {
        private RecompilerContext _context;

        public override string Name => "Type Conversion Insertion";

        public override bool ApplyTransformation(RecompilerContext context, CilCompilationUnit unit)
        {
            _context = context;
            return base.ApplyTransformation(context, unit);
        }

        public override bool VisitInstructionExpression(CilInstructionExpression expression)
        {
            if (TryOptimizeLdcI(expression))
                return true;
            
            bool changed = base.VisitInstructionExpression(expression);

            foreach (var argument in expression.Arguments.ToArray())
                changed |= EnsureTypeSafety(argument);

            return changed;
        }

        public override bool VisitAssignmentStatement(CilAssignmentStatement statement)
        {
            return base.VisitAssignmentStatement(statement) | EnsureTypeSafety(statement.Value);
        }

        private static unsafe bool TryOptimizeLdcI(CilInstructionExpression expression)
        {
            if (expression.Instructions.Count != 1 || expression.ExpectedType == null)
                return false;

            var instruction = expression.Instructions[0];
            
            if (instruction.IsLdcI4())
            {
                int i4Value = instruction.GetLdcI4Constant();
                if (!expression.ExpectedType.IsValueType)
                {
                    if (i4Value == 0)
                    {
                        ReplaceWithSingleInstruction(expression, new CilInstruction(CilOpCodes.Ldnull));
                        return true;
                    }
                }
                else if (expression.ExpectedType.IsTypeOf("System", "Single"))
                {
                    float actualValue = *(float*) &i4Value;
                    ReplaceWithSingleInstruction(expression, new CilInstruction(CilOpCodes.Ldc_R4, actualValue));
                    return true;
                }
            }
            else if (instruction.OpCode.Code == CilCode.Ldc_I8 && expression.ExpectedType.IsTypeOf("System", "Double"))
            {
                long i8Value = (long) instruction.Operand;
                double actualValue = *(double*) &i8Value;
                ReplaceWithSingleInstruction(expression, new CilInstruction(CilOpCodes.Ldc_R8, actualValue));
                return true;
            }

            return false;
        }

        private static void ReplaceWithSingleInstruction(CilInstructionExpression expression, CilInstruction newInstruction)
        {
            expression.Instructions.Clear();
            expression.Instructions.Add(newInstruction);
            expression.ExpressionType = expression.ExpectedType;
        }

        private bool EnsureTypeSafety(CilExpression argument)
        {
            if (argument?.ExpressionType == null || argument.ExpectedType == null)
                return false;

            bool changed = false;
            
            if (!_context.TypeHelper.IsAssignableTo(argument.ExpressionType, argument.ExpectedType))
            {
                if (!argument.ExpressionType.IsValueType && argument.ExpectedType.IsValueType)
                {
                    changed = ConvertRefTypeToValueType(argument);
                }
                else if (!argument.ExpressionType.IsValueType && !argument.ExpectedType.IsValueType)
                {
                    CastClass(argument);
                    changed = true;
                }
                else if (argument.ExpressionType.IsValueType && !argument.ExpectedType.IsValueType)
                {
                    var newArg = Box(argument);
                    if (!newArg.ExpectedType.IsTypeOf("System", "Object"))
                        CastClass(newArg);

                    changed = true;
                }
                else if (argument.ExpressionType.IsValueType && argument.ExpectedType.IsValueType)
                {
                    changed = !ReferenceEquals(ConvertValueType(argument), argument);
                }
            }

            return changed;
        }

        private bool ConvertRefTypeToValueType(CilExpression argument)
        {
            if (argument?.ExpressionType == null || argument.ExpectedType == null)
                return false;

            if (argument.ExpressionType.IsTypeOf("System", "Object"))
            {
                if (argument is CilInstructionExpression e
                    && e.Instructions.Count == 1)
                {
                    switch (e.Instructions[0].OpCode.Code)
                    {
                        case CilCode.Ldind_Ref:
                            LdObj(e);
                            break;

                        case CilCode.Box:
                            e.Arguments[0].ExpectedType = argument.ExpectedType;
                            argument.ReplaceWith(ConvertValueType(e.Arguments[0]).Remove());
                            return true;

                        default:
                            UnboxAny(argument);
                            break;
                    }
                }
                else
                {
                    UnboxAny(argument);
                }

                return true;
            }

            if (argument.ExpressionType is PointerTypeSignature)
            {
                ConvertValueType(argument);
                return true;
            }

            return false;
        }

        private CilExpression UnboxAny(CilExpression argument)
        {
            var type = argument.ExpectedType?.ToTypeDefOrRef();
            if (type == null)
                return argument;

            var newArgument = new CilInstructionExpression(CilOpCodes.Unbox_Any,
                _context.ReferenceImporter.ImportType(type))
            {
                ExpectedType = argument.ExpectedType,
                ExpressionType = argument.ExpectedType,
            };   
            ReplaceArgument(argument, newArgument);
            
            return newArgument;
        }

        private CilExpression LdObj(CilInstructionExpression argument)
        {
            var type = argument.ExpectedType?.ToTypeDefOrRef();
            if (type == null)
                return argument;

            var newArgument = new CilInstructionExpression(CilOpCodes.Ldobj,
                _context.ReferenceImporter.ImportType(type))
            {
                ExpectedType = argument.ExpectedType,
                ExpressionType = argument.ExpectedType
            };
            argument.ReplaceWith(newArgument);
            
            foreach (var arg in argument.Arguments.ToArray())
                newArgument.Arguments.Add((CilExpression) arg.Remove());
            
            return newArgument;
        }

        private CilExpression Box(CilExpression argument)
        {
            var type = argument.ExpressionType?.ToTypeDefOrRef();
            if (type == null)
                return argument;

            var newArgument = new CilInstructionExpression(CilOpCodes.Box,
                _context.ReferenceImporter.ImportType(type))
            {
                ExpectedType = argument.ExpectedType,
                ExpressionType = _context.TargetModule.CorLibTypeFactory.Object,
            };
            ReplaceArgument(argument, newArgument);

            return newArgument;
        }

        private CilExpression CastClass(CilExpression argument)
        {
            var type = argument.ExpectedType?.ToTypeDefOrRef();
            if (type == null)
                return argument;

            var newArgument = new CilInstructionExpression(CilOpCodes.Castclass,
                _context.ReferenceImporter.ImportType(type))
            {
                ExpectedType = argument.ExpectedType,
                ExpressionType = argument.ExpectedType,
            };
            ReplaceArgument(argument, newArgument);
            
            return newArgument;
        }

        private CilExpression ConvertValueType(CilExpression argument)
        {
            if (argument?.ExpectedType == null || argument.ExpressionType == null)
                return argument;

            if (argument.ExpectedType.FullName == argument.ExpressionType.FullName)
                return argument;
            
            var corlibType = _context.TargetModule.CorLibTypeFactory.FromType(argument.ExpectedType);
            if (corlibType == null)
            {
                var typeDef = argument.ExpectedType.Resolve();

                if (typeDef?.IsEnum == true)
                {
                    var underlyingType = typeDef.GetEnumUnderlyingType();
                    if (underlyingType != null && argument.ExpressionType.FullName == underlyingType.FullName)
                    {
                        argument.ExpressionType = argument.ExpectedType;
                        return argument;
                    }
                    
                    corlibType = _context.TargetModule.CorLibTypeFactory.FromType(underlyingType);
                }
                
                if (corlibType == null)
                    return argument;
            }
            
            var opCode = SelectPrimitiveConversionOpCode(argument, corlibType.ElementType);
            var newArgument = new CilInstructionExpression(opCode)
            {
                ExpectedType = argument.ExpectedType,
                ExpressionType = argument.ExpectedType
            };
            ReplaceArgument(argument, newArgument);

            return newArgument;
        }

        private static CilOpCode SelectPrimitiveConversionOpCode(CilExpression argument, ElementType elementType)
        {
            CilOpCode code;
            switch (elementType)
            {
                case ElementType.I1:
                    code = CilOpCodes.Conv_I1;
                    break;
                case ElementType.U1:
                    code = CilOpCodes.Conv_U1;
                    break;
                case ElementType.I2:
                    code = CilOpCodes.Conv_I2;
                    break;
                case ElementType.Char:
                case ElementType.U2:
                    code = CilOpCodes.Conv_U2;
                    break;
                case ElementType.Boolean:
                case ElementType.I4:
                    code = CilOpCodes.Conv_I4;
                    break;
                case ElementType.U4:
                    code = CilOpCodes.Conv_U4;
                    break;
                case ElementType.I8:
                    code = CilOpCodes.Conv_I8;
                    break;
                case ElementType.U8:
                    code = CilOpCodes.Conv_U8;
                    break;
                case ElementType.R4:
                    code = CilOpCodes.Conv_R4;
                    break;
                case ElementType.R8:
                    code = CilOpCodes.Conv_R8;
                    break;
                case ElementType.I:
                    code = CilOpCodes.Conv_I;
                    break;
                case ElementType.U:
                    code = CilOpCodes.Conv_U;
                    break;
                default:
                    throw new RecompilerException(
                        $"Conversion from value type {argument.ExpressionType} to value type {argument.ExpectedType} is not supported.");
            }

            return code;
        }

        private static void ReplaceArgument(CilExpression argument, CilInstructionExpression newArgument)
        {
            argument.ReplaceWith(newArgument);
            argument.ExpectedType = argument.ExpressionType;
            newArgument.Arguments.Add(argument);
        }
            
    }
}
