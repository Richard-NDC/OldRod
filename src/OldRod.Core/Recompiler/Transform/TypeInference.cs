
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;
using OldRod.Core.Ast.Cil;

namespace OldRod.Core.Recompiler.Transform
{
    public class TypeInference : ChangeAwareCilAstTransform
    {
        private static readonly SignatureComparer Comparer = new SignatureComparer();
        
        private TypeHelper _helper;
        private RecompilerContext _context;
        
        public override string Name => "Type Inference";

        public override bool ApplyTransformation(RecompilerContext context, CilCompilationUnit unit)
        {
            _context = context;
            _helper = new TypeHelper(context.ReferenceImporter);
            return base.ApplyTransformation(context, unit);
        }

        public override bool VisitCompilationUnit(CilCompilationUnit unit)
        {
            bool changed = false;
            
            foreach (var variable in unit.Variables.Where(x => x.UsedBy.Count > 0))
                changed |= TryInferVariableType(variable);

            foreach (var parameter in unit.Parameters.Where(x => x.UsedBy.Count > 0 && !x.HasFixedType))
                changed |= TryInferVariableType(parameter);

            return changed;
        }

        private bool TryInferVariableType(CilVariable variable)
        {
            if (_context.FlagVariable == variable)
                return false;
            
            var expectedTypes = CollectExpectedTypes(variable)
                .Where(t => t != null)
                .ToArray();

            if (expectedTypes.Length == 0)
                return false;

            ITypeDescriptor newVariableType = null;
            
            if (expectedTypes.Any(t => t.IsTypeOf("System", "Array")))
                newVariableType = TryInferArrayType(variable);

            if (newVariableType == null) 
                newVariableType = _helper.GetCommonBaseType(expectedTypes);

            return TrySetVariableType(variable, newVariableType);
        }

        private ICollection<ITypeDescriptor> CollectExpectedTypes(CilVariable variable)
        {
            var expectedTypes = new List<ITypeDescriptor>();
            foreach (var use in variable.UsedBy)
            {
                var expectedType = use.ExpectedType;
                if (expectedType == null)
                    continue;
                
                if (!use.IsReference)
                {
                    expectedTypes.Add(expectedType);
                }
                else if (expectedType is ByReferenceTypeSignature byRefType)
                {
                    expectedTypes.Add(byRefType.BaseType);
                }
                else
                {

                    throw new RecompilerException(
                        $"Variable {use.Variable.Name} in the expression `{use.Parent}` in "
                        + $"{_context.MethodBody.Owner.Name} ({_context.MethodBody.Owner.MetadataToken}) was passed on " +
                        $"by reference, but does not have a by-reference expected type.");
                }
            }

            return expectedTypes;
        }

        private ITypeDescriptor TryInferArrayType(CilVariable variable)
        {
            if (variable.AssignedBy.Count == 0)
                return null;
            
            var types = variable.AssignedBy
                .Select(a => a.Value.ExpressionType)
                .ToArray();

            if (types.Length > 0
                && types[0] is SzArrayTypeSignature arrayType
                && types.All(t => t != null && Comparer.Equals(t, arrayType)))
            {
                return arrayType;
            }

            return null;
        }

        private bool TrySetVariableType(CilVariable variable, ITypeDescriptor variableType)
        {
            if (variableType != null
                && (variable.VariableType == null || variable.VariableType.FullName != variableType.FullName))
            {
                TypeSignature newType = _context.TargetModule.CorLibTypeFactory.FromType(variableType);
                if (newType == null)
                {
                    var newTypeSignature = variableType.ToTypeSignature();
                    if (newTypeSignature == null)
                        return false;

                    newType = _context.ReferenceImporter.ImportTypeSignature(newTypeSignature);
                    if (newType == null)
                        return false;
                }

                variable.VariableType = newType;

                foreach (var use in variable.UsedBy)
                {
                    use.ExpressionType = use.IsReference
                        ? new ByReferenceTypeSignature(newType)
                        : newType;
                }

                foreach (var assign in variable.AssignedBy)
                    assign.Value.ExpectedType = newType;

                return true;
            }

            return false;
        }
    }
}
