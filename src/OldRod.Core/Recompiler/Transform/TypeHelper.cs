
using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Signatures;
using AsmResolver.DotNet.Signatures.Types;

namespace OldRod.Core.Recompiler.Transform
{
    public class TypeHelper
    {
        private readonly ITypeDefOrRef _arrayType;
        private readonly ITypeDefOrRef _objectType;

        private readonly IList<TypeSignature> _signedIntegralTypes;
        private readonly IList<TypeSignature> _unsignedIntegralTypes;
        private readonly IList<TypeSignature> _integralTypes;

        public TypeHelper(ReferenceImporter importer)
        {
            var ownerModule = importer.TargetModule;
            var factory = ownerModule.CorLibTypeFactory;
            var scope = ownerModule.CorLibTypeFactory.CorLibScope;

            _arrayType = new TypeReference(ownerModule, scope, "System", "Array");
            _objectType = new TypeReference(ownerModule, scope, "System", "Object");

            _signedIntegralTypes = new TypeSignature[]
            {
                factory.SByte,
                factory.Int16,
                factory.Int32,
                factory.IntPtr,
                factory.Int64,
            };
            
            _unsignedIntegralTypes = new TypeSignature[]
            {
                factory.Byte,
                factory.UInt16,
                factory.UInt32,
                factory.UIntPtr,
                factory.UInt64,
            };

            _integralTypes = new TypeSignature[]
            {
                factory.SByte,
                factory.Byte,
                factory.Int16,
                factory.UInt16,
                factory.Int32,
                factory.UInt32,
                factory.IntPtr,
                factory.UIntPtr,
                factory.Int64,
                factory.UInt64,
            };
        }
        
        public IList<ITypeDescriptor> GetTypeHierarchy(ITypeDescriptor type)
        {
            var result = new List<ITypeDescriptor>();
            
            TypeSignature typeSig;
            switch (type)
            {
                case ArrayTypeSignature _:
                case SzArrayTypeSignature _:
                    result.AddRange(GetTypeHierarchy(_arrayType));
                    result.Add(type);
                    return result;
                
                case ByReferenceTypeSignature byRef:
                    result.AddRange(GetTypeHierarchy(byRef.BaseType));
                    return result;
                
                case TypeSpecification typeSpec:
                    result.AddRange(GetTypeHierarchy(typeSpec.Signature));
                    result.Add(typeSpec);
                    return result;
                
                case GenericParameterSignature genericParam:
                    result.Add(_objectType);
                    return result;
                
                case null:
                    return Array.Empty<ITypeDescriptor>();
                
                default:
                    typeSig = type.ToTypeSignature();
                    break;
            }
            
            var genericContext = new GenericContext(null, null);
            
            while (typeSig != null)
            {
                if (typeSig is GenericInstanceTypeSignature genericInstance)
                    genericContext = new GenericContext(genericInstance, null);

                result.Add(typeSig);

                var typeDef = typeSig.ToTypeDefOrRef()?.Resolve();
                if (typeDef is null)
                    break;

                if (typeDef.IsEnum)
                    typeSig = typeDef.GetEnumUnderlyingType();
                else if (typeDef.IsInterface && typeDef.BaseType is null)
                    typeSig = _objectType.ToTypeSignature();
                else
                    typeSig = typeDef.BaseType?.ToTypeSignature().InstantiateGenericTypes(genericContext);
            }

            result.Reverse();
            return result;
        }

        public bool IsIntegralType(ITypeDescriptor type)
        {
            if (type == null)
                return false;

            return _integralTypes.Any(x => type.IsTypeOf(x.Namespace, x.Name));
        }
        
        public bool IsOnlyIntegral(IEnumerable<ITypeDescriptor> types)
        {
            var typeList = types?
                .Where(t => t != null)
                .ToList();

            return typeList?.Count > 0 && typeList.All(IsIntegralType);
        }

        public TypeSignature GetBiggestIntegralType(IEnumerable<ITypeDescriptor> types)
        {
            TypeSignature biggest = null;
            int biggestIndex = 0;
            
            foreach (var type in types)
            {
                if (type == null)
                    continue;

                int index = 0;
                for (index = 0; index < _integralTypes.Count; index++)
                {
                    if (_integralTypes[index].IsTypeOf(type.Namespace, type.Name))
                        break;
                }

                if (index > biggestIndex && index < _integralTypes.Count)
                {
                    biggest = _integralTypes[index];
                    biggestIndex = index;
                }
            }

            return biggest;
        }

        private static TypeDefinition SafeResolve(ITypeDescriptor type)
        {
            try
            {
                return type?.Resolve();
            }
            catch
            {
                return null;
            }
        }
        
        public ITypeDescriptor GetCommonBaseType(ICollection<ITypeDescriptor> types)
        {
            if (types == null || types.Count == 0)
                return _objectType;

            var typeList = types
                .Where(t => t != null)
                .ToList();

            if (typeList.Count == 0)
                return _objectType;

            if (typeList.Count == 1)
                return typeList[0];
            
            if (IsOnlyIntegral(typeList))
            {
                ITypeDescriptor integralType = GetBiggestIntegralType(typeList);
                return integralType ?? _objectType;
            }

            
            
            var hierarchies = typeList
                .Where(t => SafeResolve(t)?.IsInterface != true)
                .Select(GetTypeHierarchy)
                .Where(h => h.Count > 0)
                .ToList();
            if (hierarchies.Count == 0)
                return _objectType;
            
            ITypeDescriptor commonType = _objectType;

            int currentTypeIndex = 0;
            while (hierarchies.Count > 0)
            {
                ITypeDescriptor nextType = null;

                for (int i = 0; i < hierarchies.Count; i++)
                {
                    var hierarchy = hierarchies[i];
                    if (currentTypeIndex >= hierarchy.Count)
                    {
                        hierarchies.RemoveAt(i);
                        i--;
                    }
                    else if (nextType == null)
                    {
                        nextType = hierarchy[currentTypeIndex];
                    }
                    else
                    {
                        if (hierarchy[currentTypeIndex]?.FullName != nextType?.FullName)
                            return commonType;
                    }
                }

                if (nextType == null)
                    return commonType;
                
                commonType = nextType;
                currentTypeIndex++;
            }

            return commonType;
        }

        public bool IsAssignableTo(ITypeDescriptor from, ITypeDescriptor to)
        {
            if (from == null
                || to == null
                || from.FullName == to.FullName
                || from.IsTypeOf("System", "Int32") && to.IsTypeOf("System", "Boolean"))
            {
                return true;
            }

            if (from.IsValueType != to.IsValueType)
                return false;

            var typeHierarchy = GetTypeHierarchy(from);
            return typeHierarchy.Any(x => x?.FullName == to.FullName);
        }
    }
}
