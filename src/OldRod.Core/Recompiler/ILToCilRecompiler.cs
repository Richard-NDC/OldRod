
using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver.DotNet;
using AsmResolver.DotNet.Code.Cil;
using AsmResolver.DotNet.Signatures.Types;
using AsmResolver.PE.DotNet.Cil;
using OldRod.Core.Architecture;
using OldRod.Core.Ast.Cil;
using OldRod.Core.Ast.IL;
using OldRod.Core.Disassembly.ControlFlow;
using OldRod.Core.Disassembly.DataFlow;
using OldRod.Core.Recompiler.Transform;
using Rivers;

namespace OldRod.Core.Recompiler
{
    public class ILToCilRecompiler : IILAstVisitor<CilAstNode>
    {
        public const string Tag = "IL2CIL";
        
        public event EventHandler<CilCompilationUnit> InitialAstBuilt;
        public event EventHandler<CilTransformEventArgs> TransformStart;
        public event EventHandler<CilTransformEventArgs> TransformEnd;
        
        private readonly RecompilerContext _context;

        public ILToCilRecompiler(CilMethodBody methodBody, ModuleDefinition targetModule, IVMFunctionResolver exportResolver)
        {
            _context = new RecompilerContext(methodBody, targetModule, this, exportResolver);
        }

        public ILogger Logger
        {
            get => _context.Logger;
            set => _context.Logger = value;
        }

        public bool InferParameterTypes
        {
            get;
            set;
        }

        public CilCompilationUnit Recompile(ILCompilationUnit unit)
        {
            Logger.Debug(Tag, $"Building initial CIL AST...");
            var cilUnit = (CilCompilationUnit) unit.AcceptVisitor(this);
            OnInitialAstBuilt(cilUnit);
            
            Logger.Debug(Tag, $"Applying CIL AST transformations...");
            ApplyTransformations(cilUnit);

            foreach (var variable in _context.Variables.Values)
            {
                if (variable.AssignedBy.Count == 0 && variable.UsedBy.Count == 0)
                    cilUnit.Variables.Remove(variable);
            }
            
            return cilUnit;
        }

        private void ApplyTransformations(CilCompilationUnit cilUnit)
        {
            var transforms = new ICilAstTransform[]
            {
                new TypeInference(),
                new ArrayAccessTransform(),
                new TypeConversionInsertion(),
                new BoxMinimizer(), 
            };

            foreach (var transform in transforms)
            {
                var args = new CilTransformEventArgs(cilUnit, transform);
                Logger.Debug2(Tag, $"Applying {transform.Name}...");
                
                OnTransformStart(args);
                transform.ApplyTransformation(_context, cilUnit);
                OnTransformEnd(args);
            }
        }

        public CilAstNode VisitCompilationUnit(ILCompilationUnit unit)
        {
            var result = new CilCompilationUnit(unit.ControlFlowGraph);

            foreach (var variable in unit.Variables)
            {
                switch (variable)
                {
                    case ILFlagsVariable _:
                    {
                        CilVariable cilVariable;
                        
                        if (result.FlagVariable == null)
                        {
                            cilVariable = new CilVariable("FL", _context.TargetModule.CorLibTypeFactory.Byte);
                            
                            result.FlagVariable = cilVariable;
                            _context.FlagVariable = cilVariable;
                            result.Variables.Add(cilVariable);
                        }

                        cilVariable = result.FlagVariable;
                        _context.Variables[variable] = cilVariable;
                        break;
                    }

                    case ILParameter parameter:
                    {
                        var methodBody = _context.MethodBody;
                        var physicalParameter = methodBody.Owner.Parameters.GetBySignatureIndex(parameter.ParameterIndex);
                        bool isThisParameter = physicalParameter == methodBody.Owner.Parameters.ThisParameter;
                        
                        var cilParameter = new CilParameter(
                            parameter.Name,
                            physicalParameter.ParameterType,
                            parameter.ParameterIndex,
                            !InferParameterTypes || isThisParameter);

                        result.Parameters.Add(cilParameter);
                        _context.Parameters[parameter] = cilParameter;
                        break;
                    }

                    default:
                    {
                        var cilVariable = new CilVariable(variable.Name, variable.VariableType
                            .ToMetadataType(_context.TargetModule)
                            .ToTypeSignature());
                        result.Variables.Add(cilVariable);
                        _context.Variables[variable] = cilVariable;
                        break;
                    }
                }
            }

            if (result.FlagVariable == null)
            {
                var flagVariable = new CilVariable("FL", _context.TargetModule.CorLibTypeFactory.Byte);
                result.FlagVariable = flagVariable;
                _context.FlagVariable = flagVariable;
                result.Variables.Add(flagVariable);
            }

            foreach (var node in result.ControlFlowGraph.Nodes)
                node.UserData[CilAstBlock.AstBlockProperty] = new CilAstBlock();

            foreach (var node in result.ControlFlowGraph.Nodes)
            {
                var ilBlock = (ILAstBlock) node.UserData[ILAstBlock.AstBlockProperty];
                var cilBlock = (CilAstBlock) ilBlock.AcceptVisitor(this);
                node.UserData[CilAstBlock.AstBlockProperty] = cilBlock;
            }
            
            return result;
        }

        public CilAstNode VisitBlock(ILAstBlock block)
        {
            var currentNode = block.GetParentNode();
            var result = (CilAstBlock) currentNode.UserData[CilAstBlock.AstBlockProperty];
            foreach (var statement in block.Statements)
                result.Statements.Add((CilStatement) statement.AcceptVisitor(this));
            return result;
        }

        public CilAstNode VisitExpressionStatement(ILExpressionStatement statement)
        {
            var node = statement.Expression.AcceptVisitor(this);
            
            if (node is CilExpression expression)
            {
                if (expression.ExpressionType != null
                    && !expression.ExpressionType.IsTypeOf("System", "Void"))
                {
                    expression = new CilInstructionExpression(CilOpCodes.Pop, null, expression);
                }

                return new CilExpressionStatement(expression);
            }

            return (CilStatement) node;
        }

        public CilAstNode VisitAssignmentStatement(ILAssignmentStatement statement)
        {
            var cilExpression = (CilExpression) statement.Value.AcceptVisitor(this);
            
            var cilVariable = _context.Variables[statement.Variable];

            cilExpression.ExpectedType = cilVariable.VariableType;
            return new CilAssignmentStatement(cilVariable, cilExpression);
        }

        public CilAstNode VisitInstructionExpression(ILInstructionExpression expression)
        {

            if (expression.OpCode.Code == ILCode.LEAVE)
                return TranslateLeaveExpression(expression);
            
            switch (expression.OpCode.FlowControl)
            {
                case ILFlowControl.Jump:
                    return TranslateJumpExpression(expression);
                case ILFlowControl.ConditionalJump:
                    return TranslateConditionalJumpExpression(expression);
                case ILFlowControl.Return:
                    return TranslateRetExpression(expression);
                default:
                    return RecompilerService.GetOpCodeRecompiler(expression.OpCode.Code).Translate(_context, expression);
            }
        }

        private CilStatement TranslateRetExpression(ILInstructionExpression expression)
        {
            var node = expression.GetParentNode();

            var opCode = CilOpCodes.Ret;
            ITypeDescriptor expectedType = _context.MethodBody.Owner.Signature!.ReturnType;

            if (node.SubGraphs.Count > 0)
            {
                if (TryGetTopMostEhFrame(node, out var ehFrame) || TryGetContainingHandlerFrame(node, out ehFrame))
                {
                    switch (ehFrame.Type)
                    {
                        case EHType.FILTER:
                            opCode = CilOpCodes.Endfilter;
                            expectedType = _context.TargetModule.CorLibTypeFactory.Boolean;
                            break;

                        case EHType.FAULT:
                        case EHType.FINALLY:
                            opCode = CilOpCodes.Endfinally;
                            expectedType = null;
                            break;

                        case EHType.CATCH:
                            Logger.Warning(Tag,
                                $"Return instruction in {node.Name} appears inside a catch handler. Emitting ret.");
                            break;

                        default:
                            throw new ArgumentOutOfRangeException();
                    }
                }
                else
                {
                    Logger.Warning(Tag,
                        $"Return instruction in {node.Name} is inside an EH region but no top-most handler information was found. Emitting ret.");
                }
            }

            var expr = new CilInstructionExpression(opCode);
            if (expression.Arguments.Count > 0 && opCode != CilOpCodes.Endfinally)
            {
                var value = (CilExpression) expression.Arguments[0].AcceptVisitor(this);
                value.ExpectedType = expectedType;
                expr.Arguments.Add(value);
            }
            else if (expression.Arguments.Count > 0)
            {
                Logger.Warning(Tag,
                    $"Ignoring unexpected return value for endfinally emitted at {node.Name}.");
            }

            return new CilExpressionStatement(expr);
        }

        private static bool TryGetTopMostEhFrame(Node node, out EHFrame ehFrame)
        {
            if (node.UserData.TryGetValue(ControlFlowGraph.TopMostEHProperty, out var data) && data is EHFrame frame)
            {
                ehFrame = frame;
                return true;
            }

            ehFrame = null;
            return false;
        }

        private static bool TryGetContainingHandlerFrame(Node node, out EHFrame ehFrame)
        {
            foreach (var subGraph in node.SubGraphs.OrderBy(x => x.Nodes.Count))
            {
                if (!subGraph.UserData.TryGetValue(EHFrame.EHFrameProperty, out var ehData) || !(ehData is EHFrame frame))
                    continue;

                if (!subGraph.UserData.TryGetValue(ControlFlowGraph.HandlerBlockProperty, out var handlerData)
                    || !(handlerData is IEnumerable<Node> handlerNodes))
                {
                    continue;
                }

                if (handlerNodes.Contains(node))
                {
                    ehFrame = frame;
                    return true;
                }
            }

            ehFrame = null;
            return false;
        }

        private CilStatement TranslateJumpExpression(ILInstructionExpression expression)
        {
            var currentNode = expression.GetParentNode();
            var targetNode = currentNode.OutgoingEdges.First().Target;
            
            var targetBlock = (CilAstBlock) targetNode.UserData[CilAstBlock.AstBlockProperty];
            bool isLeave = currentNode.SubGraphs.Except(targetNode.SubGraphs).Any();
                
            return new CilExpressionStatement(new CilInstructionExpression(
                isLeave ? CilOpCodes.Leave : CilOpCodes.Br, 
                new CilInstructionLabel(targetBlock.BlockHeader)));
        }

        private CilStatement TranslateConditionalJumpExpression(ILInstructionExpression expression)
        {
            switch (expression.OpCode.Code)
            {
                case ILCode.JZ:
                    return TranslateSimpleCondJumpExpression(expression, CilOpCodes.Brfalse);
                case ILCode.JNZ:
                    return TranslateSimpleCondJumpExpression(expression, CilOpCodes.Brtrue);
                case ILCode.SWT:
                    return TranslateSwitchExpression(expression);
                default:
                    throw new ArgumentOutOfRangeException(nameof(expression));
            }
        }

        private CilStatement TranslateSimpleCondJumpExpression(ILInstructionExpression expression, CilOpCode opCode)
        {          
            var currentNode = expression.GetParentNode();
            var trueBlock = (CilAstBlock) currentNode.OutgoingEdges
                .First(x => x.UserData.ContainsKey(ControlFlowGraph.ConditionProperty))
                .Target
                .UserData[CilAstBlock.AstBlockProperty];
            
            var falseBlock = (CilAstBlock) currentNode.OutgoingEdges
                .First(x => !x.UserData.ContainsKey(ControlFlowGraph.ConditionProperty))
                .Target
                .UserData[CilAstBlock.AstBlockProperty];

            var conditionalBranch = new CilInstructionExpression(opCode,
                new CilInstructionLabel(trueBlock.BlockHeader));
            conditionalBranch.Arguments.Add((CilExpression) expression.Arguments[0].AcceptVisitor(this));
            
            return new CilAstBlock
            {
                Statements =
                {
                    new CilExpressionStatement(conditionalBranch),
                    
                    new CilExpressionStatement(new CilInstructionExpression(CilOpCodes.Br, 
                        new CilInstructionLabel(falseBlock.BlockHeader))),
                }
            };   
        }

        private CilStatement TranslateSwitchExpression(ILInstructionExpression expression)
        {
            var currentNode = expression.GetParentNode();

            var caseBlocks = new Dictionary<int, CilAstBlock>();
            CilAstBlock defaultBlock = null; 
            foreach (var edge in currentNode.OutgoingEdges)
            {
                var targetBlock = (CilAstBlock) edge.Target.UserData[CilAstBlock.AstBlockProperty];
                
                if (edge.UserData.TryGetValue(ControlFlowGraph.ConditionProperty, out var c))
                {
                    var conditions = (IEnumerable<int>) c;
                    
                    foreach (int condition in conditions)
                    {
                        if (condition != ControlFlowGraph.ExceptionConditionLabel
                            && condition != ControlFlowGraph.EndFinallyConditionLabel)
                        {
                            caseBlocks[condition] = targetBlock;
                        }
                    } 
                        
                }
                else if (defaultBlock == null)
                {
                    defaultBlock = targetBlock;
                }
                else
                {
                    throw new RecompilerException(
                        "Encountered a switch instruction that has multiple default case blocks."
                        + " This could mean the IL AST builder contains a bug or is incomplete. For more details, inspect "
                        + "the control flow graphs generated by the IL AST builder and each transform.");
                }
            }

            if (defaultBlock == null)
            {
                throw new RecompilerException(
                    "Encountered a switch instruction that does not have an edge to a default case block."
                    + " This could mean the IL AST builder contains a bug or is incomplete. For more details, inspect "
                    + "the control flow graphs generated by the IL AST builder and each transform.");
            }

            var caseLabels = new List<CilAstBlock>(caseBlocks.Count);
            foreach (var entry in caseBlocks.OrderBy(e => e.Key))
            {
                for (int i = caseLabels.Count; i < entry.Key; i++)
                    caseLabels.Add(defaultBlock);
                
                caseLabels.Add(entry.Value);
            }

            var valueExpression = (CilExpression) expression.Arguments[1].AcceptVisitor(this);
            valueExpression.ExpectedType = _context.TargetModule.CorLibTypeFactory.Int32;
            
            var table = caseLabels
                .Select(x => (ICilLabel) new CilInstructionLabel(x.BlockHeader))
                .ToArray();
            
            var switchExpression = new CilInstructionExpression(CilOpCodes.Switch, table, valueExpression);

            return new CilAstBlock
            {
                Statements =
                {
                    new CilExpressionStatement(switchExpression),

                    new CilExpressionStatement(new CilInstructionExpression(CilOpCodes.Br,
                        new CilInstructionLabel(defaultBlock.BlockHeader))),
                }
            };
        }

        private CilStatement TranslateLeaveExpression(ILInstructionExpression expression)
        {
            var targetBlock = (CilAstBlock) expression.GetParentNode().OutgoingEdges.First()
                .Target.UserData[CilAstBlock.AstBlockProperty];
            
            var result = new CilInstructionExpression(CilOpCodes.Leave, 
                new CilInstructionLabel(targetBlock.BlockHeader));
            return new CilExpressionStatement(result);
        }

        public CilAstNode VisitVariableExpression(ILVariableExpression expression)
        {
            var cilVariable = expression.Variable is ILParameter parameter
                ? _context.Parameters[parameter]
                : _context.Variables[expression.Variable];

            var result = new CilVariableExpression(cilVariable)
            {
                ExpressionType = cilVariable.VariableType,
                IsReference = expression.IsReference,
            };

            if (expression.IsReference)
                result.ExpressionType = new ByReferenceTypeSignature((TypeSignature) result.ExpressionType);
            
            return result;
        }

        public CilAstNode VisitVCallExpression(ILVCallExpression expression)
        {
            return RecompilerService.GetVCallRecompiler(expression.Call).Translate(_context, expression);
        }

        public CilAstNode VisitPhiExpression(ILPhiExpression expression)
        {
            
            
            throw new RecompilerException(
                "Encountered a stray phi node in the IL AST. This could mean the IL AST builder contains a "
                + "bug or is incomplete. For more details, inspect the control flow graphs generated by the IL AST "
                + "builder and each transform.");
        }

        public CilAstNode VisitExceptionExpression(ILExceptionExpression expression)
        {
            return new CilInstructionExpression(CilOpCodes.Nop)
            {
                ExpressionType = expression.ExceptionType
            }; 
        }

        protected virtual void OnInitialAstBuilt(CilCompilationUnit cilUnit)
        {
            InitialAstBuilt?.Invoke(this, cilUnit);
        }

        protected virtual void OnTransformStart(CilTransformEventArgs e)
        {
            TransformStart?.Invoke(this, e);
        }

        protected virtual void OnTransformEnd(CilTransformEventArgs e)
        {
            TransformEnd?.Invoke(this, e);
        }
    }
}
