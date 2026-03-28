
using System;
using System.Collections.Generic;
using System.Linq;
using AsmResolver;
using OldRod.Core.Architecture;
using OldRod.Core.Disassembly.ControlFlow;
using OldRod.Core.Disassembly.DataFlow;

namespace OldRod.Core.Disassembly.Inference
{
    public class InferenceDisassembler
    {
        public event EventHandler<FunctionEventArgs> FunctionInferred;
        
        private const string Tag = "InferenceDisasm";
        
        private readonly InstructionDecoder _decoder;
        private readonly InstructionProcessor _processor;
        private readonly IDictionary<uint, VMFunction> _functions = new Dictionary<uint, VMFunction>();
        private readonly ControlFlowGraphBuilder _cfgBuilder;

        public InferenceDisassembler(VMConstants constants, KoiStream koiStream)
        {
            Constants = constants ?? throw new ArgumentNullException(nameof(constants));
            KoiStream = koiStream ?? throw new ArgumentNullException(nameof(koiStream));
            _decoder = new InstructionDecoder(constants, KoiStream.Contents.CreateReader());
            _processor = new InstructionProcessor(this);
            _cfgBuilder = new ControlFlowGraphBuilder();

        }

        public ILogger Logger
        {
            get => _cfgBuilder.Logger;
            set => _cfgBuilder.Logger = value;
        }

        public VMConstants Constants
        {
            get;
        }

        public KoiStream KoiStream
        {
            get;
        }

        public IVMFunctionFactory FunctionFactory
        {
            get;
            set;
        }

        public bool SalvageCfgOnError
        {
            get => _cfgBuilder.SalvageOnError;
            set => _cfgBuilder.SalvageOnError = value;
        }

        public IExitKeyResolver ExitKeyResolver
        {
            get;
            set;
        }

        public bool ResolveUnknownExitKeys
        {
            get;
            set;
        } = false;
        
        public ISMCTrampolineDetector SMCTrampolineDetector 
        {
            get;
            set;
        }
        
        public void AddFunction(VMFunction function)
        {
            _functions.Add(function.EntrypointAddress, function);
        }

        public VMFunction GetOrCreateFunctionInfo(uint address, uint entryKey)
        {
            if (!_functions.TryGetValue(address, out var function))
            {
                Logger.Debug(Tag, $"Inferred new function_{address:X4} with entry key {entryKey:X8}.");

                function = FunctionFactory != null
                    ? FunctionFactory.CreateFunction(address, entryKey)
                    : new VMFunction(address, entryKey);
                
                _functions.Add(address, function);
                OnFunctionInferred(new FunctionEventArgs(function));
            }

            return function;
        }
        
        public IDictionary<uint, ControlFlowGraph> DisassembleFunctions()
        {
            if (_functions.Count == 0)
                throw new InvalidOperationException("Cannot start disassembly procedure if no functions have been added yet to the symbols.");

            try
            {
                while (DisassembleFunctionsImpl() 
                       && _functions.Any(f => !f.Value.ExitKey.HasValue)
                       && ResolveUnknownExitKeys
                       && TryResolveExitKeys())
                {
                }
            }
            catch (DisassemblyException ex) when (SalvageCfgOnError)
            {
                Logger.Error(Tag, ex.Message);
                Logger.Log(Tag, "Attempting to salvage control flow graphs...");
            }

            return ConstructControlFlowGraphs();
        }

        private bool DisassembleFunctionsImpl()
        {
            bool changedAtLeastOnce = false;
            bool changed = true;

            while (changed)
            {
                changed = false;

                int functionsCount = _functions.Count;
                foreach (var function in _functions.Values.ToArray())
                    changed |= ContinueDisassemblyForFunction(function);

                changedAtLeastOnce |= changed;
                changed |= functionsCount != _functions.Count;
            }

            return changedAtLeastOnce;
        }

        private bool ContinueDisassemblyForFunction(VMFunction function)
        {
            bool changed = false;
            
            var initialStates = new List<ProgramState>();
            if (function.Instructions.Count == 0)
            {
                Logger.Debug(Tag, $"Started disassembling function_{function.EntrypointAddress:X4}...");
                var initialState = new ProgramState()
                {
                    IP = function.EntrypointAddress,
                    Key = function.EntryKey,
                };
                initialState.Stack.Push(new SymbolicValue(
                    new ILInstruction(1, ILOpCodes.CALL, function.EntrypointAddress),
                    VMType.Qword));
                initialStates.Add(initialState);
                function.BlockHeaders.Add(function.EntrypointAddress);
            }
            else if (function.UnresolvedOffsets.Count > 0)
            {

                Logger.Debug(Tag,
                    $"Revisiting {function.UnresolvedOffsets.Count} unresolved offsets of function_{function.EntrypointAddress:X4}...");
                foreach (long offset in function.UnresolvedOffsets)
                    initialStates.Add(function.Instructions[offset].ProgramState);
            }

            if (initialStates.Count > 0)
            {
                changed = ContinueDisassembly(function, initialStates);

                if (function.UnresolvedOffsets.Count > 0)
                {
                    Logger.Debug(Tag,
                        $"Disassembly procedure stopped with {function.UnresolvedOffsets.Count} "
                        + $"unresolved offsets (new instructions decoded: {changed}).");
                }
                else if (function.Instructions.Count == 0)
                {
                    Logger.Warning(Tag,
                        $"Disassembly finalised with {function.Instructions.Count} instructions.");
                }
                else
                {
                    Logger.Debug(Tag,
                        $"Disassembly finalised with {function.Instructions.Count} instructions.");
                }
            }

            return changed;
        }

        private bool ContinueDisassembly(VMFunction function, IEnumerable<ProgramState> initialStates)
        {
            bool changed = false;
            
            var agenda = new Stack<ProgramState>();
            var initials = new HashSet<ulong>();
            foreach (var state in initialStates)
            {
                initials.Add(state.IP);
                agenda.Push(state);
            }

            while (agenda.Count > 0)
            {
                var currentState = agenda.Pop();

                if (function.Instructions.TryGetValue((long) currentState.IP, out var instruction))
                {
                    _decoder.ReaderOffset = (uint) currentState.IP;
                    _decoder.CurrentKey = currentState.Key;
                    
                    ILInstruction instruction2;
                    if (!TryReadInstruction(function, currentState, out instruction2))
                        continue;

                    if (instruction2.OpCode.Code != instruction.OpCode.Code)
                    {
                        throw new DisassemblyException(
                            $"Detected joining control flow paths in function_{function.EntrypointAddress:X4} "
                              + $"converging to the same offset (IL_{instruction.Offset:X4}) but decoding to different instructions.");
                    }

                    if (instruction.ProgramState.MergeWith(currentState) || initials.Contains(currentState.IP))
                        currentState = instruction.ProgramState;
                    else
                        continue;
                }
                else
                {
                    _decoder.ReaderOffset = (uint) currentState.IP;
                    _decoder.CurrentKey = currentState.Key;

                    if (SMCTrampolineDetector is not null && function.SMCTrampolineOffsetRange.IsEmpty
                                                          && function.BlockHeaders.Contains((long)currentState.IP)
                                                          && SMCTrampolineDetector.IsSMCTrampoline(currentState, out byte smcKey, out ulong trampolineEnd)) 
                    {
                        function.SMCTrampolineOffsetRange = new OffsetRange(currentState.IP, trampolineEnd);
                        function.SMCTrampolineKey = smcKey;
                    }

                    if (!TryReadInstruction(function, currentState, out instruction))
                        continue;

                    instruction.ProgramState = currentState;
                    function.Instructions.Add((long) currentState.IP, instruction);
                    changed = true;
                }

                currentState.Registers[VMRegisters.IP] = new SymbolicValue(instruction, VMType.Qword);

                try
                {
                    foreach (var state in _processor.GetNextStates(function, currentState, instruction,
                                 _decoder.CurrentKey))
                    {
                        agenda.Push(state);
                    }
                }
                catch (Exception ex) when (SalvageCfgOnError)
                {
                    Logger.Error(Tag, $"Could not infer next program states of {instruction}. " + ex.Message);
                }
            }

            return changed;
        }

        private bool TryReadInstruction(VMFunction function, ProgramState currentState, out ILInstruction instruction)
        {
            try
            {
                if (function.SMCTrampolineOffsetRange.Contains(currentState.IP))
                    instruction = _decoder.ReadNextInstruction(function.SMCTrampolineKey);
                else
                    instruction = _decoder.ReadNextInstruction();

                return true;
            }
            catch (DisassemblyException ex)
            {
                bool isFunctionEntrypoint = currentState.IP == function.EntrypointAddress;
                bool isFirstInstruction = function.Instructions.Count == 0;
                if (isFunctionEntrypoint && isFirstInstruction)
                    throw;

                Logger.Warning(Tag,
                    $"Ignoring invalid control-flow path in function_{function.EntrypointAddress:X4} " +
                    $"at IL_{currentState.IP:X4}. {ex.Message}");

                instruction = null;
                return false;
            }
        }

        private Dictionary<uint, ControlFlowGraph> ConstructControlFlowGraphs()
        {   
            var result = new Dictionary<uint, ControlFlowGraph>();
            foreach (var entry in _functions)
            {
                try
                {
                    if (entry.Value.UnresolvedOffsets.Count > 0)
                    {
                        Logger.Warning(Tag,
                            string.Format("Could not resolve the next states of some offsets of function_{0:X4} ({1}).",
                                entry.Key,
                                string.Join(", ", entry.Value.UnresolvedOffsets
                                    .Select(x => "IL_" + x.ToString("X4")))));
                    }

                    Logger.Debug(Tag, $"Constructing CFG of function_{entry.Key:X4}...");
                    result[entry.Key] = _cfgBuilder.BuildGraph(entry.Value);   
                }
                catch (Exception ex) when (SalvageCfgOnError)
                {
                    Logger.Error(Tag,
                        $"Failed to construct control flow graph of function_{entry.Key:X4}. " + ex.Message);
                }
            }

            return result;
        }

        private bool TryResolveExitKeys()
        {
            if (ExitKeyResolver == null)
            {
                throw new DisassemblyException(
                    $"{nameof(ResolveUnknownExitKeys)} was set to true, but no exit key resolver was provided.");
            }

            Logger.Log(Tag, $"Trying to resolve any exit keys using {ExitKeyResolver.Name}...");
            
            var unresolvedFunctions = _functions.Values
                    .Where(f => !f.ExitKey.HasValue)
                    .OrderByDescending(f => f.References.Count)
#if DEBUG
                    .ToArray()
#endif
                ;
            
            foreach (var function in unresolvedFunctions)
            {
                Logger.Log(Tag, $"Attempting to resolve exit key of function_{function.EntrypointAddress:X4}...");
                var exitKey = ExitKeyResolver.ResolveExitKey(Logger, KoiStream, Constants, function);
                if (exitKey.HasValue)
                {
                    Logger.Log(Tag,
                        $"Resolved exit key {exitKey.Value:X8} for function_{function.EntrypointAddress:X4}.");
                    function.ExitKey = exitKey;
                    return true;
                }
            }

            return false;
        }

        protected virtual void OnFunctionInferred(FunctionEventArgs e)
        {
            FunctionInferred?.Invoke(this, e);
        }
    }
}
