#! /usr/bin/env python

# Copyright (c) 2012, derrotehund361@googlemail.com
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution. 
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Cod file analysis code
"""

from instruction_reference import terminals, branches, conditional_branches, compound_branches
from instruction_reference import throwers, potential_throwers, restricted_throwers

from resolve import ClassDef, RoutineDef, FieldDef

MAX_INSTR_LEN = 100

class AnalysisException(Exception):
    pass


class JVMInstruction:
    def __init__(self, instruction):
        self.instruction = instruction
        # list of tuples of the form (condition, basic_block) possibly making entry into this basic block
        self.entry = []
        # dictionary of basic blocks mapping exit conditions to basic block
        #   ex: switch, {1:JVMInstruction1, 2:JVMInstruction2, 'default':JVMInstruction3}
        #   ex: if/else, {True:JVMInstruction1, False:JVMInstruction2}
        #   ex: goto, {'':JVMInstruction1,}
        self.exit = {}
        self.basic_block = None

    def connect(self, other, condition):
        """ Connect this instruction to another (this => other)
        """
        #print 'Setting exit condition to %s' % repr(condition)
        self.exit[condition] = other
        other.entry.append((condition, self))
            
    def is_initial(self):
        return self.entry == []
    def is_terminal(self):
        if self.exit == {}:
            return True
        if self.instruction._name == 'athrow':
            # athrow can possibly be terminal
            return True
        return False

    def set_basic_block(self, basic_block):
        self.basic_block = basic_block

    def __str__(self):
        return '%0.6d: %s' % (self.instruction.offset, str(self.instruction))


class BasicBlock:
    def __init__(self, instructions, is_entry = False):
        # stack of types PROBABLY on the runtime stack at the END of this BB
        self.tstack = None
        
        # list of types in PROBABLY in local vars at the END of this BB
        self.tlocals = None
        
        # list of instructions in order forming the basic block
        self.instructions = instructions

        self.is_entry = is_entry

        # list of tuples of the form (condition, basic_block) possibly making entry into this basic block
        self.entry = []
        
        # dictionary of basic blocks mapping exit conditions to basic block
        #   ex: switch, {1:BasicBlock1, 2:BasicBlock2, 'default':BasicBlock3}
        #   ex: if/else, {True:BasicBlock1, False:BasicBlock2}
        #   ex: goto, {'':BasicBlock1,}
        self.exit = {}
    
    def connect(self, other, condition):
        """ Connect this basic block to another (this => other)
        """
        #print 'Setting exit condition to %s' % repr(condition)
        self.exit[condition] = other
        other.entry.append((condition, self))
            
    def is_initial(self):
        return self.is_entry
    def is_terminal(self):
        if self.exit == {}:
            return True
        if self.instructions[-1]._name == 'athrow':
            # athrow can possibly be terminal
            return True
        return False
    def is_abandoned(self):
        return self.entry == [] and not self.is_initial()

    def get_instruction_string(self):
        res = []
        for instruction in self.instructions:
            comment = '' if instruction.totos is None else " ; %s" % instruction.totos
            res.append('%0.6d: %s%s' % (instruction.offset, str(instruction), comment))
        return '\n'.join(res)

    def _pretty_operand(self, operand):
        if isinstance(operand, basestring):
            return '\f09"%s"\f31' % str(operand)
        elif hasattr(operand, 'to_jts'):
            return "\f10%s\f31" % operand.to_jts()
        else:
            return "\f13%s\f31" % str(operand)

    def get_pretty_code(self):
        text = []
        opcode_width = max(len(i._name) for i in self.instructions) + 4
        code_template = "\f16%%06d\f31: \f01%%-%ds\f31 %%s%%s" % opcode_width
        for instr in self.instructions:
            extra = '' if instr.totos is None else " ; \f15%s\f31" % instr.totos
            ops = ', '.join(map(self._pretty_operand, instr.operands))
            if len(ops) > MAX_INSTR_LEN:
                ops = ops[:MAX_INSTR_LEN].rstrip() + '...\f31'
            code_text = code_template % (instr.offset, instr._name, ops, extra)
            text.append(code_text.replace('\\', '\\\\').replace('"', '\\"'))
        return '\n'.join(text)

    def __str__(self):
        return "BB_%06d" % (self.instructions[0].offset)


class Subroutine:
    def __init__(self, routine):
        self.routine = routine
        self.basic_blocks = self._get_basic_blocks()
        self.G = None
        
    def get_instruction_number(self, offset):
        for inum, instruction in enumerate(self.routine.instructions):
            if instruction.offset == offset:
                return inum
        raise(AnalysisException('Unable to find instruction at offset %d in routine %s.%s' % (offset, str(self.routine.parent), self.routine.java_def())))

    def _get_basic_blocks(self):
        # scan instructions for branches
        # list of tuples of tuples of the form (cause_string, branch_to_instruction_number)
        self.branches = []
        for i, instruction in enumerate(self.routine.instructions):
            if instruction._name in terminals or len(self.routine.instructions) == 1:
                # this instruction ends the subroutine
                self.branches.append(())
                # note: we check if this is the final instruction to catch the following case:
                # public final boolean isInstance(java.lang.Object) {
                #   //   0. (02960): iinvokenative 2, 65535
                # }
            elif instruction._name in branches:
                # this instruction unconditionally branches to another instruction
                offset = instruction.get_branch_locations()[0]
                #print instruction
                #print instruction.get_branch_locations()
                instruction_number = self.get_instruction_number(offset)
                self.branches.append((('', instruction_number),))
            elif instruction._name in conditional_branches:
                # this instruction can branch or fall through
                offset = instruction.get_branch_locations()[0]
                instruction_number = self.get_instruction_number(offset)
                if instruction._name.startswith('checkcastbranch'):
                    self.branches.append(((True, i+1), (False, instruction_number)))
                elif instruction._name.startswith('if'):
                    self.branches.append(((False, i+1), (True, instruction_number)))
                else:
                    raise(AnalysisException('Unexpected conditional branch instruction %s at %d in routine %s.%s' % (instruction._name, instruction.offset, str(self.routine.parent), self.routine.java_def())))
            elif instruction._name in compound_branches:
                # this instruction can branch to one or more locations
                offsets = instruction.get_branch_locations()
                if instruction._name == 'tableswitch':
                    switches = []
                    base_value = instruction.operands[-2]
                    for j, offset in enumerate(offsets):
                        if j == 0:
                            case = 'default'
                        else:
                            case = base_value + j
                        instruction_number = self.get_instruction_number(offset)
                        switches.append((case, instruction_number))
                    self.branches.append(tuple(switches))
                elif instruction._name == 'lookupswitch':
                    switches = []
                    for j, offset in enumerate(offsets[1:]):
                        case = instruction.operands[-2][j][0]
                        #print '%s:' % case,
                        #print offset
                        instruction_number = self.get_instruction_number(offset)
                        switches.append((case, instruction_number))

                    # do additional default case field as well
                    case = 'default'
                    offset = offsets[0]
                    #print '%s:' % case,
                    #print offset
                    instruction_number = self.get_instruction_number(offset)
                    switches.append((case, instruction_number))

                    self.branches.append(tuple(switches))
                elif instruction._name == 'lookupswitch_short':
                    switches = []
                    for j, offset in enumerate(offsets[1:]):
                        case = instruction.operands[-2][j][0]
                        #print '%s:' % case,
                        #print offset
                        instruction_number = self.get_instruction_number(offset)
                        switches.append((case, instruction_number))

                    # do additional default case field as well
                    case = 'default'
                    offset = offsets[0]
                    #print '%s:' % case,
                    #print offset
                    instruction_number = self.get_instruction_number(offset)
                    switches.append((case, instruction_number))

                    self.branches.append(tuple(switches))
                else:
                    raise(AnalysisException('Unknown compound branch instruction %s' % str(instruction)))
            elif instruction._name in throwers:
                # this instruction throws an exception
                # if there are handlers, this may go to them
                handler_locs = []
                for handler in self.routine.handlers:
                    # TODO: is exception handler scope inclusive or exclusive
                    #       JVM says: [start_pc, end_pc)
                    # if this instruction is in scope of a handler, it may go to it
                    if handler.scope[0] <= instruction.offset < handler.scope[1]:
                        handler_name = str(handler.type)
                        if handler_name == 'None':
                            handler_name = 'finally'
                        # we only want the one handler with this exception type to trigger
                        # that is, we wan the innermost exception handler
                        if handler_name not in [x for x,y in handler_locs]:
                            handler_locs.append((handler_name, self.get_instruction_number(handler.target)))
                # if there is no handler, this terminates the current subroutine
                if handler_locs == []:
                    self.branches.append(())
                else:
                    self.branches.append(tuple(handler_locs))
            elif instruction._name in potential_throwers:
                # this instruction may throw an exception
                # if there are handlers, this may go to them
                handler_locs = []
                for handler in self.routine.handlers:
                    # TODO: is exception handler scope inclusive or exclusive
                    #       JVM says: [start_pc, end_pc)
                    # if this instruction is in scope of a handler, it may go to it
                    if handler.scope[0] <= instruction.offset < handler.scope[1]:
                        # if this instruction
                        handler_name = str(handler.type)
                        if handler_name == 'None':
                            handler_name = 'finally'
                        # we only want the one handler with this exception type to trigger
                        # that is, we wan the innermost exception handler
                        if handler_name not in [x for x,y in handler_locs]:
                            handler_locs.append((handler_name, self.get_instruction_number(handler.target)))
                # this falls through if an exception is not thrown
                handler_locs.append(('', i+1))
                self.branches.append(tuple(handler_locs))
            elif instruction._name in restricted_throwers:
                # this instruction may throw an exception
                # if there are handlers, this may go to them
                handler_locs = []
                for handler in self.routine.handlers:
                    # TODO: is exception handler scope inclusive or exclusive
                    #       JVM says: [start_pc, end_pc)
                    # if this instruction is in scope of a handler, it may go to it
                    if handler.scope[0] <= instruction.offset < handler.scope[1]:
                        # if this exception is thrown by this instruction
                        handler_name = str(handler.type)
                        if handler_name == 'None':
                            handler_name = 'finally'
                        if handler_name in restricted_throwers[instruction._name] or handler_name == 'finally':
                            # we only want the one handler with this exception type to trigger
                            # that is, we wan the innermost exception handler
                            if handler_name not in [x for x,y in handler_locs]:
                                handler_locs.append((handler_name, self.get_instruction_number(handler.target)))
                # this falls through if an exception is not thrown
                handler_locs.append(('', i+1))
                self.branches.append(tuple(handler_locs))
            else:
                # this instruction falls through to the next
                self.branches.append((('', i+1),))
        
        # list of lists of tuples of the form (cause_string, branch_from_instruction_number)
        self.branch_xrefs = [list() for x in range(len(self.branches))]
        
        for i, branch in enumerate(self.branches):
            for reason, instruction_number in branch:
                #print '%s: %d => %d' % (reason, i, instruction_number)
                self.branch_xrefs[instruction_number].append((reason, i))

        # TODO: remove
        '''
        print 'Instruction branches:'
        for i, branch in enumerate(self.branches):
            print '%d: %s' % (i, str(branch))
        print 'Instruction branch cross-references:'
        for i, branch in enumerate(self.branch_xrefs):
            print '%d: %s' % (i, str(branch))
        '''
            
        # list of lists representing basic blocks
        bb_inum_list = []
        current_bb = []
        for i in range(len(self.routine.instructions)):
            # terminal
            if self.branches[i] == ():
                # initial
                if self.branch_xrefs[i] == []:
                    bb_inum_list.append([i,])
                    current_bb = []
                # fall through to only
                elif self.branch_xrefs[i] == [('', i-1),]:
                    current_bb.append(i)
                    if current_bb:
                        bb_inum_list.append(current_bb)
                    current_bb = []
                # branched to
                else:
                    if current_bb:
                        bb_inum_list.append(current_bb)
                    current_bb = []
                    bb_inum_list.append([i,])
            # fall through
            elif self.branches[i] == (('', i+1),):
                # initial
                if self.branch_xrefs[i] == []:
                    current_bb.append(i)
                # fall through to only
                elif self.branch_xrefs[i] == [('', i-1),]:
                    current_bb.append(i)
                # branched to
                else:
                    if current_bb:
                        bb_inum_list.append(current_bb)
                    current_bb = [i,]
            # potentially branching
            else:
                # initial
                if self.branch_xrefs[i] == []:
                    bb_inum_list.append([i,])
                    current_bb = []
                # fall through to only
                elif self.branch_xrefs[i] == [('', i-1),]:
                    current_bb.append(i)
                    if current_bb:
                        bb_inum_list.append(current_bb)
                    current_bb = []
                # branched to
                else:
                    if current_bb:
                        bb_inum_list.append(current_bb)
                    current_bb = []
                    bb_inum_list.append([i,])
                
        '''
        print 'Basic blocks:'
        for bb in bb_inum_list:
            print '    %s' % str(bb)
        '''
        
        basic_blocks = []
        # finally generate BasicBlock objects
        for j, bb in enumerate(bb_inum_list):
            basic_block = BasicBlock([self.routine.instructions[i] for i in bb], is_entry=(j==0))
            basic_blocks.append(basic_block)
        
        # connect the BasicBlocks
        for bb_num, bb in enumerate(bb_inum_list):
            branch_from_inum = bb[-1]
            for condition, branch_to_inum in self.branches[branch_from_inum]:
                branch_from_bb_num = None
                for i, each in enumerate(bb_inum_list):
                    if branch_from_inum in each:
                        branch_from_bb_num = i
                        break
                bb1 = basic_blocks[branch_from_bb_num]
                branch_to_bb_num = None
                for i, each in enumerate(bb_inum_list):
                    if branch_to_inum in each:
                        branch_to_bb_num = i
                        break
                bb2 = basic_blocks[branch_to_bb_num]
                # bb1 => bb2
                #print 'Connecting %d to %d on condition %s' % (branch_from_inum, branch_to_inum, repr(condition))
                bb1.connect(bb2, condition)

        return basic_blocks

    def get_graph(self):
        import networkx as nx

        if self.G != None:
            return self.G
        G = nx.DiGraph()
        for basic_block in self.basic_blocks:
            G.add_node(basic_block)
        for bb1 in self.basic_blocks:
            for condition, bb2 in bb1.exit.items():
                G.add_edge(bb1, bb2)
        self.G = G
        return G

    def get_pos(self):
        import networkx as nx
        G = self.get_graph()

        #import matplotlib.pyplot as plt
        #nx.draw_graphviz(G, prog = 'dot')
        #plt.show()

        return nx.graphviz_layout(G, prog='dot')

    def get_pydot(self):
        import networkx as nx

        G = self.get_graph()
        return nx.to_pydot(G)
    
    def to_gdl_file(self, filename):
        with open(filename, 'wt') as fd:
            print >> fd, 'graph:{title:"%s"' % self.routine
            print >> fd, 'manhattan_edges: yes\n/*layoutalgorithm: mindepth*/'
            edges = []
            for bb in self.basic_blocks:
                bb_name = str(bb)
                label = "\fu\fb%s:\fn\n%s" % (bb_name, bb.get_pretty_code())
                border_col = 'black'
                if bb.is_initial():
                    border_col = 'green'
                elif bb.is_terminal():
                    border_col = 'red'
                elif bb.is_abandoned():
                    border_col = 'purple'
                print >> fd, 'node:{title:"%s" bordercolor:%s label:"%s"}' % (bb_name, border_col, label)
                for condition, entry in bb.entry:
                    edges.append((entry, bb, condition))
            for src, dst, why in edges:
                if why != '':
                    if why is False:
                        color = 'darkred'
                    elif why is True:
                        color = 'darkgreen'
                    elif isinstance(why, int) or isinstance(why, long) or why == 'default':
                        # switch
                        color = 'darkblue'
                    else:
                        # exception
                        color = 'darkyellow'
                    extra = 'color:%s label:"%s"' % (color, why)
                else:
                    extra = ''
                print >> fd, 'edge:{sourcename:"%s" targetname:"%s" %s}' % (src, dst, extra)
                
            print >> fd, '}'
