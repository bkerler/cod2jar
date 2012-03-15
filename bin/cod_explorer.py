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

import wx
import wx.lib.ogl as ogl
import wx.py as py
import wx.stc as stc
import os, sys, re
from time import ctime, sleep
from StringIO import StringIO
from optparse import OptionParser
import codlib
import traceback

if wx.Platform == '__WXMSW__':
    faces = { 'times': 'Times New Roman',
              'mono' : 'Courier New',
              'helv' : 'Arial',
              'other': 'Comic Sans MS',
              'size' : 10,
              'size2': 8,
             }
elif wx.Platform == '__WXMAC__':
    faces = { 'times': 'Times New Roman',
              'mono' : 'Monaco',
              'helv' : 'Arial',
              'other': 'Comic Sans MS',
              'size' : 12,
              'size2': 10,
             }
else:
    faces = { 'times': 'Times',
              'mono' : 'Courier',
              'helv' : 'Helvetica',
              'other': 'new century schoolbook',
              'size' : 12,
              'size2': 10,
             }


ID_BUTTON=100
ID_EXIT=200
ID_SPLITTER=300
ID_SPLITTER2=301
ID_SPLITTER3=302
ID_PREVIOUS=399
ID_FORWARD=398
ID_OPEN_PATH=400
ID_NEW_SEARCH_PATH=401
ID_OPEN_NAME_DB=402
ID_EXPORT_ALL=403
ID_EXPORT_CURRENT=404
ID_EXPORT_SELECTION=405
ID_FUNCTION_SIBLINGS = 410
ID_FUNCTION_SELECTED = 411
ID_RENAME_ROUTINE=412
ID_RENAME_FIELD=413


#wildcard = "Binary file (*.bin)|*.bin|"     \
#           "EFS file sytem (*.efs)|*.efs|" \
#           "All files (*.*)|*.*"
wildcard = "All files (*)|*"

# globals
ce = None


def indexes(data, pattern):
    s = []
    i = -1
    while True:
        try:
            i = data.index(pattern, i+1)
            s.append(i)
        except:
            break
    return s


class PackageNav(wx.TreeCtrl):
    def __init__(self, parent, id):
        wx.TreeCtrl.__init__(self, parent, id, wx.DefaultPosition, wx.DefaultSize)
        self.Bind(wx.EVT_TREE_ITEM_ACTIVATED, self.OnActivate)
        self.Bind(wx.EVT_TREE_ITEM_MENU, self.OnContextMenu)
        self.reset()

    def get_package_name(self, item):
        cod_name = self.GetPyData(item)

        if cod_name:
            package_name = []

            while item != self.root:
                text = self.GetItemText(item)
                package_name.append(text)
                item = self.GetItemParent(item)
            package_name = '/'.join(package_name[::-1])
            return package_name

        return None

    def OnActivate(self, event):
        global ce
        item = event.GetItem()
        cod_name = self.GetPyData(item)

        if cod_name:
            package_name = self.get_package_name(item)
            ce.open_package(package_name, cod_name)

    def OnMenuActivate(self, event):
        global ce
        cod_name = self.GetPyData(self.menu_item)

        if cod_name:
            package_name = self.get_package_name(self.menu_item)
            ce.open_package(package_name, cod_name)

    def OnMenuFunctionFlowGraph(self, event):
        global ce
        cod_name = self.GetPyData(self.menu_item)

        if cod_name:
            package_name = self.get_package_name(self.menu_item)
            ce.function_flow_graph_package(package_name)

    def OnMenuFunctionGraph(self, event):
        global ce
        cod_name = self.GetPyData(self.menu_item)

        if cod_name:
            package_name = self.get_package_name(self.menu_item)
            class_def = ce.loader.load_class(package_name)
            cod = ce.cods[cod_name]
            routine_defs = {}
            for routine_def in class_def.routines:
                name = '%s' % routine_def.java_def(params_on_newlines = False)
                routine_defs[name] = routine_def
            routine_names = routine_defs.keys()
            routine_names.sort()
            
            dlg = wx.SingleChoiceDialog(
                self, 'Choose a routine to graph', 'Routines',
                routine_names,
                wx.CHOICEDLG_STYLE
            )

            if dlg.ShowModal() == wx.ID_OK:
                routine = routine_defs[dlg.GetStringSelection()]
                dlg.Destroy()
                
                # This is a horrible hack (needs to be x-platform)
                subr = codlib.Subroutine(routine)
                try:
                    ce.hi_scanner.scan(subr)
                except:
                    print "Error HIscanning %s; type information will be incomplete..." % routine
                    traceback.print_exc()
                subr.to_gdl_file("subroutine.gdl")
                os.system("start subroutine.gdl")
                return
            else:
                dlg.Destroy()

    def OnContextMenu(self, event):
        self.menu_item = event.GetItem()

        if not hasattr(self, "popupID1"):
            self.popupID1 = wx.NewId()
            self.popupID2 = wx.NewId()
            self.popupID3 = wx.NewId()

            self.Bind(wx.EVT_MENU, self.OnMenuActivate, id=self.popupID1)
            self.Bind(wx.EVT_MENU, self.OnMenuFunctionFlowGraph, id=self.popupID2)
            self.Bind(wx.EVT_MENU, self.OnMenuFunctionGraph, id=self.popupID3)

        menu = wx.Menu()
        menu.Append(self.popupID1, "Navigate to in Code View")
        menu.Append(self.popupID2, "View class function flow graph")
        menu.Append(self.popupID3, "Graph a class function")
        ## make a submenu
        #sm = wx.Menu()
        #sm.Append(self.popupID8, "sub item 1")
        #sm.Append(self.popupID9, "sub item 1")
        #menu.AppendMenu(self.popupID7, "Test Submenu", sm)

        self.PopupMenu(menu)
        menu.Destroy()

    def add_package(self, class_def, cod_name):
        cur = self.root
        for name in str(class_def).split('/'):
            # try to find it
            matching_child = None
            
            (child, cookie) = self.GetFirstChild(cur)
            while child.IsOk():
                if self.GetItemText(child) == name:
                    matching_child = child
                    break
                (child, cookie) = self.GetNextChild(cur, cookie)

            if matching_child:
                cur = matching_child
            else:
                # otherwise create it
                cur = self.AppendItem(cur, name)
        self.SetPyData(cur, cod_name)

    def reset(self):
        self.DeleteAllItems()
        self.root = self.AddRoot('Currently loaded packages')

    def update(self):
        global ce
        self.reset()
        for cod_name in ce.cods:
            for class_def in ce.cods[cod_name].classes:
                self.add_package(class_def, cod_name)
        self.Expand(self.root)


class CodNav(wx.ListCtrl):
    def __init__(self, parent, id):
        self.parent = parent
        
        self.currentItem = None
        
        wx.ListCtrl.__init__(self, parent, id, style=wx.LC_REPORT)
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.OnItemSelected)
        self.Bind(wx.EVT_LEFT_DCLICK, self.OnDoubleClick)
        self.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.OnDoubleClick)
        
        self.InsertColumn(0, 'Module name')
        self.InsertColumn(1, 'Version')
        self.InsertColumn(2, 'Creation Date', wx.LIST_FORMAT_RIGHT)
        self.InsertColumn(3, 'Path')

        self.SetColumnWidth(0, 200)
        self.SetColumnWidth(1, 80)
        self.SetColumnWidth(2, 160)
        self.SetColumnWidth(3, 400)

        #self.il = wx.ImageList(16, 16)
        #self.il.Add(wx.Bitmap('images/folder.png'))
        #self.il.Add(wx.Bitmap('images/file.png'))
        #self.il.Add(wx.Bitmap('images/item.png'))
        #self.SetImageList(self.il, wx.IMAGE_LIST_SMALL)
        
    def update(self):
        global ce
        self.DeleteAllItems()
        for i, cod_name in enumerate(ce.cod_names):
            if ce.cache_path:
                ce.log.WriteText('Parsing %s from cache...\n' % cod_name)
                mod = ce.loader.load_module(cod_name)

                self.InsertStringItem(i, cod_name)
                #self.SetItemImage(i, 0)
                self.SetStringItem(i, 0, mod.name)
                self.SetStringItem(i, 1, mod.version)
                self.SetStringItem(i, 2, ctime(mod.timestamp))
                self.SetStringItem(i, 3, ce.cod_filenames[cod_name])
                continue
            
            ce.log.WriteText('Parsing %s from COD...\n' % cod_name)
            cf = codlib.load_cod_file(ce.cod_filenames[cod_name])
        
            self.InsertStringItem(i, cod_name)
            #self.SetItemImage(i, 0)
            self.SetStringItem(i, 0, cf.data.cod_module_name)
            self.SetStringItem(i, 1, cf.data.cod_module_version)
            self.SetStringItem(i, 2, ctime(cf.hdr.timestamp))
            self.SetStringItem(i, 3, ce.cod_filenames[cod_name])
        ce.log.WriteText('Completed parsing all cod files\n')

    def reset(self):
        self.DeleteAllItems()

    def OnItemSelected(self, event):
        self.currentItem = event.m_itemIndex

    def OnDoubleClick(self, event):
        global ce
        cod_name = self.GetItemText(self.currentItem)
        ce.open_cod(cod_name)        

        
class BasicBlockEvtHandler(ogl.ShapeEvtHandler):
    def __init__(self, basic_block):
        ogl.ShapeEvtHandler.__init__(self)
        self.basic_block = basic_block

    def OnLeftDoubleClick(self, x, y, keys, attachment):
        shape = self.GetShape()
        print dir(shape)
        print help(shape.GetRegionId)
        print help(shape.GetRegionName)
        region = self.GetRegionID()
        print 'Activated:',
        print region.instruction
        
        
class LineEvtHandler(ogl.ShapeEvtHandler):
    def __init__(self, to_shape, canvas):
        ogl.ShapeEvtHandler.__init__(self)
        self.canvas = canvas
        self.to_shape = to_shape

    def OnLeftDoubleClick(self, x, y, keys, attachment):
        # TODO: scroll to the basic block that we point to
        #print [x for x in dir(self.to_shape) if 'pos' in x.lower()]
        #print [x for x in dir(self.canvas) if 'pos' in x.lower()]
        #print [x for x in dir(self.canvas) if 'scroll' in x.lower()]
        #print 'Line clicked'
        #print help(self.to_shape.GetLinePosition)
        x = (self.to_shape.GetX() / self.canvas.GetScrollPixelsPerUnit()[0]) - (self.canvas.GetScrollPageSize(wx.HSCROLL) / 2)
        y = (self.to_shape.GetY() / self.canvas.GetScrollPixelsPerUnit()[1]) - (self.canvas.GetScrollPageSize(wx.VSCROLL) / 2)
        self.canvas.Scroll(x, y)
        #dc = wx.ClientDC(self.canvas)
        #self.canvas.PrepareDC(dc)
        #self.canvas.ScrollLines(self.to_shape.GetLinePosition(0))

        
class BasicBlockShape(ogl.DividedShape):
    def __init__(self, basic_block, canvas):
        self.basic_block = basic_block

        height = 25 * len(self.basic_block.instructions)
        width = int(8 * max([len('%0.6d: %s' % (x.offset, str(x))) for x in self.basic_block.instructions]))
        ogl.DividedShape.__init__(self, width, height)

        for instruction in self.basic_block.instructions:
            region = ogl.ShapeRegion()
            region.instruction = instruction
            region.SetText('%0.6d: %s' % (instruction.offset, str(instruction)))
            font = wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, False, faces['mono'])
            region.SetFont(font)
            region.SetProportions(0.0, 1./len(self.basic_block.instructions))
            region.SetFormatMode(ogl.FORMAT_NONE)
            self.AddRegion(region)

        self.SetRegionSizes()
        self.ReformatRegions(canvas)

    def ReformatRegions(self, canvas=None):
        rnum = 0
        if canvas is None:
            canvas = self.GetCanvas()
        dc = wx.ClientDC(canvas)  # used for measuring
        for region in self.GetRegions():
            text = region.GetText()
            self.FormatText(dc, text, rnum)
            rnum += 1

    def OnSizingEndDragLeft(self, pt, x, y, keys, attch):
        ogl.DividedShape.OnSizingEndDragLeft(self, pt, x, y, keys, attch)
        self.SetRegionSizes()
        self.ReformatRegions()
        self.GetCanvas().Refresh()


class CodeCanvas(ogl.ShapeCanvas):
    def __init__(self, parent, frame, routine):
        global ce
        ogl.ShapeCanvas.__init__(self, parent)
        
        POS_SCALE = 2
        X_MARGIN = 600
        Y_MARGIN = 300
        self.frame = frame
        max_num_instrs = max([len(basic_block.instructions) for basic_block in self.routine.basic_blocks])
        
        pos = self.routine.get_pos()
        # collect positions sorted in y order
        tmp = [(pos[bb][1], bb) for bb in pos]
        tmp.sort()
        bb_y_sorted = [x[1] for x in tmp]
        # expand the graph to account for really long basic blocks
        EXPAND_SCALE = 4
        expand_level = 0
        for bb in bb_y_sorted:
            x, y = pos[bb]
            grow = EXPAND_SCALE * len(bb.instructions)
            expand_level += grow
            pos[bb] = (x, (y + expand_level))

        min_x = min([POS_SCALE * x[0] for x in pos.values()])
        max_x = max([POS_SCALE * x[0] for x in pos.values()])
        min_y = min([POS_SCALE * x[1] for x in pos.values()])
        max_y = max([POS_SCALE * x[1] for x in pos.values()])
        maxWidth  = 2*X_MARGIN + max_x
        maxHeight = 2*Y_MARGIN + max_y

        self.SetScrollbars(20, 20, maxWidth/20, maxHeight/20)

        self.SetBackgroundColour("LIGHT BLUE") #wx.WHITE)
        self.diagram = ogl.Diagram()
        self.SetDiagram(self.diagram)
        self.diagram.SetCanvas(self)
        self.shapes = []
        self.save_gdi = []
        self.basic_blocks_to_shape = {}
        # normalize
        for each in pos:
            pos[each] = (POS_SCALE * pos[each][0] + X_MARGIN - min_x, POS_SCALE * pos[each][1] + Y_MARGIN - min_y)
        # flip y
        for each in pos:
            pos[each] = (pos[each][0], maxHeight - pos[each][1])
        
        for basic_block in pos:
            x = pos[basic_block][0]
            y = pos[basic_block][1]
            if basic_block.is_initial():
                outline = wx.Pen(wx.GREEN, 2)
            elif basic_block.is_terminal():
                outline = wx.Pen(wx.RED, 2)
            else:
                outline = wx.BLACK_PEN
            background = wx.WHITE_BRUSH
            self.MyAddShape(
                BasicBlockShape(basic_block, self),
                x, y,
                outline, background, ''
            )
        
        # connect the basic blocks on the canvas
        from_to_lines = {}
        texts = {}
        for shape in self.shapes:
            for condition in shape.basic_block.exit:
                from_basic_block = shape.basic_block
                to_basic_block = shape.basic_block.exit[condition]
                connection = (from_basic_block, to_basic_block)
                dc = wx.ClientDC(self)
                self.PrepareDC(dc)
                if connection in from_to_lines:
                    #print dir(from_to_lines[])
                    text = texts[connection]
                    new_text = text + ',\n%s' % str(condition)
                    texts[connection] = new_text
                    from_to_lines[connection].ClearText()
                    from_to_lines[connection].FormatText(dc, new_text, 0)
                else:
                    line = ogl.LineShape()
                    from_to_lines[connection] = line
                    line.SetCanvas(self)
                    texts[connection] = str(condition)
                    if condition == '':
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.BLACK_BRUSH)
                    elif condition is True:
                        line.FormatText(dc, str(condition), 0)
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.GREEN_BRUSH)
                    elif condition is False:
                        line.FormatText(dc, str(condition), 0)
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.RED_BRUSH)
                    elif isinstance(condition, int) or condition == 'default':
                        # switch
                        line.FormatText(dc, str(condition), 0)
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.BLUE_BRUSH)
                    elif isinstance(condition, str):
                        # catch or finally
                        line.FormatText(dc, str(condition), 0)
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.Brush(wx.Colour(0xFF, 0xFF, 0x33)))
                    else:
                        # other???
                        line.FormatText(dc, 'unknown', 0)
                        line.SetPen(wx.BLACK_PEN)
                        line.SetBrush(wx.BLACK_BRUSH)
                    line.AddArrow(ogl.ARROW_ARROW)
                    line.MakeLineControlPoints(2)
                    to_shape = self.basic_blocks_to_shape[to_basic_block]
                    shape.AddLine(line, to_shape)
                    self.diagram.AddShape(line)
                    evt_handler = LineEvtHandler(to_shape, self)
                    evt_handler.SetShape(line)
                    evt_handler.SetPreviousHandler(line.GetEventHandler())
                    line.SetEventHandler(evt_handler)
                    line.Show(True)
        
        # show shapes after lines so that they are on top
        for shape in self.shapes:
            shape.Show(True)
        #bmp = images.Test2.GetBitmap()
        #mask = wx.Mask(bmp, wx.BLUE)
        #bmp.SetMask(mask)

        #s = ogl.BitmapShape()
        #s.SetBitmap(bmp)
        #self.MyAddShape(s, 225, 130, None, None, "Bitmap")

        dc = wx.ClientDC(self)
        self.PrepareDC(dc)

        # scroll to the entry block
        '''
        for basic_block in self.routine.basic_blocks:
            if basic_block.is_initial():
                x = int(pos[basic_block][0])
                y = int(pos[basic_block][1])
                print 'Scrolling to',
                print ((maxWidth-x)/maxWidth, (maxHeight-y)/maxHeight)
                self.Scroll(20*x/maxWidth, 20*y/maxHeight)
                break
        '''
        self.Scroll(0, 0)

        
    def MyAddShape(self, shape, x, y, pen, brush, text):
        # Composites have to be moved for all children to get in place
        if isinstance(shape, ogl.CompositeShape):
            dc = wx.ClientDC(self)
            self.PrepareDC(dc)
            shape.Move(dc, x, y)
        else:
            shape.SetDraggable(True, True)
        shape.SetCanvas(self)
        shape.SetX(x)
        shape.SetY(y)
        if pen:    shape.SetPen(pen)
        if brush:  shape.SetBrush(brush)
        if text:
            for line in text.split('\n'):
                shape.AddText(line)
        #shape.SetShadowMode(ogl.SHADOW_RIGHT)
        self.diagram.AddShape(shape)
        evt_handler = BasicBlockEvtHandler(shape.basic_block)
        evt_handler.SetShape(shape)
        evt_handler.SetPreviousHandler(shape.GetEventHandler())
        shape.SetEventHandler(evt_handler)

        self.basic_blocks_to_shape[shape.basic_block] = shape
        self.shapes.append(shape)
        return shape

    def OnBeginDragLeft(self, x, y, keys):
        self.drag_x = x
        self.drag_y = y

    def OnEndDragLeft(self, x, y, keys):
        pass
        ##print dir(self)
        #move_x = x - self.drag_x
        #move_y = y - self.drag_y
        ##x = (self.GetViewStart()[0] / self.GetScrollPixelsPerUnit()[0]) + xs
        ##y = (self.GetViewStart()[1] / self.GetScrollPixelsPerUnit()[1]) + ys
        #x = self.GetViewStart()[0] - move_x
        #y = self.GetViewStart()[1] - move_y
        ##xs, ys = self.CalcUnscrolledPosition(x, y)
        #xs = x  / self.GetScrollPixelsPerUnit()[0]
        #ys = y  / self.GetScrollPixelsPerUnit()[1]
        #self.Scroll(xs, ys)
        
        #print (-move_x / self.GetScrollPixelsPerUnit()[0], -move_y / self.GetScrollPixelsPerUnit()[1])
        #print [x for x in dir(self) if 'pos' in x.lower()]
        #print dir(self)
        #print self.GetScrollPos(orientation = -1)
        #print self.GetScrollPos(orientation = 1)
        '''
        print move_x, move_y
        print [x for x in dir(self) if 'x' in x.lower()]
        print [x for x in dir(self) if 'y' in x.lower()]
        print help(self.MoveXY)
        print self.GetScaleX()
        print self.GetScaleY()
        print help(self.GetScrollPos)
        print self.GetScrollRange(orientation = -1)
        print self.GetScrollRange(orientation = 1)
        print self.GetScrollPos(orientation = -1)
        print self.GetScrollPos(orientation = 1)
        print self.GetScrollPixelsPerUnit()
        '''
        #self.Scroll(-move_x / self.GetScrollPixelsPerUnit()[0], -move_y / self.GetScrollPixelsPerUnit()[1])


class CodeView(wx.Frame):
    def __init__(self, routine):
        wx.Frame.__init__(self,None,-1,
                         'Code view %s (in class %s)' % (str(routine.parent), routine.java_def(params_on_newlines = False)),
                         size=(550,350))
                         
        ogl.OGLInitialize()
        self.canvas = CodeCanvas(self, self, routine)

        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.canvas, 1, wx.LEFT | wx.TOP | wx.GROW)
        self.SetSizer(self.sizer)
        self.Fit()
        self.Maximize()

    def OnPaint(self, event):
        self.canvas.draw()


class JavaBrowser(stc.StyledTextCtrl):
    fold_symbols = 2
    
    def __init__(self, parent, ID,
                 pos=wx.DefaultPosition, size=wx.DefaultSize,
                 style=0):
        stc.StyledTextCtrl.__init__(self, parent, ID, pos, size, style)

        #self.class_re = re.compile('class\s+([\w\.\<\>]+)\s*(?extends\s*[\w\.]+)*?\s*{')
        #self.routine_re = re.compile('\s+(\w+)\s*\(.*\)\s*{\s*')
        self.reset()
        self._print_key = False
        self.code_view = None

        self.CmdKeyAssign(43, stc.STC_SCMOD_CTRL, stc.STC_CMD_ZOOMIN)
        self.CmdKeyAssign(45, stc.STC_SCMOD_CTRL, stc.STC_CMD_ZOOMOUT)

        self.SetLexer(stc.STC_LEX_CPP)
        keywords = ['abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class', 'const', 'continue',
                    'default', 'do', 'double', 'else', 'enum', 'extends', 'final', 'finally', 'float', 'for', 'goto', 'if', 
                    'implements', 'import', 'instanceof', 'int', 'interface', 'long', 'native', 'new', 'package', 'private',
                    'protected', 'public', 'return', 'short', 'static', 'strictfp', 'super', 'switch', 'synchronized', 'this',
                    'throw', 'throws', 'transient', 'try', 'void', 'volatile', 'while', 'false', 'true', 'null'
                   ]
        opcodes = codlib._OPCODES

        self.SetKeyWords(0, " ".join(keywords + opcodes))

        self.SetProperty("fold", "1")
        self.SetProperty("tab.timmy.whinge.level", "1")
        self.SetMargins(0,0)

        self.SetViewWhiteSpace(False)
        #self.SetBufferedDraw(False)
        #self.SetViewEOL(True)
        #self.SetEOLMode(stc.STC_EOL_CRLF)
        #self.SetUseAntiAliasing(True)
        
        #self.SetEdgeMode(stc.STC_EDGE_BACKGROUND)
        #self.SetEdgeColumn(78)

        # Setup a margin to hold fold markers
        #self.SetFoldFlags(16)  ###  WHAT IS THIS VALUE?  WHAT ARE THE OTHER FLAGS?  DOES IT MATTER?
        self.SetMarginType(2, stc.STC_MARGIN_SYMBOL)
        self.SetMarginMask(2, stc.STC_MASK_FOLDERS)
        self.SetMarginSensitive(2, True)
        self.SetMarginWidth(2, 12)

        if self.fold_symbols == 0:
            # Arrow pointing right for contracted folders, arrow pointing down for expanded
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPEN,    stc.STC_MARK_ARROWDOWN, "black", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDER,        stc.STC_MARK_ARROW, "black", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERSUB,     stc.STC_MARK_EMPTY, "black", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERTAIL,    stc.STC_MARK_EMPTY, "black", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEREND,     stc.STC_MARK_EMPTY,     "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPENMID, stc.STC_MARK_EMPTY,     "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERMIDTAIL, stc.STC_MARK_EMPTY,     "white", "black")
            
        elif self.fold_symbols == 1:
            # Plus for contracted folders, minus for expanded
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPEN,    stc.STC_MARK_MINUS, "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDER,        stc.STC_MARK_PLUS,  "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERSUB,     stc.STC_MARK_EMPTY, "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERTAIL,    stc.STC_MARK_EMPTY, "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEREND,     stc.STC_MARK_EMPTY, "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPENMID, stc.STC_MARK_EMPTY, "white", "black")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERMIDTAIL, stc.STC_MARK_EMPTY, "white", "black")

        elif self.fold_symbols == 2:
            # Like a flattened tree control using circular headers and curved joins
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPEN,    stc.STC_MARK_CIRCLEMINUS,          "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDER,        stc.STC_MARK_CIRCLEPLUS,           "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERSUB,     stc.STC_MARK_VLINE,                "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERTAIL,    stc.STC_MARK_LCORNERCURVE,         "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEREND,     stc.STC_MARK_CIRCLEPLUSCONNECTED,  "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPENMID, stc.STC_MARK_CIRCLEMINUSCONNECTED, "white", "#404040")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERMIDTAIL, stc.STC_MARK_TCORNERCURVE,         "white", "#404040")

        elif self.fold_symbols == 3:
            # Like a flattened tree control using square headers
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPEN,    stc.STC_MARK_BOXMINUS,          "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDER,        stc.STC_MARK_BOXPLUS,           "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERSUB,     stc.STC_MARK_VLINE,             "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERTAIL,    stc.STC_MARK_LCORNER,           "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEREND,     stc.STC_MARK_BOXPLUSCONNECTED,  "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDEROPENMID, stc.STC_MARK_BOXMINUSCONNECTED, "white", "#808080")
            self.MarkerDefine(stc.STC_MARKNUM_FOLDERMIDTAIL, stc.STC_MARK_TCORNER,           "white", "#808080")

        self.Bind(stc.EVT_STC_UPDATEUI, self.OnUpdateUI)
        self.Bind(stc.EVT_STC_MARGINCLICK, self.OnMarginClick)
        self.Bind(wx.EVT_KEY_DOWN, self.OnKeyPressed)
        self.Bind(wx.EVT_FIND, self.OnFind)
        self.Bind(wx.EVT_FIND_NEXT, self.OnFind)
        #self.Bind(wx.EVT_FIND_REPLACE, self.OnFind)
        #self.Bind(wx.EVT_FIND_REPLACE_ALL, self.OnFind)
        self.Bind(wx.EVT_FIND_CLOSE, self.OnFindClose)

        # Make some styles,  The lexer defines what each style is used for, we
        # just have to define what each style looks like.  This set is adapted from
        # Scintilla sample property files.

        # Global default styles for all languages
        self.StyleSetSpec(stc.STC_STYLE_DEFAULT,     "face:%(mono)s,size:%(size)d" % faces)
        self.StyleClearAll()  # Reset all to be like the default

        # Global default styles for all languages
        self.StyleSetSpec(stc.STC_STYLE_DEFAULT,     "face:%(mono)s,size:%(size)d" % faces)
        self.StyleSetSpec(stc.STC_STYLE_LINENUMBER,  "back:#C0C0C0,face:%(mono)s,size:%(size2)d" % faces)
        self.StyleSetSpec(stc.STC_STYLE_CONTROLCHAR, "face:%(mono)s" % faces)
        self.StyleSetSpec(stc.STC_STYLE_BRACELIGHT,  "fore:#FFFFFF,back:#0000FF,bold")
        self.StyleSetSpec(stc.STC_STYLE_BRACEBAD,    "fore:#000000,back:#FF0000,bold")

        # Python styles
        # Default 
        self.StyleSetSpec(stc.STC_P_DEFAULT, "fore:#000000,face:%(mono)s,size:%(size)d" % faces)
        # Comments
        self.StyleSetSpec(stc.STC_P_COMMENTLINE, "fore:#007F00,face:%(mono)s,size:%(size)d" % faces)
        # Number
        self.StyleSetSpec(stc.STC_P_NUMBER, "fore:#007F7F,size:%(size)d" % faces)
        # String
        self.StyleSetSpec(stc.STC_P_STRING, "fore:#7F007F,face:%(mono)s,size:%(size)d" % faces)
        # Single quoted string
        self.StyleSetSpec(stc.STC_P_CHARACTER, "fore:#7F007F,face:%(mono)s,size:%(size)d" % faces)
        # Keyword
        self.StyleSetSpec(stc.STC_P_WORD, "fore:#00007F,bold,size:%(size)d" % faces)
        # Triple quotes
        self.StyleSetSpec(stc.STC_P_TRIPLE, "fore:#7F0000,size:%(size)d" % faces)
        # Triple double quotes
        self.StyleSetSpec(stc.STC_P_TRIPLEDOUBLE, "fore:#7F0000,size:%(size)d" % faces)
        # Class name definition
        self.StyleSetSpec(stc.STC_P_CLASSNAME, "fore:#0000FF,bold,underline,size:%(size)d" % faces)
        # Function or method name definition
        self.StyleSetSpec(stc.STC_P_DEFNAME, "fore:#007F7F,bold,size:%(size)d" % faces)
        # Operators
        self.StyleSetSpec(stc.STC_P_OPERATOR, "bold,size:%(size)d" % faces)
        # Identifiers
        self.StyleSetSpec(stc.STC_P_IDENTIFIER, "fore:#000000,face:%(mono)s,size:%(size)d" % faces)
        # Comment-blocks
        self.StyleSetSpec(stc.STC_P_COMMENTBLOCK, "fore:#7F7F7F,size:%(size)d" % faces)
        # End of line where string is not closed
        self.StyleSetSpec(stc.STC_P_STRINGEOL, "fore:#000000,face:%(mono)s,back:#E0C0E0,eol,size:%(size)d" % faces)

        self.SetCaretForeground("BLUE")

        # register some images for use in the AutoComplete box.
        #self.RegisterImage(1, images.Smiles.GetBitmap())
        #self.RegisterImage(2, 
        #    wx.ArtProvider.GetBitmap(wx.ART_NEW, size=(16,16)))
        #self.RegisterImage(3, 
        #    wx.ArtProvider.GetBitmap(wx.ART_COPY, size=(16,16)))

    def OnShowFind(self):
        data = wx.FindReplaceData()
        data.SetFlags(wx.FR_DOWN)
        dlg = wx.FindReplaceDialog(self, data, "Find")
        self.find_dlg = dlg
        dlg.data = data  # save a reference to it...
        dlg.Show(True)

    def OnFind(self, event):
        self.find_string = self.find_dlg.GetData().GetFindString()
        self.find_flags = self.find_dlg.GetData().GetFlags()
        if self.find_flags & wx.FR_DOWN:
            self.OnFindNext()
        else:
            self.OnFindPrev()

    def OnFindNext(self):
        if self.find_string:
            self.SetCurrentPos(self.GetCurrentPos() + 1)
            self.SetSelection(self.GetCurrentPos(), self.GetCurrentPos())
            self.SearchAnchor()
            location = self.SearchNext(self.find_flags, self.find_string)
            if location == -1:
                # could not find the pattern
                self.SetCurrentPos(self.GetCurrentPos() - 1)
                self.SetSelection(self.GetCurrentPos(), self.GetCurrentPos())
            else:
                # found the pattern
                self.GotoPos(location)
                self.SetCurrentPos(location)
                self.SetSelection(location, location + len(self.find_string))

    def OnFindPrev(self):
        if self.find_string:
            self.SetCurrentPos(self.GetCurrentPos() - 1)
            self.SetSelection(self.GetCurrentPos(), self.GetCurrentPos())
            self.SearchAnchor()
            location = self.SearchPrev(self.find_flags, self.find_string)
            if location == -1:
                # could not find the pattern
                self.SetCurrentPos(self.GetCurrentPos() + 1)
                self.SetSelection(self.GetCurrentPos(), self.GetCurrentPos())
            else:
                # found the pattern
                self.GotoPos(location)
                self.SetCurrentPos(location)
                self.SetSelection(location, location + len(self.find_string))

    def OnFindClose(self, event):
        event.GetDialog().Destroy()

    def OnKeyPressed(self, event):
        global ce
        if self.CallTipActive():
            self.CallTipCancel()
        key = event.GetKeyCode()
        if self._print_key:
            print key

        if key == 78:
            # n
            # rename a field
            # TODO: implement
            pass
        elif key == 32:
            # space
            # bring up the code view window
            
            # TODO: make it bring up the function the cursor is in rather than selecting it in a dialog
            cod = ce.cods[ce.current_cod_name]
            routine_defs = {}
            for class_def in cod.classes:
                for routine_def in class_def.routines:
                    name = '%s: %s' % (str(routine_def.parent), routine_def.java_def(params_on_newlines = False))
                    routine_defs[name] = routine_def
            routine_names = routine_defs.keys()
            routine_names.sort()
            
            dlg = wx.SingleChoiceDialog(
                self, 'Choose a routine to graph', 'Routines',
                routine_names,
                wx.CHOICEDLG_STYLE
            )

            if dlg.ShowModal() == wx.ID_OK:
                routine = routine_defs[dlg.GetStringSelection()]
                dlg.Destroy()
                
                # This is a horrible hack (needs to be x-platform)
                subr = codlib.Subroutine(routine)
                try:
                    ce.hi_scanner.scan(subr)
                except:
                    print "Error HIscanning %s; type information will be incomplete..." % routine
                    traceback.print_exc()
                subr.to_gdl_file("subroutine.gdl")
                os.system("start subroutine.gdl")
                return
                
                #~ try:
                    #~ frame = CodeView(routine)
                    #~ self.code_view = frame
                    #~ frame.Show(True)
                #~ except NameError, e:
                    #~ dlg = wx.MessageDialog(self,
                        #~ 'Could not import modules necessary for code view: %s' % str(e),
                        #~ 'Warning',
                        #~ wx.OK | wx.ICON_INFORMATION
                        #~ #wx.YES_NO | wx.NO_DEFAULT | wx.CANCEL | wx.ICON_INFORMATION
                        #~ )
                    #~ dlg.ShowModal()
                    #~ dlg.Destroy()
                #~ except Exception, e:
                    #~ dlg = wx.MessageDialog(self,
                        #~ 'Error when generating code view: %s' % str(e),
                        #~ 'Warning',
                        #~ wx.OK | wx.ICON_INFORMATION
                        #~ #wx.YES_NO | wx.NO_DEFAULT | wx.CANCEL | wx.ICON_INFORMATION
                        #~ )
                    #~ dlg.ShowModal()
                    #~ dlg.Destroy()
                #~ return
            else:
                dlg.Destroy()
        elif key in [70,] and event.ControlDown():
            # find dialog, ctrl + f
            self.OnShowFind()
        elif key in [342,] and not event.ShiftDown():
            # find next, f3
            self.OnFindNext()
        elif key in [342,] and event.ShiftDown():
            # find previous, shift + f3
            self.OnFindPrev()
        elif key in [344,] and not event.ShiftDown():
            # refresh, f5
            ce.refresh()
        elif key in [312, 313, 314, 315, 316, 317, 366, 367]:
            # pass home, end, up, down, left, right, pgup, pgdn
            event.Skip()
        elif key in [65, 67] and event.ControlDown():
            # pass ctrl + [c, a]
            event.Skip()
        elif key in [43, 45] and event.ControlDown():
            # pass ctrl + [-, =]
            event.Skip()

    def OnUpdateUI(self, evt):
        # check for matching braces
        braceAtCaret = -1
        braceOpposite = -1
        charBefore = None
        caretPos = self.GetCurrentPos()

        if caretPos > 0:
            charBefore = self.GetCharAt(caretPos - 1)
            styleBefore = self.GetStyleAt(caretPos - 1)

        # check before
        if charBefore and chr(charBefore) in "[]{}()" and styleBefore == stc.STC_P_OPERATOR:
            braceAtCaret = caretPos - 1

        # check after
        if braceAtCaret < 0:
            charAfter = self.GetCharAt(caretPos)
            styleAfter = self.GetStyleAt(caretPos)

            if charAfter and chr(charAfter) in "[]{}()" and styleAfter == stc.STC_P_OPERATOR:
                braceAtCaret = caretPos

        if braceAtCaret >= 0:
            braceOpposite = self.BraceMatch(braceAtCaret)

        if braceAtCaret != -1  and braceOpposite == -1:
            self.BraceBadLight(braceAtCaret)
        else:
            self.BraceHighlight(braceAtCaret, braceOpposite)
            #pt = self.PointFromPosition(braceOpposite)
            #self.Refresh(True, wxRect(pt.x, pt.y, 5,5))
            #print pt
            #self.Refresh(False)

    def OnMarginClick(self, evt):
        # fold and unfold as needed
        if evt.GetMargin() == 2:
            if evt.GetShift() and evt.GetControl():
                self.FoldAll()
            else:
                lineClicked = self.LineFromPosition(evt.GetPosition())

                if self.GetFoldLevel(lineClicked) & stc.STC_FOLDLEVELHEADERFLAG:
                    if evt.GetShift():
                        self.SetFoldExpanded(lineClicked, True)
                        self.Expand(lineClicked, True, True, 1)
                    elif evt.GetControl():
                        if self.GetFoldExpanded(lineClicked):
                            self.SetFoldExpanded(lineClicked, False)
                            self.Expand(lineClicked, False, True, 0)
                        else:
                            self.SetFoldExpanded(lineClicked, True)
                            self.Expand(lineClicked, True, True, 100)
                    else:
                        self.ToggleFold(lineClicked)

    def FoldAll(self):
        lineCount = self.GetLineCount()
        expanding = True

        # find out if we are folding or unfolding
        for lineNum in range(lineCount):
            if self.GetFoldLevel(lineNum) & stc.STC_FOLDLEVELHEADERFLAG:
                expanding = not self.GetFoldExpanded(lineNum)
                break

        lineNum = 0

        while lineNum < lineCount:
            level = self.GetFoldLevel(lineNum)
            if level & stc.STC_FOLDLEVELHEADERFLAG and \
               (level & stc.STC_FOLDLEVELNUMBERMASK) == stc.STC_FOLDLEVELBASE:

                if expanding:
                    self.SetFoldExpanded(lineNum, True)
                    lineNum = self.Expand(lineNum, True)
                    lineNum = lineNum - 1
                else:
                    lastChild = self.GetLastChild(lineNum, -1)
                    self.SetFoldExpanded(lineNum, False)

                    if lastChild > lineNum:
                        self.HideLines(lineNum+1, lastChild)

            lineNum = lineNum + 1

    def Expand(self, line, doExpand, force=False, visLevels=0, level=-1):
        lastChild = self.GetLastChild(line, level)
        line = line + 1

        while line <= lastChild:
            if force:
                if visLevels > 0:
                    self.ShowLines(line, line)
                else:
                    self.HideLines(line, line)
            else:
                if doExpand:
                    self.ShowLines(line, line)

            if level == -1:
                level = self.GetFoldLevel(line)

            if level & stc.STC_FOLDLEVELHEADERFLAG:
                if force:
                    if visLevels > 1:
                        self.SetFoldExpanded(line, True)
                    else:
                        self.SetFoldExpanded(line, False)

                    line = self.Expand(line, doExpand, force, visLevels-1)

                else:
                    if doExpand and self.GetFoldExpanded(line):
                        line = self.Expand(line, True, force, visLevels-1)
                    else:
                        line = self.Expand(line, False, force, visLevels-1)
            else:
                line = line + 1

        return line

    def get_selected_class(self):
        pass
        '''
        line_number = self.GetCurrentLine()
        return self.class_lines[line_number]
        '''

    def get_selected_routine_name(self):
        pass
        '''
        line_number = self.GetCurrentLine()
        return self.routine_lines[line_number]
        '''
        
    def reset(self):
        pass
        '''
        self.class_lines = []
        self.routine_lines = []
        '''

    def update(self):
        global ce
        pass
        '''
        cod = ce.cods[ce.current_cod_name]
        class_defs = [x.java_def() for x in cod.classes]
        routine_defs = [x.java_def() for x in cod.routines]
        self.reset()
        lines = self.GetText().splitlines()

        self.class_lines = [None,] * len(lines)
        self.routine_lines = [None,] * len(lines)
        
        for line in lines:
            if
        '''
        

class CodExplorer(wx.Frame):
    def __init__(self, parent, id, paths = [], cache_path = None, startup_load_cods = []):
        global ce
        wx.Frame.__init__(self, parent, id, 'Cod Explorer')

        ce = self

        self.font = wx.Font(8, wx.DEFAULT, wx.NORMAL, wx.NORMAL, False, faces['mono'])
        #self.SetStatusText(intro)
        self.splitter3 = wx.SplitterWindow(self, ID_SPLITTER3, style=wx.SP_BORDER)
        self.splitter3.SetMinimumPaneSize(50)
        
        self.splitter = wx.SplitterWindow(self.splitter3, ID_SPLITTER, style=wx.SP_BORDER)
        self.splitter.SetMinimumPaneSize(50)

        self.nav_notebook = wx.Notebook(self.splitter, -1)
        self.cod_nav_tab = CodNav(self.nav_notebook, -1)
        self.package_nav_tab = PackageNav(self.nav_notebook, -1)
        self.nav_notebook.AddPage(self.cod_nav_tab, 'Cod files')
        self.nav_notebook.AddPage(self.package_nav_tab, 'Packages')
        self.cod_nav_tab.SetFocus()

        self.info_notebook = wx.Notebook(self.splitter, -1) # , style=wx.TOP
        self.text = JavaBrowser(self.info_notebook, -1)
        #self.graph = GraphBrowser(self.info_notebook, -1)
        self.info_notebook.AddPage(self.text, 'Code view')
        #self.info_notebook.AddPage(self.graph, 'Graph view')
        self.set_text('')
        '''
        if not _USE_PANEL:
            ed = p = PythonSTC(nb, -1)
        else:
            p = wx.Panel(nb, -1, style = wx.NO_FULL_REPAINT_ON_RESIZE)
            ed = PythonSTC(p, -1)
            s = wx.BoxSizer(wx.HORIZONTAL)
            s.Add(ed, 1, wx.EXPAND)
            p.SetSizer(s)
            p.SetAutoLayout(True)
        '''

        #p2 = MyListCtrl(self.splitter, -1)
        self.splitter.SplitVertically(self.nav_notebook, self.info_notebook, 300)

        #self.Bind(wx.EVT_SIZE, self.OnSize)

        filemenu= wx.Menu()
        filemenu.Append(ID_OPEN_PATH, "&Open the primary COD path", " Open a directory of extracted COD files for analysis")
        filemenu.Append(ID_NEW_SEARCH_PATH, "Open an &additional COD path", "Open an additional directory of extracted COD files for analysis")
        filemenu.Append(ID_OPEN_NAME_DB, "Open &name database", "Open &name database for renaming")
        filemenu.Append(ID_EXIT, "E&xit", " Terminate the program")

        menuBar = wx.MenuBar()
        menuBar.Append(filemenu, "&File")
        self.SetMenuBar(menuBar)
        self.Bind(wx.EVT_MENU, self.OnExit, id=ID_EXIT)
        self.Bind(wx.EVT_MENU, self.OnOpenPath, id=ID_OPEN_PATH)
        self.Bind(wx.EVT_MENU, self.OnNewSearchPath, id=ID_NEW_SEARCH_PATH)
        self.Bind(wx.EVT_MENU, self.OnOpenNameDB, id=ID_OPEN_NAME_DB)

        tb = self.CreateToolBar( wx.TB_HORIZONTAL | wx.NO_BORDER | wx.TB_FLAT | wx.TB_TEXT)

        tsize = (24,24)
        tb.AddSimpleTool(ID_PREVIOUS, wx.ArtProvider.GetBitmap(wx.ART_GO_BACK, wx.ART_TOOLBAR, tsize), 'Previous')
        tb.AddSimpleTool(ID_FORWARD, wx.ArtProvider.GetBitmap(wx.ART_GO_FORWARD, wx.ART_TOOLBAR, tsize), 'Forward')
        tb.AddSeparator()
        tb.AddSimpleTool(ID_EXPORT_ALL, wx.ArtProvider.GetBitmap(wx.ART_FILE_SAVE, wx.ART_TOOLBAR, tsize), 'Export all')
        tb.AddSimpleTool(ID_EXPORT_CURRENT, wx.ArtProvider.GetBitmap(wx.ART_FILE_SAVE, wx.ART_TOOLBAR, tsize), 'Export currently resolved')
        tb.AddSimpleTool(ID_EXPORT_SELECTION, wx.ArtProvider.GetBitmap(wx.ART_FILE_SAVE, wx.ART_TOOLBAR, tsize), 'Export selection')
        tb.AddSeparator()
        tb.AddSimpleTool(ID_FUNCTION_SIBLINGS, wx.ArtProvider.GetBitmap(wx.ART_REPORT_VIEW, wx.ART_TOOLBAR, tsize), 'Display function call graph for all siblings of currently selected cod')
        tb.AddSimpleTool(ID_FUNCTION_SELECTED, wx.ArtProvider.GetBitmap(wx.ART_REPORT_VIEW, wx.ART_TOOLBAR, tsize), 'Display function call graph for currently selected cod')
        tb.AddSeparator()
        tb.AddSimpleTool(ID_RENAME_ROUTINE, wx.ArtProvider.GetBitmap(wx.ART_INFORMATION, wx.ART_TOOLBAR, tsize), 'Rename a routine')
        tb.AddSimpleTool(ID_RENAME_FIELD, wx.ArtProvider.GetBitmap(wx.ART_INFORMATION, wx.ART_TOOLBAR, tsize), 'Rename a field')
        tb.Realize()

        self.Bind(wx.EVT_TOOL, self.OnPrevious, id=ID_PREVIOUS)
        self.Bind(wx.EVT_TOOL, self.OnForward, id=ID_FORWARD)
        self.Bind(wx.EVT_TOOL, self.OnExportAll, id=ID_EXPORT_ALL)
        self.Bind(wx.EVT_TOOL, self.OnExportCurrent, id=ID_EXPORT_CURRENT)
        self.Bind(wx.EVT_TOOL, self.OnExportSelection, id=ID_EXPORT_SELECTION)
        self.Bind(wx.EVT_TOOL, self.OnFunctionSiblings, id=ID_FUNCTION_SIBLINGS)
        self.Bind(wx.EVT_TOOL, self.OnFunctionSelected, id=ID_FUNCTION_SELECTED)
        self.Bind(wx.EVT_TOOL, self.OnRenameRoutine, id=ID_RENAME_ROUTINE)
        self.Bind(wx.EVT_TOOL, self.OnRenameField, id=ID_RENAME_FIELD)

        #self.sizer2 = wx.BoxSizer(wx.HORIZONTAL)

        self.splitter2 = wx.SplitterWindow(self.splitter3, ID_SPLITTER2, style=wx.SP_BORDER)
        self.splitter2.SetMinimumPaneSize(50)

        intro = ''
        intro += 'codlib:  cod analysis library\n'
        intro += 'ce:      cod explorer wx frame\n'
        intro += 'ce.cods: dictionary of currently loaded cods (cod module name => cod module)\n'
        self.py = py.shell.Shell(self.splitter2, -1, introText=intro, locals={'ce': self, 'codlib': codlib})
        
        self.log = wx.TextCtrl(self.splitter2, -1, '', style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.log.flush = lambda: True
        self.log.SetFont(self.font)

        self.splitter2.SplitHorizontally(self.py, self.log, -100)
        self.splitter3.SplitHorizontally(self.splitter, self.splitter2, -300)
        
        #self.sizer2.Add(self.splitter2, 1, wx.EXPAND)

        #self.sizer = wx.BoxSizer(wx.VERTICAL)
        #self.sizer.Add(self.splitter, 3, wx.EXPAND)
        #self.sizer.Add(self.sizer2, 1, wx.EXPAND)
        #self.SetSizer(self.sizer)

        #size = wx.DisplaySize()
        #self.SetSize(size)
        
        self.sb = self.CreateStatusBar()
        status = self.sb
        self.sb.SetStatusText('')
        self.Center()
        self.Maximize()
        self.Show(True)

        self.reset()
        self.paths = paths
        self.cache_path = cache_path

        if self.paths:
            self.update()
        else:
            self.OnOpenPath(None)

        for cod_name in startup_load_cods:
            cod_name = os.path.splitext(os.path.split(cod_name)[1])[0]
            self.open_cod(cod_name)

    def set_text(self, text, line_number=None):
        """ Load the code view window with text.
        """
        self.text.SetText(text)
        self.text.EmptyUndoBuffer()
        self.text.Colourise(0, -1)
        self.text.SetMarginType(1, stc.STC_MARGIN_NUMBER)
        self.text.SetMarginWidth(1, 25)
        self.text.update()
        self.text.SetFocus()
        if line_number is not None:
            ce.text.ScrollToLine(line_number)

    def update(self):
        if not self.paths:
            return
        
        if not self.loader:
            if not self.cache_path:
                self.cache_path = self.find_cache_path()
            self.loader = codlib.Loader(self.paths, cache_root=self.cache_path, auto_resolve=True, log_file=self.log)
            self.hi_scanner = codlib.HIScanner(self.loader)
            self.cods = {}
            self.cod_filenames = {}
            self.cod_names = []
        else:
            if not self.cache_path:
                self.cache_path = self.find_cache_path()
                self.loader.set_cache_root(self.cache_path)

        for path in self.paths:
            if not os.path.isdir(path):
                self.log.WriteText('Cod path %s does not exist!\n' % path)
                self.sb.SetStatusText('Could not load cod path %s...' % path)
                self.reset()
                return

            self.log.WriteText('Opening cod path %s\n' % path)
            
            cod_filenames = [os.path.join(path, x) for x in os.listdir(path) if os.path.isfile(os.path.join(path, x)) and x.endswith('.cod')]
            cod_filenames.sort()
            for cod_filename in cod_filenames:
                cod_name = os.path.splitext(os.path.basename(cod_filename))[0]
                # skip duplicate cods
                if cod_name not in self.cod_names:
                    self.cod_names.append(cod_name)
                    self.cod_filenames[cod_name] = cod_filename

        self.cod_nav_tab.update()
        self.package_nav_tab.update()

        self.sb.SetStatusText('Cod directory successfully initialized')

    def reset(self):
        self.cods = {}
        self.cod_filenames = {}
        self.cod_names = []
        self.history = []
        self.forward_history = []
        self.current_cod_name = None
        self.loader = None
        self.paths = []
        self.cache_path = None
        self.set_text('')
        self.cod_nav_tab.reset()

    def load_cod(self, cod_name):
        """ Performs resolution on cod file cod_name and all of its dependencies.
        """
        if cod_name not in self.cods:
            # we need to resolve this one
            try:
                self.sb.SetStatusText('Loading %s... (%s)' % (cod_name, self.cod_filenames[cod_name]))
                cod = self.loader.load_module(self.cod_filenames[cod_name])
                cod.resolve()
                cod.actualize()
                cod.disasm()
                self.cods[cod_name] = cod
                self.package_nav_tab.update()
                self.sb.SetStatusText('Loaded %s (%s)' % (cod_name, self.cod_filenames[cod_name]))
                self.log.WriteText("Loader cache: %d modules containing %d classes\n" % (len(self.loader._modules), len(self.loader._classes)))
            except Exception, e:
                self.sb.SetStatusText('Could not load %s! (%s)' % (cod_name, self.cod_filenames[cod_name]))
                self.log.WriteText('Could not load %s! (%s)\n' % (cod_name, self.cod_filenames[cod_name]))
                self.log.WriteText('    %s\n' % str(e))
                import traceback
                traceback.print_exc(file=self.log)
                return None
        else:
            cod = self.cods[cod_name]
        return cod

    def open_package(self, package_name, cod_name, track_history=True):
        """ Opens a package if it has already been resolved from a cod file
            and loads it into the GUI for analysis.
        """        
        if track_history:
            self.forward_history = []
            if self.current_cod_name:
                self.history.append((self.current_cod_name, self.text.GetCurrentLine()))

        cod = self.load_cod(cod_name)
        if cod:
            self.current_cod_name = cod_name
            dump = StringIO()
            D = codlib.ResolvedDumper(dump)
            D.dump_module(cod, True)
            dump.seek(0)
            #ce.cod_dumps[cod_name] = dump.read()
            #ce.set_text(ce.cod_dumps[cod_name])
            text = dump.read()
            # seek to this class
            try:
                line_number = text[:indexes(text, 'class '+package_name+' ')[-1]].count('\n')
            except IndexError:
                try:
                    line_number = text[:indexes(text, 'interface '+package_name+' ')[-1]].count('\n')
                except IndexError:
                    # could not find it for some reason
                    line_number = 0
            self.set_text(text, line_number=line_number)
            return cod

        self.sb.SetStatusText('Could not find package %s' % package_name)
        self.log.WriteText('Could not find package %s' % package_name)
        return None

    def open_cod(self, cod_name, line_number=0, track_history=True):
        """ Performs resolution on cod file cod_name and all of its dependencies
            and loads it into the GUI for analysis.
        """
        if track_history:
            self.forward_history = []
            if self.current_cod_name:
                self.history.append((self.current_cod_name, self.text.GetCurrentLine()))

        cod = self.load_cod(cod_name)
        if cod:
            self.current_cod_name = cod_name
            dump = StringIO()
            D = codlib.ResolvedDumper(dump)
            D.dump_module(cod, True)
            dump.seek(0)
            #ce.cod_dumps[cod_name] = dump.read()
            #ce.set_text(ce.cod_dumps[cod_name])
            self.set_text(dump.read(), line_number=line_number)
            return cod
        self.sb.SetStatusText('Could not open cod %s' % cod_name)
        self.log.WriteText('Could not open cod %s' % cod_name)
        return None

    def refresh(self):
        if self.current_cod_name:
            current_pos = self.text.GetCurrentPos()
            self.open_cod(self.current_cod_name, self.text.GetCurrentLine(), track_history=False)
            self.text.SetCurrentPos(current_pos)

    '''def add_new_search_path(self, new_path):
        """ Append a new search path to the current list of paths containing cod files.
        """
        if self.loader:
            self.paths.append(new_path)
            if not self.cache_path:
                self.cache_path = self.find_cache_path()
                self.loader.set_cache_root(self.cache_path)
            self.loader.add_new_search_path(new_path)
        else:
            dlg = wx.MessageDialog(self,
                                   'A cod directory has not been selected.  Please select a cod directory first.',
                                   'Warning',
                                   wx.OK | wx.ICON_INFORMATION
                                   #wx.YES_NO | wx.NO_DEFAULT | wx.CANCEL | wx.ICON_INFORMATION
                                   )
            dlg.ShowModal()
            dlg.Destroy()
    '''

    def find_cache_path(self):
        """ Returns the first located cache path in the paths list or None
        """
        for path in self.paths:
            if os.path.isfile(path + '_cache.zip'):
                return path + '_cache.zip'
            elif os.path.isdir(path + '_cache'):
                return path + '_cache'
        return None
            
    def OnExit(self, event):
        self.Close(True)

    def OnOpenPath(self, event):
        dlg = wx.DirDialog(self, "Choose a COD directory:",
                           defaultPath=os.path.realpath('.'),
                           style=wx.DD_DEFAULT_STYLE
                               | wx.DD_DIR_MUST_EXIST
                              #| wx.DD_CHANGE_DIR
                           )
        if dlg.ShowModal() == wx.ID_OK:
            self.paths = [dlg.GetPath(), ]
            dlg.Destroy()
        else:
            dlg.Destroy()
            return

        self.cache_path = self.find_cache_path()
        if not self.cache_path:
            dlg = wx.MessageDialog(self, 'Could not find cache path',
                       'A cache could not be automatically found.  Would you like to specify a cache?',
                       wx.ICON_INFORMATION | wx.YES_NO
                       )
            cache = dlg.ShowModal()
            dlg.Destroy()

            if cache == wx.ID_YES:
                dlg = wx.MessageDialog(self, 'Cache type selection',
                           'Is the cache zip compressed?',
                           wx.ICON_INFORMATION | wx.YES_NO
                           )
                zipped = dlg.ShowModal()
                dlg.Destroy()
                if zipped == wx.ID_YES:
                    dlg = wx.FileDialog(self, message="Choose a COD cache zip file:",
                                        defaultDir=os.path.realpath('.'),
                                        defaultFile="",
                                        wildcard="Zip files (*.zip)|*.zip",
                                        style=wx.OPEN | wx.CHANGE_DIR
                                       )
                    if dlg.ShowModal() == wx.ID_OK:
                        self.cache_path = dlg.GetPath()
                        dlg.Destroy()
                    else:
                        self.cache_path = None
                        dlg.Destroy()
                elif zipped == wx.ID_NO:
                    dlg = wx.DirDialog(self, "Choose a COD cache directory:",
                                       defaultPath=os.path.realpath('.'),
                                       style=wx.DD_DEFAULT_STYLE
                                          #| wx.DD_DIR_MUST_EXIST
                                          #| wx.DD_CHANGE_DIR
                                       )
                    if dlg.ShowModal() == wx.ID_OK:
                        self.cache_path = dlg.GetPath()
                        dlg.Destroy()
                    else:
                        self.cache_path = None
                        dlg.Destroy()
            
        self.update()

    def OnPrevious(self, event):
        if self.history:
            hist = self.history.pop()
            self.forward_history.append((self.current_cod_name, self.text.GetCurrentLine()))
            cod_name, line_number = hist
            self.open_cod(cod_name, line_number=line_number, track_history=False)

    def OnForward(self, event):
        if self.forward_history:
            hist = self.forward_history.pop()
            self.history.append((self.current_cod_name, self.text.GetCurrentLine()))
            cod_name, line_number = hist
            self.open_cod(cod_name, line_number=line_number, track_history=False)

    def OnNewSearchPath(self, event):
        dlg = wx.DirDialog(self, "Choose a COD directory:",
                           defaultPath=os.path.realpath('.'),
                           style=wx.DD_DEFAULT_STYLE
                               | wx.DD_DIR_MUST_EXIST
                              #| wx.DD_CHANGE_DIR
                           )
        if dlg.ShowModal() == wx.ID_OK:
            self.paths.append(dlg.GetPath())
            dlg.Destroy()
            self.update()
        else:
            dlg.Destroy()

    def export(self, cod_name, path):
        """ Export cod dump and package information to a specified path.
        """
        cod = self.load_cod(cod_name)
        if not cod:
            self.log.WriteText('Could not export %s!\n' % cod_name)
            return
        self.sb.SetStatusText('Exporting %s...' % cod_name)
        self.log.WriteText('Exporting %s...\n' % cod_name)
        try:
            D = codlib.ResolvedDumper(open(os.path.join(path, 'dumps', cod_name + '.txt'), 'w'))
            D.dump_module(cod, True)

            PD = codlib.PackageDumper(os.path.join(path, 'packages'))
            for class_def in cod.classes:
                PD.dump_class_file(class_def)
        except Exception, e:
            self.log.WriteText('Could not export %s!\n' % cod_name)
            self.log.WriteText('    %s\n' % str(e))            
          
    def OnExportAll(self, event):
        path = None
        dlg = wx.DirDialog(self, "Choose a directory:",
                           style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
        dlg.Destroy()

        if path:
            try: os.mkdir(os.path.join(path, 'dumps'))
            except: pass
            try: os.mkdir(os.path.join(path, 'packages'))
            except: pass

            for cod_name in self.cod_names:
                self.export(cod_name, path)

            self.sb.SetStatusText('Export completed')
            self.log.WriteText('Export completed\n')
        
    def OnExportCurrent(self, event):
        path = None
        dlg = wx.DirDialog(self, "Choose a directory:",
                           style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
        dlg.Destroy()

        if path:
            try: os.mkdir(os.path.join(path, 'dumps'))
            except: pass
            try: os.mkdir(os.path.join(path, 'packages'))
            except: pass

            for cod_name in self.cods.keys():
                self.export(cod_name, path)

            self.sb.SetStatusText('Export completed')
            self.log.WriteText('Export completed\n')
        
    def OnExportSelection(self, event):
        path = None
        dlg = wx.DirDialog(self, "Choose a directory:",
                           style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            path = dlg.GetPath()
        dlg.Destroy()

        item = self.cod_nav_tab.currentItem
        if path and item >= 0:
            try: os.mkdir(os.path.join(path, 'dumps'))
            except: pass
            try: os.mkdir(os.path.join(path, 'packages'))
            except: pass

            cod_name = self.cod_nav_tab.GetItemText(item)
            if cod_name:
                self.export(cod_name, path)

            self.sb.SetStatusText('Export completed')
            self.log.WriteText('Export completed\n')

    def function_flow_graph(self, selected_functions, title = 'Function flow graph'):
        # set of all function either called or calling
        function_names = set()
        # set of tuples of all calls
        function_calls = set()
        
        for function in selected_functions:
            function_name = str(function)
            function_names.add(function_name)

            # perform a hiscan for better analysis
            subroutine = codlib.Subroutine(function)
            try:
                self.hi_scanner.scan(subroutine)
            except Exception, e:
                print >>self.log, 'Could not scan routine %s: %s' % (function.to_jts(), str(e))
            
            for instruction in function.instructions:
                if 'invoke' in instruction._name:
                    callee = instruction.operands[0]
                    if isinstance(callee, codlib.resolve.RoutineDef):
                        callee_name = str(callee)
                        function_names.add(callee_name)
                        function_calls.add((function_name, callee_name))

        gdl_filename = 'function_flow_graph.gdl'
        with open(gdl_filename, 'wt') as fd:
            print >> fd, 'graph:{title:"%s"' % title
            print >> fd, 'layoutalgorithm: minbackward\nyspace:210'
            #print >> fd, '/*layoutalgorithm: mindepth*/'
            for function_name in function_names:
                label = "%s" % (function_name)
                border_col = 'black'
                print >> fd, 'node:{title:"%s" bordercolor:%s label:"%s"}' % (function_name, border_col, label)
            for caller, callee in function_calls:
                caller_name = str(caller)
                callee_name = str(callee)
                extra = ''
                print >> fd, 'edge:{sourcename:"%s" targetname:"%s" %s}' % (caller_name, callee_name, extra)
                
            print >> fd, '}'
        os.system('start %s' % gdl_filename)
        return

    def function_flow_graph_package(self, package_name):
        functions = self.loader.load_class(package_name).routines
        title = 'Function flow graph of class %s' % package_name
        self.function_flow_graph(functions, title)
       
    def OnFunctionSiblings(self, event):
        item = self.cod_nav_tab.currentItem
        if item >= 0:
            cod_name = self.cod_nav_tab.GetItemText(item)
            cod = self.load_cod(cod_name)
            sibling_names = cod.siblings
            functions = []
            for sibling_name in sibling_names:
                cod = self.load_cod(cod_name)
                for cod_class in cod.classes:
                    functions += cod_class.routines
            title = 'Function flow graph for %s and siblings' % cod_name
            self.function_flow_graph(functions, title)
    def OnFunctionSelected(self, event):
        item = self.cod_nav_tab.currentItem
        if item >= 0:
            cod_name = self.cod_nav_tab.GetItemText(item)
            cod = self.load_cod(cod_name)
            functions = []
            for cod_class in cod.classes:
                functions += cod_class.routines
            title = 'Function flow graph for %s' % cod_name
            self.function_flow_graph(functions, title)

    def OnOpenNameDB(self, event):
        if self.loader:
            dlg = wx.FileDialog(self, message="Choose a renaming database file:",
                                defaultDir=os.path.realpath('.'),
                                defaultFile="names.db",
                                wildcard="Database files (*.db)|*.db",
                                style=wx.OPEN | wx.CHANGE_DIR
                               )

            if dlg.ShowModal() == wx.ID_OK:
                path = dlg.GetPath()
                dlg.Destroy()
                print >>self.log, 'Opening name database: %s' % path
                self.loader.open_name_db(path)
                self.refresh()
            else:
                dlg.Destroy()

    def OnRenameRoutine(self, event):
        if self.loader:
            if not self.loader.name_db_path:
                self.OnOpenNameDB(None)
                if not self.loader.name_db_path:
                    return

            dlg = wx.TextEntryDialog(
                self, 'Enter the Java type string for the routine to rename:',
                'Rename routine', '')
            dlg.SetValue("foo/bar/SomeClass/my_routine(Ljava/lang/Object;)I")

            if dlg.ShowModal() == wx.ID_OK:
                old_name = dlg.GetValue()
                dlg.Destroy()
            else:
                dlg.Destroy()
                return

            dlg = wx.TextEntryDialog(
                self, 'Enter the new routine name:',
                'Rename routine', '')
            dlg.SetValue("my_new_routine_name")

            if dlg.ShowModal() == wx.ID_OK:
                new_name = dlg.GetValue()
                dlg.Destroy()
            else:
                dlg.Destroy()
                return
            try:
                self.loader.rename_routine(old_name, new_name)
                self.refresh()
            except Exception, e:
                print >>self.log, str(e)

    def OnRenameField(self, event):
        if self.loader:
            if not self.loader.name_db_path:
                self.OnOpenNameDB(None)
                if not self.loader.name_db_path:
                    return

            dlg = wx.TextEntryDialog(
                self, 'Enter the Java type string for the field to rename:',
                'Rename field', '')
            dlg.SetValue("foo/bar/SomeClass/my_field")

            if dlg.ShowModal() == wx.ID_OK:
                old_name = dlg.GetValue()
                dlg.Destroy()
            else:
                dlg.Destroy()
                return

            dlg = wx.TextEntryDialog(
                self, 'Enter the new field name:',
                'Rename field', '')
            dlg.SetValue("my_new_field_name")

            if dlg.ShowModal() == wx.ID_OK:
                new_name = dlg.GetValue()
                dlg.Destroy()
            else:
                dlg.Destroy()
                return

            try:
                self.loader.rename_field(old_name, new_name)
                self.refresh()
            except Exception, e:
                print >>self.log, str(e)


if __name__ == '__main__':
    paths = []

    usage = 'usage: %prog [options] [cod_path1 [cod_path2 [...]]]'
    parser = OptionParser(usage)
    parser.add_option("-c", "--cache-root", dest="cache_root",
                      help="load cached modules/classes from CACHE_ROOT",
                      default=None, metavar="CACHE_ROOT")
    
    (options, args) = parser.parse_args()

    paths = []
    cods_to_open = []
    for path in args:
        if os.path.isfile(path):
            filename_path, filename = os.path.split(path)
            paths.append(filename_path)
            cods_to_open.append(path)
        elif os.path.isdir(path):
            paths.append(path)

    app = wx.App(0)
    ce = CodExplorer(None, -1, paths = paths, cache_path = options.cache_root, startup_load_cods = cods_to_open)

    app.MainLoop()