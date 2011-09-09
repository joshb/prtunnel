# Microsoft Developer Studio Generated NMAKE File, Based on prtunnel.dsp

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE 
NULL=nul
!ENDIF 

OUTDIR=.\Release
INTDIR=.\Release

ALL : "$(OUTDIR)\prtunnel.exe"


CLEAN :
	-@erase "$(INTDIR)\connect.obj"
	-@erase "$(INTDIR)\direct.obj"
	-@erase "$(INTDIR)\getopt.obj"
	-@erase "$(INTDIR)\http.obj"
	-@erase "$(INTDIR)\main.obj"
	-@erase "$(INTDIR)\proxy.obj"
	-@erase "$(INTDIR)\socks5.obj"
	-@erase "$(OUTDIR)\prtunnel.exe"

"$(OUTDIR)" :
    if not exist "$(OUTDIR)/$(NULL)" mkdir "$(OUTDIR)"

CPP=cl.exe
CPP_PROJ=/nologo /MD /W3 /O2 /Ob2 /I "./" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /Fo"$(INTDIR)\\" /Fd"$(INTDIR)\\" /FD /c 

.c{$(INTDIR)}.obj::
   $(CPP) @<<
   $(CPP_PROJ) $< 
<<

LINK32=link.exe
LINK32_FLAGS=kernel32.lib user32.lib gdi32.lib advapi32.lib ws2_32.lib /nologo /subsystem:console /incremental:no /pdb:"$(OUTDIR)\prtunnel.pdb" /machine:I386 /out:"$(OUTDIR)\prtunnel.exe" 
LINK32_OBJS= \
	"$(INTDIR)\connect.obj" \
	"$(INTDIR)\direct.obj" \
	"$(INTDIR)\getopt.obj" \
	"$(INTDIR)\http.obj" \
	"$(INTDIR)\main.obj" \
	"$(INTDIR)\proxy.obj" \
	"$(INTDIR)\socks5.obj"

"$(OUTDIR)\prtunnel.exe" : "$(OUTDIR)" $(DEF_FILE) $(LINK32_OBJS)
    $(LINK32) @<<
  $(LINK32_FLAGS) $(LINK32_OBJS)
<<


