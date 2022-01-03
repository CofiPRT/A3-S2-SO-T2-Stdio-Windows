build:
	cl /nologo /DDLL_IMPORTS /Z7 /MD /w /c so_stdio.c
	link /nologo /dll /out:so_stdio.dll /implib:so_stdio.lib so_stdio.obj

clean:
	del /Q /F *.obj *.lib *.dll