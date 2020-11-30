
from building import *
import rtconfig

cwd     = GetCurrentDir()
src     = Glob('src/*.c')
src     += Glob('wolfcrypt/src/*.c')
src     += Glob('examples/*.c')

CPPPATH = [cwd]
LOCAL_CCFLAGS = ''


group = DefineGroup('wolfSSL', src, depend = [], CPPPATH = CPPPATH, LOCAL_CCFLAGS = LOCAL_CCFLAGS)

Return('group')