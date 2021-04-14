env = Environment(
    CCFLAGS=['-Wall','-Werror','-g'],
    #CPPDEFINES={'DEBUG': None},
)

env.Program('rawrsa', ['main.c'], LIBS=['crypto'])
