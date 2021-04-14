env = Environment(
    CCFLAGS=['-Wall','-Werror','-g'],
    #CPPDEFINES={'DEBUG': None},
)

env.Program(
    target = 'rawrsa',
    source = [
        'main.c',
        'librsaconverter.c',
    ],
    LIBS=['crypto'],
)
