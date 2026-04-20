import ctypes as ct


class CommonData(ct.Structure):
    _fields_ = [
        ("type", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("comm", ct.c_char * 16)
    ]


class ExecData(ct.Structure):
    _fields_ = [
        ("common", CommonData),
        ("filename", ct.c_char * 256),
        ("arg", ct.c_char * 128)
    ]


class ConnectData(ct.Structure):
    _fields_ = [
        ("common", CommonData),
        ("ip", ct.c_uint32),
        ("port", ct.c_uint16),
        ("_pad", ct.c_uint16)
    ]


class MemfdData(ct.Structure):
    _fields_ = [
        ("common", CommonData),
        ("name", ct.c_char * 256)
    ]


class MprotectData(ct.Structure):
    _fields_ = [
        ("common", CommonData),
        ("addr", ct.c_uint64),
        ("len", ct.c_uint64),
        ("prot", ct.c_uint32),
        ("_pad", ct.c_uint32)
    ]


class VMWriteData(ct.Structure):
    _fields_ = [
        ("common", CommonData),
        ("target_pid", ct.c_uint32),
        ("_pad", ct.c_uint32),
        ("remote_addr", ct.c_uint64),
        ("local_addr", ct.c_uint64),
        ("bytes", ct.c_uint64)
    ]