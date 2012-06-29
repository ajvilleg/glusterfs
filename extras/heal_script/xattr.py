import ctypes

try:
        dlhandle = ctypes.CDLL("libc.so.6")
        raw_get = dlhandle.getxattr
        raw_set = dlhandle.setxattr
except (OSError, AttributeError):
        pass

def get (path, name):
        if not raw_get:
                raise RuntimeError, "raw_get function not available"
        buf = ctypes.create_string_buffer(1024)
        size = raw_get(path,name,buf,1024)
        if size < 0:
                return size
        return buf.raw[:size]

def set (path, name, value):
        if not raw_set:
                raise RuntimeError, "raw_set function not available"
        size = raw_set(path,name,value,len(value),0)
        if size < 0:
                return size

