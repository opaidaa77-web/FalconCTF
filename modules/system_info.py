import platform


def get_system_info():
    print("Operating System :", platform.system())
    print("Release          :", platform.release())
    print("Machine          :", platform.machine())
    print("Processor        :", platform.processor())
