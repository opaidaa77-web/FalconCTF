from config.settings import *
from modules.system_info import get_system_info

print("=" * 40)
print(" Welcome to", PROJECT_NAME)
print("=" * 40)

get_system_info()
