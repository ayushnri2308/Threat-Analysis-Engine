import os
with open('high_entropy_test.bin', 'wb') as f:
    f.write(os.urandom(1024 * 1024)) # 1MB of random data