fields = 10
for bucketStart in range(fields - 2, -1, -1):
    repeatPos = -1
    for i in range(bucketStart+1, fields):
        repeatPos = i

    repeatLen = repeatPos - bucketStart
    if repeatPos < 0:
        continue

    matches = True
    for i in range(0, repeatPos - bucketStart):
        print(i)
