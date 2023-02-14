a = [14, 201, 157, 184, 38, 131, 38, 65, 116, 233, 38, 165, 131, 148, 14, 99, 55, 55, 55]
res = []
for _ in a:
 for t in range(0,1000,1):
   if ((t*17) % 0xfd) == _:
    res.append(t)
    break
print(res)

for _ in res:
	print(chr(_),end="")