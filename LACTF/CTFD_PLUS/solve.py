from z3 import *

ida_chars = \
[\
 0x9c7f9274,\
 0xc2bb0ce9,\
 0x409b1929,\
 0xbe3d6ed7,\
 0x4f83e104,\
 0x9185d483,\
 0xfd5d70af,\
 0x88c47ff1,\
 0xe678fa71,\
 0x72cbdf0d,\
 0xf4b63da7,\
 0x54299e3d,\
 0xaa057bf4,\
 0x14144da3,\
 0xe1c6023c,\
 0x74b9b539,\
 0x545fd80f,\
 0x47a7329,\
 0xad41d93f,\
 0x9616bcd0,\
 0x76596250,\
 0xaaa7ec0f,\
 0x21b1f22f,\
 0x8780b37e,\
 0x768d1415,\
 0x56f3ad60,\
 0x2c846f4d,\
 0x1538573e,\
 0x6a957b9e,\
 0xaa030870,\
 0x27c7bfbc,\
 0x472e884d,\
 0xbc340971,\
 0x9570c094,\
 0xd65521ea,\
 0x868414be,\
 0xfff7ec8d,\
 0xaa1465ff,\
 0x21d16aa7,\
 0x8497c10c,\
 0x513ad2f7,\
 0x6211bbca,\
 0x8799c8e5,\
 0xb537fcbd,\
 0x44cc29ed,\
 0x408ad95d,\
 0x2d0902b1]

for value in ida_chars:
	edi = BitVecVal(value,32)
	eax = BitVecVal(0,32)
	for i in range(32):
		edi = edi*edi
		edi = RotateRight(edi, i)
		edi = edi * 0x1337 + 0x4201337
		edi = edi ^ eax
		eax += 0x13371337
	eax = edi
	edx = edi
	eax = eax >> 8
	edx = edx >> 0x10
	eax = eax + edx + edi
	edi = edi >> 0x18
	eax = eax + edi
	print(chr(int(simplify(eax).sexpr()[2:],16) & 0xff),end="")