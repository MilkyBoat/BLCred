import random
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp

# 在FBB和WBB中遇到的一个Bug
G = bp.BpGroup()
p=19
m=16
x = Bn(p).random()
print(x)
# 这种情况会报错:TypeError: bad operand type for abs(): 'Bn'
num = Bn(x+m).mod_inverse(G.order())
print(num)
# 解决方案:改为如下写法
num = Bn(int(x+m)).mod_inverse(G.order())
print(num)

# 在BLS，FBB，WBB中会遇到另外一个Bug
# 无法使用大整数问题：如果是Bn(x)，x不能超过2^32，而且必须是int类型，即最好写成Bn(int(x))，否则可能报错（上述
# 因此我们可以用别的方法来避免这种调用
Bn.from_decimal(str(x+m))