from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp
# 计时函数
import time

class BLS:
    
    def __init__(self,p,m):
        self.G = bp.BpGroup()
        # g1, g2 is the generator of G1, G2 
        self.g1, self.g2 = self.G.gen1(), self.G.gen2()
        self.x = 0
        self.X = 0
        self.p = p
        self.m = m
        self.h = 0
        print("G的order为",self.G.order())

    def keygen(self,p):
        self.x = Bn().from_decimal(str(self.p)).random()
        self.X = self.x * self.g2
        sk = self.x
        vk = self.X
        return sk,vk
    
    def sign(self,sk,m):
        # 输入类型检测,要求m属于Zp
        try:
            m = Bn.from_decimal(str(m))
            if m < 0 or m > self.p:  # if not a positive int print message and ask for input again
                print("m is out of range, please ensure m to be an integer in [0,p)")
        except ValueError:
            print("m is not an int, please ensure m to be an integer in [0,p)")
        # 把这个整数类型的信息m转化为字符串类型,便于使用hashG1函数
        m = str(m)
        self.h = self.G.hashG1(m.encode("utf8"))
        theta = self.x * self.h
        return theta

    def verify(self,vk,m,theta):
        return self.G.pair(theta,self.g2)==self.G.pair(self.h,self.X)



class WBB:
    
    def __init__(self,p,m):
        self.G = bp.BpGroup()
        # g1, g2 分别是G1，G2的生成元
        self.g1, self.g2 = self.G.gen1(), self.G.gen2()
        # x,X 分别是私钥和公钥
        self.x = 0
        self.X = 0
        # p,m是传入的参数，p为传入的大质数，G1，G2，GT的阶为另一个给定的大质数，m是传入的消息，属于Zp
        self.p = p
        self.m = m

    # 生成公钥和私钥
    def keygen(self,p):
        # 调用petlib.bn中的Bn，生成(0,p)的随机数，作为私钥sk
        self.x = Bn().from_decimal(str(self.p)).random()
        # 将私钥x与g2做标量乘法,得到公钥X
        self.X = self.x * self.g2
        sk = (self.x)
        vk = (self.X)
        return sk,vk
    
    # 生成数字签名
    def sign(self,sk,m):
        # 输入类型检测,要求m属于Zp
        try:
            m = Bn.from_decimal(str(m))
            if m < 0 or m > self.p:  # if not a positive int print message and ask for input again
                print("m is out of range, please ensure m to be an integer in [0,p)")
        except ValueError:
            print("m is not an int, please ensure m to be an integer in [0,p)")
        # 把这个整数类型的信息m转化为字符串类型,便于使用hashG1函数
        # while语句使得x + m != 0
        if self.x + m == 0:
            print("x有问题")
        theta = (Bn.from_decimal(str(self.x + m)).mod_inverse(self.G.order()) * self.g1)
        return theta

    # 验证签名
    def verify(self,vk,m,theta):
        return self.G.pair(theta, self.X + (m * self.g2)) == self.G.pair(self.g1, self.g2)




if __name__ == "__main__":
    p = Bn.get_prime(100)
    m = p.random()
    print(p,m)
    # 测试BLS
    bls = BLS(p,m)
    # 测试产生公钥私钥函数正确性
    (sk,vk) = bls.keygen(p)
    print(sk,vk)
     # 测试生成签名函数正确性
    theta = bls.sign(sk,m)
    print(theta)
    # 测量生成签名函数执行时间
    total_time=0
    for i in range(1000):
        start = time.clock()
        bls.sign(sk,m)
        total_time += time.clock() - start
    print("BLS生成签名时间为",total_time/1000)
    # 测试验证签名函数正确性
    verify = bls.verify(vk,m,theta)
    print(verify)
    # 测量验证签名函数执行时间
    total_time=0
    for i in range(1000):
        start = time.clock()
        bls.verify(vk,m,theta)
        total_time += time.clock() - start
    print("BLS验证时间为",total_time/1000)

    # 测试WBB
    wbb = WBB(p,m)
    # 测试产生公钥私钥函数正确性
    (sk,vk) = wbb.keygen(p)
    print(sk,vk)
    # 测试生成签名函数正确性
    theta = wbb.sign(sk,m)
    print(theta)
    # 测量生成签名函数执行时间
    total_time=0
    for i in range(1000):
        start = time.clock()
        wbb.sign(sk,m)
        total_time += time.clock() - start
    print("WBB生成签名时间为",total_time/1000)
    # 测试验证签名函数正确性
    verify = wbb.verify(vk,m,theta)
    print(verify)
    # 测量验证签名函数执行时间
    total_time=0
    for i in range(1000):
        start = time.clock()
        wbb.verify(vk,m,theta)
        total_time += time.clock() - start
    print("WBB验证时间为",total_time/1000)