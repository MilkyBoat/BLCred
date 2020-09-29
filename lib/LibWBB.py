from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp


class WBB: 

    def __init__(self,p,m):
        self.G = bp.BpGroup()
        # g1, g2 分别是G1，G2的生成元
        self.g1, self.g2 = self.G.gen1(), self.G.gen2()
        # x,X 分别是私钥和公钥
        self.x = 0
        self.X = 0
        # p,m是传入的参数，p为传入的大质数，G1，G2，GT的阶为质数p2，m是传入的消息，属于Zp,
        self.p = p
        self.m = m

    # 生成公钥和私钥
    def keygen(self,p):
        # 调用petlib.bn中的Bn，生成(0,p)的随机数，作为私钥sk
        self.x = Bn(self.p).random()
        # 将私钥x与g2做标量乘法,得到公钥X
        self.X = self.x * self.g2
        sk = (self.x)
        vk = (self.X)
        return sk,vk
    
    # 生成数字签名
    def sign(self,sk,m):
        # while语句使得x + r*y + m != 0
        if self.x + m == 0:
            print("x有问题")
        theta = Bn(self.x+m).mod_inverse() * self.g1
        return theta

    # 验证签名
    def verify(self,vk,m,theta):
        # return self.G.pair(theta_prime, self.X) * self.G.pair(theta_prime, (self.r * self.Y)) * self.G.pair(theta_prime, (m * self.g2)) == self.G.pair(self.g1, self.g2)
        return self.G.pair(theta, self.X + (m * self.g2)) == self.G.pair(self.g1, self.g2)

 

if __name__ == "__main__":
    p = 19999
    # m 属于Zp
    m = 500
    wbb = WBB(p,m)
    (sk,vk) = wbb.keygen(p)
    print(sk,vk)
    theta = wbb.sign(sk,m)
    print(theta)
    verify = wbb.verify(vk,m,theta)
    print(verify)