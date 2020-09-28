from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp


# 怎么体现G1，G2，GT的阶为质数p
class FBB:
    
    def __init__(self,p,m):
        self.G = bp.BpGroup()
        # g1, g2 分别是G1，G2的生成元
        self.g1, self.g2 = self.G.gen1(), self.G.gen2()
        # x,y,X,Y 分别是私钥和公钥中的元素
        self.x = 0
        self.y = 0
        self.X = 0
        self.Y = 0
        # p,m是传入的参数，p为传入的大质数，使得G1，G2，GT的阶为质数p，m是传入的消息，属于Zp
        self.p = p
        self.m = m
        # r是theta中的一个元素，从消息空间Zp中随机获得（这里暂且先生成一个candidate，之后在sign函数中会进行筛选
        self.r = Bn(self.p).random()
        self.theta_prime = 0
        print("G的order为",self.G.order())

    # 生成公钥和私钥
    def keygen(self,p):
        # 调用petlib.bn中的Bn，生成两个[0,p)的随机数，作为私钥sk
        self.x = Bn(self.p).random()
        self.y = Bn(self.p).random()
        # 将私钥中两个元素x，y分别与g2做标量乘法
        self.X = self.x * self.g2
        self.Y = self.y * self.g2
        sk = (self.x, self.y)
        vk = (self.X, self.Y)
        return sk,vk
    
    # 生成数字签名
    def sign(self,sk,m):
        # 输入类型检测,要求m属于Zp
        try:
            m = int(m)
            if m < 0 or m > self.p:  # if not a positive int print message and ask for input again
                print("m is out of range, please ensure m to be an integer in [0,p)")
        except ValueError:
            print("m is not an int, please ensure m to be an integer in [0,p)")
        # while语句使得x + r*y + m != 0
        while self.x + self.r * self.y + m == 0:
            self.r = Bn(self.p).random()
        self.theta_prime = ((self.x + self.r * self.y + m) * self.g1).neg()
        theta = (self.theta_prime, self.r)
        return theta

    # 验证签名
    def verify(self,vk,m,theta):
        self.theta_prime = theta[0]
        self.r = theta[1]
        # return self.G.pair(theta_prime, self.X) * self.G.pair(theta_prime, (self.r * self.Y)) * self.G.pair(theta_prime, (m * self.g2)) == self.G.pair(self.g1, self.g2)
        return self.G.pair(self.theta_prime, self.X + (self.r * self.Y) + (m * self.g2)) == self.G.pair(self.g1, self.g2)

 

if __name__ == "__main__":
    p = 199
    # m 属于Zp
    m = 500
    fbb = FBB(p,m)
    (sk,vk) = fbb.keygen(p)
    print(sk,vk)
    theta = fbb.sign(sk,m)
    print(theta)
    verify = fbb.verify(vk,m,theta)
    print(verify)