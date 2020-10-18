from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp
from lib.LibRS import RS
from lib.LibNIZK import NIZK
from lib.LibFBB import FBB
from lib.LibBLS import BLS
import hashlib


def H(otsvk):
    # 这里要确保这里生成的G和BLCred的self.G是一样的才行
    G = bp.BpGroup()
    X_ = otsvk[0].export()
    Y_ = otsvk[1].export()
    bytestr = X_ + Y_
    str0 = str(bytestr)
    return G.hashG1(str0.encode("utf8"))


def H_hat(pi_NIZK,phi,otsvk):
    X_ = otsvk[0].export()
    Y_ = otsvk[1].export()
    X_str = str(X_)
    Y_str = str(Y_)
    str0 = pi_NIZK + phi + X_str + Y_str
    c_ = hashlib.md5(str0.encode('utf8')).hexdigest()
    c_ = Bn.from_hex(str(c_))
    return c_


class BLCred:
    def __init__(self ,p):
        self.G = 0
        self.g1 = 0
        self.g2 = 0
        self.x = 0
        self.X = 0
        # Zp中的p
        self.p = p
        self.fbb = FBB(self.p)
        self.bls = BLS(self.p)
        self.nizk = NIZK(self.p)
        self.rs = RS()



    def setup(self):
        # Choose a bilinear group
        self.G = bp.BpGroup()
        self.g1, self.g2 = self.G.gen1(), self.G.gen2()
        # crs = NIZK.setup(),由于这里实现的是schnor版本,暂时不需要
        # Choose collision-resistant hash function H for DS and H_hat for OTS
    




    def authkeygen(self , n):
        # 得到x,{yi}
        x = Bn().from_decimal(str(self.p)).random()
        y = []
        for i in range(n):
            y.append(Bn().from_decimal(str(self.p)).random())
        # 得到X,X_,{Yi},{Y_i}
        X = x * self.g1
        X_ = x * self.g2
        Y = []
        for i in range(n):
            Y.append(y[i]*self.g1)
        Y_ = []
        for i in range(n):
            Y_.append(y[i]*self.g2)
        # 得到Z
        Z = {}
        for i in range(n):
            for j in range(i):
                # Z[i * n + j] is Z(i, j), 0 < j < i
                Z[(i+1) * n + j+1] = (y[i] * y[j]) * self.g1
        ask = [x, y]
        avk = [X, X_, Y, Y_, Z]
        return ask, avk


    def ukeygen(self):
        self.x = Bn().from_decimal(str(self.p)).random()
        self.X = self.x * self.g2
        usk = self.x
        uvk = self.X
        return usk,uvk


    def issuecred(self,usk,uvk,m,ask,avk):
        n = len(m)
        # 得到s
        s = p.random()
        print("s为",s)
        # 得到{Qi},i=[1,n],其中Qi都是G2上的元素
        G = bp.BpGroup()
        g2 = G.gen2()
        Q = []
        for _ in range(n):
            rand = p.random()
            Q.append(rand * g2)
        # (user) ObtainCommit
        # 得到pi_1和pi_2
        
        pi_1 = self.nizk.proveK(m,s,uvk,Q)
        # 由于proveDL的接口,只能传入list形式的参数,这里需要用[usk],[self.g2],而不能用usk,self.g2
        pi_2 = self.nizk.proveDL([usk],[self.g2])
        # (auth)sigma_cred_ <-Issue(uvk,ask,pi)
        # 同样DL的接口,只能传入list形式的参数,这里需要用pi_2(pi_2本身就是三个元素的list),[self.g2]
        if(self.nizk.verifyK(pi_1,uvk,Q)==1 and self.nizk.verifyDL(pi_2,[self.g2])==1):
            w = p.random()
            sigma_cred_ = (w*uvk,w*(avk[1]+pi_1[0]))
        else:
            print("auth验证失败")
        #(user)delta_cred<-Unblind(delta_cred_,s)
        sigma_cred = (self.g1,self.g1,sigma_cred_[0],sigma_cred_[1]-s*sigma_cred_[0])
        return sigma_cred



    def deriveshow(self,phi,usk,avk,sigma_cred,D):
        # (otssk,otsvk)<-OTS.keygen()

        (otssk,otsvk) = self.fbb.keygen()
        # delta_s<-DS.sign(usk,H(otsvk))

        # 这里需要设计以下otsvk到m的哈希函数,因为otsvk是(ponit_g2,point_g2)类型,而m是整数类型
        pt_H = H(otsvk)
        print("pt_H为",pt_H)
        sigma_s = self.bls.sign(pt_H,usk)
        # delta_D = RS.derive(avk,sigma_cred,{mi},D)
        # 因此还需要传入sigma_cred和D

        sigma_D = self.rs.derive(avk,m,D,sigma_cred)
        # pi_NIZK = NIZK.prove(crs,z,{mi},uvk,sigma_s,sigma_D),暂时没写,随机给定一个字符串
        # sigma_show_ <-OTS.sign(otssk,(pi_NIZK,phi,otsvk))
        pi_NIZK = "aaa"
        m_ = H_hat(pi_NIZK,phi,otsvk)
        sigma_show_ = self.fbb.sign(otssk,m_)
        sigma_show = (sigma_show_,otsvk,pi_NIZK)
        return sigma_show


    def credverify(self,avk,sigma_show,phi):
        (sigma_show_,otsvk,pi_NIZK) = sigma_show
        m_ = H_hat(pi_NIZK,phi,otsvk)
        result = self.fbb.verify(otsvk,m_,sigma_show_)
        return result


if __name__ == "__main__":
    # 准备部分
    # 随机得到一个大质数p
    p = Bn.get_prime(100)
    print("p为",p)
    # 取n为10,可变
    n = 10
    # 得到{mi}:随机生成n个不同的信息{mi}
    m = []
    for i in range(n):
        m.append(p.random())
    print("m为",m)

    
    # 开始测试
    blcred = BLCred(p)
    # SetUp初始化
    blcred.setup()
    # 测试Authkeygen
    (ask,avk) = blcred.authkeygen(n)
    # 测试Ukeygen
    (usk,uvk) = blcred.ukeygen()
    # 测试IssueCred
    sigma_cred = blcred.issuecred(usk,uvk,m,ask,avk)
    print("sigma_cred为",sigma_cred)
    # 测试DeriveShow
    phi = "abcdefg"
    D = set([1, 3, 4])
    sigma_show = blcred.deriveshow(phi,usk,avk,sigma_cred,D)

    print("sigma_show为",sigma_show)
    (sigma_show_,otsvk,pi_NIZK) = sigma_show
    sigma_show_[0].export()

    # 测试Crederify
    result = blcred.credverify(avk,sigma_show,phi)
    print(result)
