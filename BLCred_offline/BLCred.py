from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp
from lib.LibRS import RS
from lib.LibNIZK import NIZK
from lib.LibFBB import FBB
from lib.LibBLS import BLS
import hashlib
# from Crypto.Cipher import AES


# def H(otsvk):
#     # 这里要确保这里生成的G和BLCred的self.G是一样的才行
#     G = bp.BpGroup()
#     X_ = otsvk[0].export()
#     Y_ = otsvk[1].export()
#     bytestr = X_ + Y_
#     str0 = str(bytestr)
#     return G.hashG1(str0.encode("utf8"))


# def H_hat(pi_NIZK,phi,otsvk):
#     X_ = otsvk[0].export()
#     Y_ = otsvk[1].export()
#     X_str = str(X_)
#     Y_str = str(Y_)
#     str0 = pi_NIZK + phi + X_str + Y_str
#     c_ = hashlib.sha1(str0.encode('utf8')).hexdigest()
#     c_ = Bn.from_hex(str(c_))
#     return c_


class BLCred:
    def __init__(self ,p):
        self.G = 0
        self.g1 = 0
        self.g2 = 0
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
    

    def ipkeygen(self , n):
        return self.rs.keygen(n)


    def ukeygen(self):
        usk = Bn().from_decimal(str(self.p)).random()
        uvk = usk * self.g2
        return usk,uvk


    def skeygen(self):
        ssk = Bn().from_decimal(str(self.p)).random()
        svk = ssk * self.g2
        return ssk,svk


    def commit(self, usk, uvk, avk, m):
        n = len(m)
        S = Bn().from_decimal(str(self.p)).random()
        C = S * uvk
        for i in range(n):
            C = C + (m[i] * avk[3][i])
        Q = []
        for _ in range(n):
            Q.append(self.p.random() * self.g2)
        Pi1 = self.nizk.proveK(m, S, uvk, Q)
        Pi2 = self.nizk.proveDL([usk], [self.g2])
        return (C, S, Pi1, Pi2, Q)


    def issue(self, uvk, ask, C, Pi1, Pi2, Q):
        n = len(ask[1])
        # NIZK verify
        zk1 = self.nizk.verifyK(Pi1, uvk, Q)
        zk2 = self.nizk.verifyDL(Pi2, [self.g2])
        if(zk1 and zk2):
            w = self.p.random()
            return (w * uvk, w * (ask[0] * self.g2 + C))
        else:
            print(zk1, zk2)
            raise "NIZK verify failed"
        

    def unblind(self, sigma_cred_, S, usk):
        return (self.g1, self.g1, sigma_cred_[0], sigma_cred_[1] - S * sigma_cred_[0])


    def issuecred(self,usk,uvk,m,ask,avk):
        n = len(m)

        # (user) Commit
        (C, S, Pi1, Pi2, Q) = self.commit(usk, uvk, avk, m)
        
        # (auth) sigma_cred_ <- Issue(uvk,ask,C,pi)
        sigma_cred_ = self.issue(uvk, ask, C, Pi1, Pi2, Q)

        # (user) sigma_cred <- Unblind(delta_cred_,s,usk)
        sigma_cred = self.unblind(sigma_cred_, S, usk)
        return sigma_cred


    def deriveshow(self, sigma_cred, avk, m, D):
        
        sigma_D = self.rs.derive(avk, m, D, sigma_cred)

        tag = self.p.random()

        LK_str = str(tag) + str(usk)
        LK = hashlib.sha1(LK_str.encode('utf8')).hexdigest()
        LK = Bn.from_hex(LK)

        Q = []
        for _ in range(n):
            Q.append(self.p.random() * self.g2)
        m_d = []
        for i in D:
            m_d.append(m[i])
        Pi1 = self.nizk.proveK(m_d, self.p.random(), uvk, Q)
        Pi2 = None # TODO: zkSNARK?
        Pi3 = self.nizk.proveDL([LK], [self.g2])
        
        return (LK, Pi1, Pi2, Pi3, Q)


    def link(self, sigma_show1, sigma_show2):
        return sigma_show1[0] == sigma_show2[0]


    # def credverify(self,avk,sigma_show,phi):
    #     (sigma_show_,otsvk,pi_NIZK) = sigma_show
    #     m_ = H_hat(pi_NIZK,phi,otsvk)
    #     result = self.fbb.verify(otsvk,m_,sigma_show_)
    #     return result


if __name__ == "__main__":
    # before the test
    # get a big prime p
    p = Bn.get_prime(100)
    print("p = ",p)
    n = 8
    m = []
    for i in range(n):
        m.append(p.random())
    print("m is ",m)

    
    # begin test
    blcred = BLCred(p)
    # SetUp init
    blcred.setup()
    # test Ipkeygen
    (ask,avk) = blcred.ipkeygen(n)
    # test Ukeygen
    (usk,uvk) = blcred.ukeygen()
    # test Skeygen
    (ssk,svk) = blcred.skeygen()
    # test IssueCred
    sigma_cred = blcred.issuecred(usk,uvk,m,ask,avk)
    print("sigma_cred is ",sigma_cred)
    # test DeriveShow
    D = set([1, 3, 4])
    sigma_show = blcred.deriveshow(sigma_cred,avk,m,D)
    # print("sigma_show is ",sigma_show)
    print("sigma_show is ",sigma_show)

    # # 测试Crederify
    # result = blcred.credverify(avk,sigma_show,phi)
    # print(result)
