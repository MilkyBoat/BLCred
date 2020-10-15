from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
from bplib import bp
import hashlib
# 数组均采用 计算机中 0 对应数学中的1,计算机中n-1对应数学中的n,计算机中的n对应数学中的n+1的规范,不空置0号位置


class NIZK:

    def __init__(self,p):
        self.p = p


    def proveK(self,m,s,P,Q):
        # 得到C
        n = len(m)
        C = s * P
        # i = [0,n-1]
        for i in range(n):
            C += Q[i] * m[i]
        # 得到{wi}
        w = []
        for i in range(n + 1):
            w.append(Bn().from_decimal(str(self.p)).random())
        # 得到W
        W = w[n] * P  # w_{n+1}*P
        for i in range(n): 
            W += Q[i] * w[i]
        # 得到c,分为(1),(2),(3),(4)四步
        # (1)得到P,Qi,C,W各自的二进制表示P_,Q_[],C_,W_
        P_ = P.export()
        Q_ = []
        for i in range(n):
            Q_.append(Q[i].export())
        C_ = C.export()
        W_ = W.export()
        print("W_为",W_)
        # (2)将P_,Q_[],C_,W_顺次拼接在一起,得到二进制串bytestr
        bytestr = P_
        for i in range(n):
            bytestr += Q_[i]
        bytestr += C_ + W_
        # (3)将二进制串bytestr转换成字符串str0
        str0 = str(bytestr)
        # (4)调用hashlib中的md5函数,将str0映射成为十六进制数字c,再进一步转换为Bn类型的大整数对象
        c = hashlib.md5(str0.encode('utf8')).hexdigest()
        c = Bn.from_hex(str(c))
        # 得到ri
        r = []
        for i in range(n):
            r.append(w[i]-c*m[i])
        # 得到r_{i+1},存放在r[n]位置
        r.append(w[n] - c * s)
        # 返回pi
        pi = (C,c,r)
        return pi


    def verifyK(self,pi,P,Q):
        # c是内部的?C也是内部的?r也是内部的?不用不用,pi传入了
        # 预处理
        n = len(Q)
        (C,c,r) = pi
        # 得到c_,同样分为(1),(2),(3),(4)四步
        # (1)得到P,Qi,C各自的二进制表示P_,Q_[],C_,Sigma_(1,n){ri*Qi+r_{n+1}*P+c*C}_
        P_ = P.export()
        Q_ = []
        for i in range(n):
            Q_.append(Q[i].export())
        C_ = C.export()
        # 求点Sigma的位置:
        Sigma = r[n] * P + c * C
        for i in range(n):
            Sigma += r[i] * Q[i] 
        # 将点Sigma转换成byte形式
        Sigma_ = Sigma.export()
        # (2)将P_,Q_[],C_,Sigma_(1,n){ri*Qi+r_{n+1}*P+c*C}顺次拼接在一起,得到二进制串bytestr
        bytestr = P_
        for i in range(n):
            bytestr += Q_[i]
        bytestr += C_ + Sigma_
        # (3)将二进制串bytestr转换成字符串str0
        str0 = str(bytestr)
        # (4)调用hashlib中的md5函数,将str0映射成为十六进制数字c_,再进一步转换为Bn类型的大整数对象c_
        c_ = hashlib.md5(str0.encode('utf8')).hexdigest()
        c_ = Bn.from_hex(str(c_))
        return c_==c

    def proveDL(self,m,Q):
        n = len(m)
        # 得到C
        C = m[0] * Q[0]
        for i in range(1,n):
            C += m[i] * Q[i]
        # 得到{wi}
        w = []
        for i in range(n):
            w.append(Bn().from_decimal(str(self.p)).random())
        # 得到W
        W = w[0] * Q[0]
        for i in range(1,n):
            W += w[i] * Q[i]
        # 得到c,分为(1),(2),(3),(4)四步
        # (1)得到{Qi},C,W各自的二进制表示Q_[],C_,W_
        Q_ = []
        for i in range(n):
            Q_.append(Q[i].export())
        C_ = C.export()
        W_ = W.export()
        # (2)将Q_[],C_,W_顺次拼接在一起,得到二进制串bytestr
        bytestr = Q_[0]
        for i in range(1,n):
            bytestr += Q_[i]
        bytestr += C_ + W_
        # (3)将二进制串bytestr转换成字符串str0
        str0 = str(bytestr)
        # (4)调用hashlib中的md5函数,将str0映射成为十六进制数字c,再进一步转换为Bn类型的大整数对象
        c = hashlib.md5(str0.encode('utf8')).hexdigest()
        c = Bn.from_hex(str(c))
        # 得到ri
        r = []
        for i in range(n):
            r.append(w[i]-c*m[i])
        # 返回pi
        pi = (C,c,r)
        return pi

        

    def verifyDL(self,pi,Q):
        # 预处理
        n = len(Q)
        (C,c,r) = pi
        # 得到c_,同样分为(1),(2),(3),(4)四步
        # (1)得到{Qi},C,Sigma_(1,n){ri*Qi+c*C}各自的二进制表示Q_[],C_,Sigma_
        Q_ = []
        for i in range(n):
            Q_.append(Q[i].export())
        C_ = C.export()
        # 求点Sigma的位置:
        Sigma = c * C 
        for i in range(n):
            Sigma += r[i] * Q[i]
        # 将点Sigma转换成byte形式
        Sigma_ = Sigma.export()
        # (2)将Q_[],C_,Sigma_顺次拼接在一起,得到二进制串bytestr
        bytestr = Q_[0]
        for i in range(1,n):
            bytestr += Q_[i]
        bytestr += C_ + Sigma_
        # (3)将二进制串bytestr转换成字符串str0
        str0 = str(bytestr)
        # (4)调用hashlib中的md5函数,将str0映射成为十六进制数字c_,再进一步转换为Bn类型的大整数对象c_
        c_ = hashlib.md5(str0.encode('utf8')).hexdigest()
        c_ = Bn.from_hex(str(c_))
        return c_==c



# 测试样例
if __name__ == "__main__":
    # 得到m,s,P,Q
    G = bp.BpGroup()
    g1 = G.gen1()
    # size是n,因为是从1到n,共n个元素
    size = 5
    P = 10 * g1
    Q = []
    for i in range(size):
        Q.append( 3 * i * g1)     
    s = 50
    m = []
    for i in range(size):
        m.append(4 * i) 
    #print(m,s,P,Q)
    # 得到大质数p
    p = Bn.get_prime(100)
    # 验证proveK函数
    nizk = NIZK(p)
    pi = nizk.proveK(m,s,P,Q)
    #print("pi为:",pi)
    # 验证verifyK函数
    result = nizk.verifyK(pi,P,Q)
    print("verifyK的结果为",result)
    # 验证proveDL函数
    pi = nizk.proveDL(m,Q)
    #print("pi为",pi)
    # 验证verifyDL函数
    result = nizk.verifyDL(pi,Q)
    print("verifyDL的结果为",result)